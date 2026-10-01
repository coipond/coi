// Package bedrock detects AWS Bedrock configuration in Claude settings and
// validates that a Colima environment is set up correctly to use it.
package bedrock

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ValidationIssue represents a problem found during validation
type ValidationIssue struct {
	Severity string // "error" or "warning"
	Message  string
	Fix      string
}

// ValidationResult contains all issues found
type ValidationResult struct {
	Issues []ValidationIssue
}

// HasErrors returns true if there are any error-level issues
func (vr *ValidationResult) HasErrors() bool {
	for _, issue := range vr.Issues {
		if issue.Severity == "error" {
			return true
		}
	}
	return false
}

// FormatError returns a formatted error message with all issues
func (vr *ValidationResult) FormatError() string {
	if len(vr.Issues) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("AWS Bedrock configuration detected but setup incomplete\n\n")
	sb.WriteString("You're running in Colima with Bedrock configured in settings.json.\n")
	sb.WriteString("Detected issues:\n\n")

	for _, issue := range vr.Issues {
		if issue.Severity == "error" {
			sb.WriteString("❌ ")
		} else {
			sb.WriteString("⚠️  ")
		}
		sb.WriteString(issue.Message)
		sb.WriteString("\n")
		if issue.Fix != "" {
			sb.WriteString("   Fix: ")
			sb.WriteString(issue.Fix)
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("After fixing these issues, try again.\n")
	return sb.String()
}

// IsBedrockConfigured checks if settings.json contains Bedrock configuration
func IsBedrockConfigured(settingsPath string) (bool, error) {
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return false, err
	}

	// Check for anthropic.apiProvider = "bedrock"
	anthropic, ok := settings["anthropic"].(map[string]interface{})
	if !ok {
		return false, nil
	}

	apiProvider, ok := anthropic["apiProvider"].(string)
	if !ok {
		return false, nil
	}

	return apiProvider == "bedrock", nil
}

// ValidateColimaBedrockSetup validates AWS Bedrock setup in Colima environment
func ValidateColimaBedrockSetup() *ValidationResult {
	result := &ValidationResult{
		Issues: []ValidationIssue{},
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		result.Issues = append(result.Issues, ValidationIssue{
			Severity: "error",
			Message:  "Failed to determine home directory",
			Fix:      "",
		})
		return result
	}

	// Check 1: AWS CLI installed
	if !isAWSCLIInstalled() {
		result.Issues = append(result.Issues, ValidationIssue{
			Severity: "error",
			Message:  "AWS CLI not found",
			Fix:      "Install AWS CLI: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html",
		})
		return result // Can't continue without AWS CLI
	}

	// Check 2: Detect dual .aws paths
	limaPath := filepath.Join(homeDir, ".aws")
	macPath := "/Users"

	// Check if we're in Lima (homeDir would be /home/lima)
	isLima := strings.HasPrefix(homeDir, "/home/lima")

	if isLima {
		// Try to detect macOS username by looking at /Users
		entries, err := os.ReadDir(macPath)
		macHomeFound := false
		var macAWSPath string

		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() && entry.Name() != "Shared" {
					testPath := filepath.Join(macPath, entry.Name(), ".aws")
					if _, err := os.Stat(testPath); err == nil {
						macHomeFound = true
						macAWSPath = testPath
						break
					}
				}
			}
		}

		// Check if both paths exist
		limaExists := false
		if _, err := os.Stat(limaPath); err == nil {
			limaExists = true
		}

		if limaExists && macHomeFound {
			result.Issues = append(result.Issues, ValidationIssue{
				Severity: "warning",
				Message:  fmt.Sprintf("Found .aws directories in TWO locations:\n   • %s (Lima VM home)\n   • %s (macOS home)\n   \n   These can get out of sync! Recommendation:\n   - Use macOS path: %s\n   - Run \"aws sso login\" on macOS (not inside Colima)\n   - Ensure it's mounted to container", limaPath, macAWSPath, macAWSPath),
				Fix:      "",
			})
		}
	}

	// Check 3: Check .aws directory exists somewhere
	awsPath := limaPath
	if _, err := os.Stat(awsPath); err != nil {
		result.Issues = append(result.Issues, ValidationIssue{
			Severity: "error",
			Message:  fmt.Sprintf("~/.aws directory not found at %s", awsPath),
			Fix:      "Run: aws configure sso",
		})
		return result
	}

	// Check 4: Check SSO cache file permissions
	ssoCache := filepath.Join(awsPath, "sso", "cache")
	if entries, err := os.ReadDir(ssoCache); err == nil {
		hasRestrictivePerms := false
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
				filePath := filepath.Join(ssoCache, entry.Name())
				if info, err := os.Stat(filePath); err == nil {
					mode := info.Mode().Perm()
					// Check if permissions are too restrictive (only owner can read)
					if mode&0o044 == 0 { // No group or other read permissions
						hasRestrictivePerms = true
						break
					}
				}
			}
		}

		if hasRestrictivePerms {
			result.Issues = append(result.Issues, ValidationIssue{
				Severity: "error",
				Message:  "AWS SSO cache files have restrictive permissions",
				Fix:      fmt.Sprintf("chmod 644 %s/*.json", ssoCache),
			})
		}
	}

	// Check 5: Validate AWS credentials work
	if !testAWSCredentials() {
		result.Issues = append(result.Issues, ValidationIssue{
			Severity: "error",
			Message:  "AWS credentials not working",
			Fix:      "Run: aws sso login",
		})
	}

	return result
}

// isAWSCLIInstalled checks if AWS CLI is available
func isAWSCLIInstalled() bool {
	_, err := exec.LookPath("aws")
	return err == nil
}

// testAWSCredentials tests if AWS credentials are valid
func testAWSCredentials() bool {
	cmd := exec.Command("aws", "sts", "get-caller-identity")
	err := cmd.Run()
	return err == nil
}

// CheckMountConfiguration checks if .aws is properly mounted
func CheckMountConfiguration(mounts []string) *ValidationIssue {
	// Check if any mount includes .aws
	for _, mount := range mounts {
		if strings.Contains(mount, ".aws") {
			return nil // Found .aws mount
		}
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return &ValidationIssue{
			Severity: "error",
			Message:  "Failed to determine home directory for mount check",
			Fix:      "",
		}
	}

	return &ValidationIssue{
		Severity: "error",
		Message:  "~/.aws not mounted to container",
		Fix:      fmt.Sprintf("Add to your ~/.coi/config.toml:\n\n   [[mounts.default]]\n   host = \"%s/.aws\"\n   container = \"/home/code/.aws\"", homeDir),
	}
}
