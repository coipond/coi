package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/mensfeld/code-on-incus/internal/config"
	"github.com/spf13/cobra"
)

var profileFormat string

// profileCmd is the parent command for profile operations
var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage profiles",
	Long:  `List and inspect available profiles from all configuration sources.`,
}

// profileListCmd lists all available profiles
var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available profiles",
	Long: `List all profiles from system, user, and project configuration.

Profiles are defined as directories under profiles/, each containing a config.toml.

Examples:
  coi profile list
  coi profile list --format json`,
	RunE: app.profileListRunE,
}

func (a *App) profileListRunE(cmd *cobra.Command, args []string) error {
	applyJSONFormatAlias(cmd, &profileFormat)
	if err := validateTextOrJSON(profileFormat); err != nil {
		return err
	}

	if len(a.cfg.Profiles) == 0 {
		if profileFormat == "json" {
			fmt.Println("[]")
			return nil
		}
		fmt.Fprintln(os.Stderr, "No profiles configured.")
		return nil
	}

	// Sort profile names for consistent output
	names := make([]string, 0, len(a.cfg.Profiles))
	for name := range a.cfg.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)

	if profileFormat == "json" {
		type profileEntry struct {
			Name        string `json:"name"`
			Image       string `json:"image"`
			Persistent  *bool  `json:"persistent"`
			StoragePool string `json:"storage_pool,omitempty"`
			Inherits    string `json:"inherits,omitempty"`
			Source      string `json:"source,omitempty"`
		}
		entries := make([]profileEntry, 0, len(names))
		for _, name := range names {
			p := a.cfg.Profiles[name]
			entries = append(entries, profileEntry{
				Name:        name,
				Image:       p.Container.Image,
				Persistent:  p.Container.Persistent,
				StoragePool: p.Container.StoragePool,
				Inherits:    p.Inherits,
				Source:      p.Source,
			})
		}
		jsonData, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	tbl := NewTable("NAME", "IMAGE", "PERSISTENT", "INHERITS", "SOURCE")
	for _, name := range names {
		p := a.cfg.Profiles[name]
		image := p.Container.Image
		if image == "" {
			image = "(default)"
		}
		persistent := "-"
		if p.Container.Persistent != nil {
			if *p.Container.Persistent {
				persistent = "true"
			} else {
				persistent = "false"
			}
		}
		inherits := "-"
		if p.Inherits != "" {
			inherits = p.Inherits
		}
		source := p.Source
		if source == "" {
			source = "(unknown)"
		}
		tbl.AddRow(name, image, persistent, inherits, source)
	}
	tbl.Render()
	return nil
}

// profileInfoCmd shows details of a specific profile
var profileInfoCmd = &cobra.Command{
	Use:   "info <name>",
	Short: "Show detailed information about a profile",
	Long: `Display the full configuration of a named profile.

Examples:
  coi profile info rust-dev`,
	Args: cobra.ExactArgs(1),
	RunE: app.profileInfoRunE,
}

//nolint:gocyclo // Profile info rendering has many optional fields — sequential by design
func (a *App) profileInfoRunE(cmd *cobra.Command, args []string) error {
	name := args[0]
	p := a.cfg.GetProfile(name)
	if p == nil {
		return fmt.Errorf("profile '%s' not found", name)
	}

	fmt.Printf("Profile: %s\n", name)
	if p.Source != "" {
		fmt.Printf("Source:  %s\n", p.Source)
	}
	fmt.Println()
	printProfileTopLevel(p)
	printProfileContainer(p)
	printProfileEnvironment(p)
	printProfileTool(p)
	printProfileBuild(p)
	printProfileMounts(p)
	printProfileNetwork(p)
	if p.Limits != nil {
		printLimits(p.Limits)
	}
	printProfilePaths(p)
	printProfileIncus(p)
	printProfileGit(p)
	printProfileSSH(p)
	printProfileSecurity(p)
	printProfileMonitoring(p)
	printProfileTimezone(p)
	return nil
}

// shellQuote wraps a string in single quotes for safe shell interpolation.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func formatStringSlice(ss []string) string {
	quoted := make([]string, len(ss))
	for i, s := range ss {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(quoted, ", ")
}

func printLimits(l *config.LimitsConfig) {
	if l.CPU.Count != "" || l.CPU.Allowance != "" || l.CPU.Priority != 0 {
		fmt.Println()
		fmt.Println("[limits.cpu]")
		if l.CPU.Count != "" {
			fmt.Printf("count = %q\n", l.CPU.Count)
		}
		if l.CPU.Allowance != "" {
			fmt.Printf("allowance = %q\n", l.CPU.Allowance)
		}
		if l.CPU.Priority != 0 {
			fmt.Printf("priority = %d\n", l.CPU.Priority)
		}
	}
	if l.Memory.Limit != "" || l.Memory.Enforce != "" || l.Memory.Swap != "" {
		fmt.Println()
		fmt.Println("[limits.memory]")
		if l.Memory.Limit != "" {
			fmt.Printf("limit = %q\n", l.Memory.Limit)
		}
		if l.Memory.Enforce != "" {
			fmt.Printf("enforce = %q\n", l.Memory.Enforce)
		}
		if l.Memory.Swap != "" {
			fmt.Printf("swap = %q\n", l.Memory.Swap)
		}
	}
	if l.Disk.Read != "" || l.Disk.Write != "" || l.Disk.Max != "" || l.Disk.Size != "" || l.Disk.TmpfsSize != "" {
		fmt.Println()
		fmt.Println("[limits.disk]")
		if l.Disk.Read != "" {
			fmt.Printf("read = %q\n", l.Disk.Read)
		}
		if l.Disk.Write != "" {
			fmt.Printf("write = %q\n", l.Disk.Write)
		}
		if l.Disk.Max != "" {
			fmt.Printf("max = %q\n", l.Disk.Max)
		}
		if l.Disk.Size != "" {
			fmt.Printf("size = %q\n", l.Disk.Size)
		}
		if l.Disk.TmpfsSize != "" {
			fmt.Printf("tmpfs_size = %q\n", l.Disk.TmpfsSize)
		}
	}
	if l.Runtime.MaxDuration != "" || l.Runtime.MaxProcesses != 0 {
		fmt.Println()
		fmt.Println("[limits.runtime]")
		if l.Runtime.MaxDuration != "" {
			fmt.Printf("max_duration = %q\n", l.Runtime.MaxDuration)
		}
		if l.Runtime.MaxProcesses != 0 {
			fmt.Printf("max_processes = %d\n", l.Runtime.MaxProcesses)
		}
	}
}

// profileShowCmd is a hidden backward-compatible alias for profileInfoCmd
var profileShowCmd = &cobra.Command{
	Use:    "show <name>",
	Short:  profileInfoCmd.Short,
	Long:   profileInfoCmd.Long,
	Args:   profileInfoCmd.Args,
	RunE:   app.profileInfoRunE,
	Hidden: true,
}

// resolveProfileDir determines the target directory for a new profile.
func (a *App) resolveProfileDir(name string, forceUser, forceProject bool) (string, error) {
	if forceUser {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		return filepath.Join(homeDir, ".coi", "profiles", name), nil
	}

	if forceProject {
		absWorkspace, err := filepath.Abs(a.workspace)
		if err != nil {
			return "", fmt.Errorf("cannot resolve workspace: %w", err)
		}
		return filepath.Join(absWorkspace, ".coi", "profiles", name), nil
	}

	// Default: project if .coi/ exists, otherwise user home
	absWorkspace, err := filepath.Abs(a.workspace)
	if err != nil {
		return "", fmt.Errorf("cannot resolve workspace: %w", err)
	}
	coiDir := filepath.Join(absWorkspace, ".coi")
	info, statErr := os.Stat(coiDir)
	if statErr == nil {
		if info.IsDir() {
			return filepath.Join(coiDir, "profiles", name), nil
		}
	} else if !os.IsNotExist(statErr) {
		return "", fmt.Errorf("cannot stat project .coi directory %q: %w", coiDir, statErr)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(homeDir, ".coi", "profiles", name), nil
}

// profileCreateCmd creates a new profile
var profileCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new profile",
	Long: `Create a new profile directory with a minimal config.toml.

By default, creates in .coi/profiles/ if inside a project with .coi/ directory,
otherwise creates in ~/.coi/profiles/. Use --user or --project to override.

The special name "default" scaffolds the MAIN config (the file that backs the
built-in default profile) instead of a profile directory: ~/.coi/config.toml,
or ./.coi/config.toml with --project. It writes a documented starter only when
no config exists there (it never overwrites), and rejects --inherits. Coi runs
fine without any config — this just gives you a commented starting point to
customize.

Settings like [container] image / persistent are edited into the created
config.toml afterwards (coi profile edit <name>).

Examples:
  coi profile create rust-dev --inherits default
  coi profile create my-profile --project
  coi profile create default              # scaffold ~/.coi/config.toml
  coi profile create default --project    # scaffold ./.coi/config.toml`,
	Args: cobra.ExactArgs(1),
	RunE: app.profileCreateRunE,
}

func (a *App) profileCreateRunE(cmd *cobra.Command, args []string) error {
	name := args[0]

	// Validate name
	if name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return fmt.Errorf("profile name cannot contain slashes")
	}
	if strings.Trim(name, ".") == "" {
		return fmt.Errorf("profile name cannot be '.', '..', or consist only of dots")
	}
	// "default" is the built-in profile; it has no profiles/ directory — its
	// values are backed by the main config. So scaffold the main config instead.
	if name == "default" {
		return a.scaffoldMainConfig(cmd)
	}

	forceUser, _ := cmd.Flags().GetBool("user")
	forceProject, _ := cmd.Flags().GetBool("project")
	if forceUser && forceProject {
		return fmt.Errorf("--user and --project are mutually exclusive")
	}

	// Check if a profile with this name already exists in any config source
	if existing := a.cfg.GetProfile(name); existing != nil {
		return fmt.Errorf("profile '%s' already exists (source: %s)", name, existing.Source)
	}

	profileDir, err := a.resolveProfileDir(name, forceUser, forceProject)
	if err != nil {
		return err
	}

	// Check directory doesn't already exist on disk
	if _, statErr := os.Stat(profileDir); statErr == nil {
		return fmt.Errorf("profile directory already exists: %s", profileDir)
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("failed to check profile directory %s: %w", profileDir, statErr)
	}

	// Build TOML content. Only --inherits seeds the file — everything else
	// ([container] image / persistent, limits, network, ...) is edited into
	// the created config.toml, keeping config the single authoring surface.
	var content string
	if inherits, _ := cmd.Flags().GetString("inherits"); inherits != "" {
		content = fmt.Sprintf("inherits = %q\n", inherits)
	}

	// Create directory and write config
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		return fmt.Errorf("failed to create profile directory: %w", err)
	}

	configPath := filepath.Join(profileDir, "config.toml")
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		// Clean up directory on write failure
		os.RemoveAll(profileDir)
		return fmt.Errorf("failed to write config.toml: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Created profile '%s' at %s\n", name, configPath)
	return nil
}

// scaffoldMainConfig handles `coi profile create default`: it writes the main
// config (the file that backs the built-in default profile) from the curated
// starter template, but only when no config exists there — it never overwrites.
func (a *App) scaffoldMainConfig(cmd *cobra.Command) error {
	// --inherits configures a profile, not the main config.
	if cmd.Flags().Changed("inherits") {
		return fmt.Errorf("--inherits is not valid for 'coi profile create default'; " +
			"it scaffolds the main config — edit the generated file to set values")
	}

	forceUser, _ := cmd.Flags().GetBool("user")
	forceProject, _ := cmd.Flags().GetBool("project")
	if forceUser && forceProject {
		return fmt.Errorf("--user and --project are mutually exclusive")
	}

	// Resolve the target main config path. Default is the user/global config;
	// --project targets the workspace. (Not resolveProfileDir, whose project
	// auto-detection would override the user-default behavior.)
	var path string
	if forceProject {
		absWorkspace, err := filepath.Abs(a.workspace)
		if err != nil {
			return fmt.Errorf("invalid workspace path: %w", err)
		}
		path = filepath.Join(absWorkspace, ".coi", "config.toml")
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to determine home directory: %w", err)
		}
		path = filepath.Join(home, ".coi", "config.toml")
	}

	// Only when absent — never clobber an existing config.
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config already exists: %s (refusing to overwrite; edit it directly or remove it first)", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to check %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	if err := os.WriteFile(path, config.EmbeddedStarterConfig, 0o644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Created main config at %s\n", path)
	fmt.Fprintln(os.Stderr, "It overrides nothing yet — uncomment and edit lines to customize.")
	return nil
}

// profileEditCmd opens a profile's config in an editor
var profileEditCmd = &cobra.Command{
	Use:   "edit <name>",
	Short: "Edit a profile's config.toml in your editor",
	Long: `Open a profile's config.toml in $VISUAL, $EDITOR, or vi.

After the editor exits, the file is re-parsed and validated.
A warning is printed if the TOML is invalid, but the file is not deleted.

Examples:
  coi profile edit rust-dev
  EDITOR=nano coi profile edit my-profile`,
	Args: cobra.ExactArgs(1),
	RunE: app.profileEditRunE,
}

func (a *App) profileEditRunE(cmd *cobra.Command, args []string) error {
	name := args[0]

	p := a.cfg.GetProfile(name)
	if p == nil {
		return fmt.Errorf("profile '%s' not found", name)
	}
	if p.Source == "(built-in)" {
		return fmt.Errorf("cannot edit built-in profile 'default'")
	}

	sourcePath := p.Source

	// Determine editor
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}

	// Use sh -c to support multi-word editor values like "code --wait".
	// editor comes from $VISUAL/$EDITOR set by the user — taint is intentional.
	editorCmd := exec.Command("sh", "-c", editor+" "+shellQuote(sourcePath)) //nolint:gosec
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr

	if err := editorCmd.Run(); err != nil {
		return fmt.Errorf("editor exited with error: %w", err)
	}

	// Re-parse and validate
	var profileCfg config.ProfileConfig
	if _, err := toml.DecodeFile(sourcePath, &profileCfg); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %s contains invalid TOML: %v\n", sourcePath, err)
		return nil
	}
	if err := profileCfg.Validate(name); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: profile validation failed: %v\n", err)
	}

	return nil
}

// profileDeleteCmd deletes a profile directory
var profileDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a profile",
	Long: `Delete a profile directory and its config.toml.

Without --force, prompts for confirmation before deleting.

Examples:
  coi profile delete rust-dev
  coi profile delete old-profile --force`,
	Args: cobra.ExactArgs(1),
	RunE: app.profileDeleteRunE,
}

func (a *App) profileDeleteRunE(cmd *cobra.Command, args []string) error {
	name := args[0]

	p := a.cfg.GetProfile(name)
	if p == nil {
		return fmt.Errorf("profile '%s' not found", name)
	}
	if p.Source == "(built-in)" {
		return fmt.Errorf("cannot delete built-in profile 'default'")
	}

	profileDir := filepath.Dir(p.Source)
	force, _ := cmd.Flags().GetBool("force")

	if !force {
		fmt.Fprintf(os.Stderr, "This will delete profile '%s' at %s\n", name, profileDir)
		if !confirmAction("Continue?") {
			fmt.Fprintln(os.Stderr, "Aborted.")
			return nil
		}
	}

	if err := os.RemoveAll(profileDir); err != nil {
		return fmt.Errorf("failed to delete profile directory: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Deleted profile '%s' (%s)\n", name, profileDir)
	return nil
}

func init() {
	profileListCmd.Flags().StringVar(&profileFormat, "format", "text", "Output format: text or json")
	profileListCmd.Flags().Bool("json", false, "Alias for --format json")

	profileCreateCmd.Flags().String("inherits", "", "Set the parent profile to inherit from")
	profileCreateCmd.Flags().Bool("user", false, "Force creation in ~/.coi/profiles/")
	profileCreateCmd.Flags().Bool("project", false, "Force creation in ./.coi/profiles/")

	profileDeleteCmd.Flags().BoolP("force", "f", false, "Skip confirmation prompt")

	profileCmd.AddCommand(profileListCmd)
	profileCmd.AddCommand(profileInfoCmd)
	profileCmd.AddCommand(profileShowCmd)
	profileCmd.AddCommand(profileCreateCmd)
	profileCmd.AddCommand(profileEditCmd)
	profileCmd.AddCommand(profileDeleteCmd)
}

// printProfileTopLevel prints its section of a profile's config, if present.
func printProfileTopLevel(p *config.ProfileConfig) {
	if p.Inherits != "" {
		fmt.Printf("inherits = %q\n", p.Inherits)
	}
	if p.Context != "" {
		fmt.Printf("context = %q\n", p.Context)
	}
	if len(p.ForwardEnv) > 0 {
		fmt.Printf("forward_env = [%s]\n", formatStringSlice(p.ForwardEnv))
	}
	if p.EnvCommandTimeout != "" {
		fmt.Printf("env_command_timeout = %q\n", p.EnvCommandTimeout)
	}
}

// printProfileContainer prints its section of a profile's config, if present.
func printProfileContainer(p *config.ProfileConfig) {
	if p.Container.HasContainerConfig() {
		fmt.Println()
		fmt.Println("[container]")
		if p.Container.Image != "" {
			fmt.Printf("image = %q\n", p.Container.Image)
		}
		if p.Container.Persistent != nil {
			fmt.Printf("persistent = %v\n", *p.Container.Persistent)
		}
		if p.Container.Docker != nil {
			fmt.Printf("docker = %v\n", *p.Container.Docker)
		}
		if p.Container.StoragePool != "" {
			fmt.Printf("storage_pool = %q\n", p.Container.StoragePool)
		}
	}
}

// printProfileEnvironment prints its section of a profile's config, if present.
func printProfileEnvironment(p *config.ProfileConfig) {
	if len(p.Environment) > 0 {
		fmt.Println()
		fmt.Println("[environment]")
		keys := make([]string, 0, len(p.Environment))
		for k := range p.Environment {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("%s = %q\n", k, p.Environment[k])
		}
	}
}

// printProfileTool prints its section of a profile's config, if present.
func printProfileTool(p *config.ProfileConfig) {
	if p.Tool != nil {
		fmt.Println()
		fmt.Println("[tool]")
		if p.Tool.Name != "" {
			fmt.Printf("name = %q\n", p.Tool.Name)
		}
		if p.Tool.Binary != "" {
			fmt.Printf("binary = %q\n", p.Tool.Binary)
		}
		if p.Tool.PermissionMode != "" {
			fmt.Printf("permission_mode = %q\n", p.Tool.PermissionMode)
		}
		if p.Tool.ContextFile != "" {
			fmt.Printf("context_file = %q\n", p.Tool.ContextFile)
		}
		if p.Tool.AutoContext != nil {
			fmt.Printf("auto_context = %v\n", *p.Tool.AutoContext)
		}
		if p.Tool.Claude.EffortLevel != "" || p.Tool.Claude.Model != "" {
			fmt.Println()
			fmt.Println("[tool.claude]")
			if p.Tool.Claude.EffortLevel != "" {
				fmt.Printf("effort_level = %q\n", p.Tool.Claude.EffortLevel)
			}
			if p.Tool.Claude.Model != "" {
				fmt.Printf("model = %q\n", p.Tool.Claude.Model)
			}
		}
		if p.Tool.Codex.Model != "" || p.Tool.Codex.ReasoningEffort != "" {
			fmt.Println()
			fmt.Println("[tool.codex]")
			if p.Tool.Codex.Model != "" {
				fmt.Printf("model = %q\n", p.Tool.Codex.Model)
			}
			if p.Tool.Codex.ReasoningEffort != "" {
				fmt.Printf("reasoning_effort = %q\n", p.Tool.Codex.ReasoningEffort)
			}
		}
	}
}

// printProfileBuild prints its section of a profile's config, if present.
func printProfileBuild(p *config.ProfileConfig) {
	if p.Container.Build.HasBuildConfig() {
		fmt.Println()
		fmt.Println("[container.build]")
		if p.Container.Build.Base != "" {
			fmt.Printf("base = %q\n", p.Container.Build.Base)
		}
		if p.Container.Build.Script != "" {
			fmt.Printf("script = %q\n", p.Container.Build.Script)
		}
		if len(p.Container.Build.Commands) > 0 {
			fmt.Printf("commands = [%s]\n", formatStringSlice(p.Container.Build.Commands))
		}
	}
}

// printProfileMounts prints its section of a profile's config, if present.
func printProfileMounts(p *config.ProfileConfig) {
	if len(p.Mounts) > 0 {
		for _, m := range p.Mounts {
			fmt.Println()
			fmt.Println("[[mounts]]")
			fmt.Printf("host = %q\n", m.Host)
			fmt.Printf("container = %q\n", m.Container)
		}
	}
}

// printProfileNetwork prints its section of a profile's config, if present.
func printProfileNetwork(p *config.ProfileConfig) {
	if p.Network != nil {
		fmt.Println()
		fmt.Println("[network]")
		if p.Network.Mode != "" {
			fmt.Printf("mode = %q\n", string(p.Network.Mode))
		}
		if len(p.Network.AllowedDomains) > 0 {
			fmt.Printf("allowed_domains = [%s]\n", formatStringSlice(p.Network.AllowedDomains))
		}
	}
}

// printProfilePaths prints its section of a profile's config, if present.
func printProfilePaths(p *config.ProfileConfig) {
	if p.Paths != nil {
		fmt.Println()
		fmt.Println("[paths]")
		if p.Paths.SessionsDir != "" {
			fmt.Printf("sessions_dir = %q\n", p.Paths.SessionsDir)
		}
		if p.Paths.StorageDir != "" {
			fmt.Printf("storage_dir = %q\n", p.Paths.StorageDir)
		}
		if p.Paths.LogsDir != "" {
			fmt.Printf("logs_dir = %q\n", p.Paths.LogsDir)
		}
		if p.Paths.PreserveWorkspacePath {
			fmt.Println("preserve_workspace_path = true")
		}
	}
}

// printProfileIncus prints its section of a profile's config, if present.
func printProfileIncus(p *config.ProfileConfig) {
	if p.Incus != nil {
		fmt.Println()
		fmt.Println("[incus]")
		if p.Incus.Project != "" {
			fmt.Printf("project = %q\n", p.Incus.Project)
		}
		if p.Incus.Group != "" {
			fmt.Printf("group = %q\n", p.Incus.Group)
		}
		if p.Incus.CodeUID != 0 {
			fmt.Printf("code_uid = %d\n", p.Incus.CodeUID)
		}
		if p.Incus.CodeUser != "" {
			fmt.Printf("code_user = %q\n", p.Incus.CodeUser)
		}
	}
}

// printProfileGit prints its section of a profile's config, if present.
func printProfileGit(p *config.ProfileConfig) {
	if p.Git != nil {
		fmt.Println()
		fmt.Println("[git]")
		if p.Git.WritableHooks != nil {
			fmt.Printf("writable_hooks = %v\n", *p.Git.WritableHooks)
		}
	}
}

// printProfileSSH prints its section of a profile's config, if present.
func printProfileSSH(p *config.ProfileConfig) {
	if p.SSH != nil {
		fmt.Println()
		fmt.Println("[ssh]")
		if p.SSH.ForwardAgent != nil {
			fmt.Printf("forward_agent = %v\n", *p.SSH.ForwardAgent)
		}
	}
}

// printProfileSecurity prints its section of a profile's config, if present.
func printProfileSecurity(p *config.ProfileConfig) {
	if p.Security != nil {
		fmt.Println()
		fmt.Println("[security]")
		if len(p.Security.ProtectedPaths) > 0 {
			fmt.Printf("protected_paths = [%s]\n", formatStringSlice(p.Security.ProtectedPaths))
		}
		if len(p.Security.AdditionalProtectedPaths) > 0 {
			fmt.Printf("additional_protected_paths = [%s]\n", formatStringSlice(p.Security.AdditionalProtectedPaths))
		}
		if p.Security.DisableProtection {
			fmt.Println("disable_protection = true")
		}
		if p.Security.HostImmutable != nil {
			fmt.Printf("host_immutable = %v\n", *p.Security.HostImmutable)
		}
		if len(p.Security.WritablePaths) > 0 {
			fmt.Printf("writable_paths = [%s]\n", formatStringSlice(p.Security.WritablePaths))
		}
		if len(p.Security.SecretPaths) > 0 {
			fmt.Printf("secret_paths = [%s]\n", formatStringSlice(p.Security.SecretPaths))
		}
		if p.Security.ReduceKernelSurface != nil {
			fmt.Printf("reduce_kernel_surface = %v\n", *p.Security.ReduceKernelSurface)
		}
		if p.Security.ReduceKernelSurfaceStrict != nil {
			fmt.Printf("reduce_kernel_surface_strict = %v\n", *p.Security.ReduceKernelSurfaceStrict)
		}
	}
}

// printProfileMonitoring prints its section of a profile's config, if present.
func printProfileMonitoring(p *config.ProfileConfig) {
	if p.Monitoring != nil {
		fmt.Println()
		fmt.Println("[monitoring]")
		if p.Monitoring.Enabled != nil {
			fmt.Printf("enabled = %v\n", *p.Monitoring.Enabled)
		}
		if p.Monitoring.AutoPauseOnHigh != nil {
			fmt.Printf("auto_pause_on_high = %v\n", *p.Monitoring.AutoPauseOnHigh)
		}
		if p.Monitoring.AutoKillOnCritical != nil {
			fmt.Printf("auto_kill_on_critical = %v\n", *p.Monitoring.AutoKillOnCritical)
		}
	}
}

// printProfileTimezone prints its section of a profile's config, if present.
func printProfileTimezone(p *config.ProfileConfig) {
	if p.Timezone != nil {
		fmt.Println()
		fmt.Println("[timezone]")
		if p.Timezone.Mode != "" {
			fmt.Printf("mode = %q\n", p.Timezone.Mode)
		}
		if p.Timezone.Name != "" {
			fmt.Printf("name = %q\n", p.Timezone.Name)
		}
	}
}
