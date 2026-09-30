package image

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/coipond/coi/internal/container"
)

// ImageInfo contains image metadata
type ImageInfo struct {
	Fingerprint string    `json:"fingerprint"`
	Aliases     []string  `json:"aliases"`
	Size        int64     `json:"size"`
	CreatedAt   time.Time `json:"created_at"`
}

// ListVersions returns all images matching a prefix, sorted by timestamp
// Assumes aliases follow format: prefix-YYYYMMDD-HHMMSS
func ListVersions(prefix string) ([]ImageInfo, error) {
	// Get all images
	output, err := container.IncusOutput("image", "list", "--format=json")
	if err != nil {
		return nil, fmt.Errorf("failed to list images: %w", err)
	}

	var rawImages []struct {
		Fingerprint string                  `json:"fingerprint"`
		Aliases     []struct{ Name string } `json:"aliases"`
		Size        int64                   `json:"size"`
		CreatedAt   time.Time               `json:"created_at"`
	}

	if err := json.Unmarshal([]byte(output), &rawImages); err != nil {
		return nil, fmt.Errorf("failed to parse images: %w", err)
	}

	// Filter and convert to ImageInfo
	var images []ImageInfo
	for _, img := range rawImages {
		for _, alias := range img.Aliases {
			if strings.HasPrefix(alias.Name, prefix) {
				// Extract all matching aliases for this image
				var matchingAliases []string
				for _, a := range img.Aliases {
					if strings.HasPrefix(a.Name, prefix) {
						matchingAliases = append(matchingAliases, a.Name)
					}
				}

				images = append(images, ImageInfo{
					Fingerprint: img.Fingerprint,
					Aliases:     matchingAliases,
					Size:        img.Size,
					CreatedAt:   img.CreatedAt,
				})
				break // Only add image once
			}
		}
	}

	// Sort by primary alias timestamp (extract from first matching alias)
	sort.Slice(images, func(i, j int) bool {
		timeI, errI := ExtractTimestamp(images[i].Aliases[0])
		timeJ, errJ := ExtractTimestamp(images[j].Aliases[0])

		// If timestamp extraction fails, sort by alias name
		if errI != nil || errJ != nil {
			return images[i].Aliases[0] < images[j].Aliases[0]
		}

		return timeI.Before(timeJ)
	})

	return images, nil
}

// ExtractTimestamp parses timestamp from alias like "prefix-20260108-103000"
func ExtractTimestamp(alias string) (time.Time, error) {
	// Pattern: anything followed by -YYYYMMDD-HHMMSS
	pattern := regexp.MustCompile(`-(\d{8})-(\d{6})$`)
	matches := pattern.FindStringSubmatch(alias)

	if len(matches) != 3 {
		return time.Time{}, fmt.Errorf("invalid format: expected suffix -YYYYMMDD-HHMMSS")
	}

	dateStr := matches[1]
	timeStr := matches[2]

	// Parse as YYYYMMDD-HHMMSS -> 20060102-150405
	combined := dateStr + timeStr
	t, err := time.Parse("20060102150405", combined)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	return t, nil
}

// Cleanup deletes old versions, keeping only the N most recent
// Returns lists of deleted and kept aliases
func Cleanup(prefix string, keepCount int) (deleted []string, kept []string, err error) {
	if keepCount <= 0 {
		return nil, nil, fmt.Errorf("keepCount must be > 0")
	}

	// Get all versions
	images, err := ListVersions(prefix)
	if err != nil {
		return nil, nil, err
	}

	if len(images) == 0 {
		return nil, nil, nil
	}

	// Sort by timestamp (oldest first)
	sort.Slice(images, func(i, j int) bool {
		timeI, errI := ExtractTimestamp(images[i].Aliases[0])
		timeJ, errJ := ExtractTimestamp(images[j].Aliases[0])

		if errI != nil || errJ != nil {
			return images[i].Aliases[0] < images[j].Aliases[0]
		}

		return timeI.Before(timeJ)
	})

	// Determine which to delete (oldest ones beyond keepCount)
	deleteCount := len(images) - keepCount
	if deleteCount <= 0 {
		// Keep all
		for _, img := range images {
			kept = append(kept, img.Aliases...)
		}
		return nil, kept, nil
	}

	// Delete old versions
	for i := 0; i < deleteCount; i++ {
		img := images[i]

		// Delete by fingerprint (removes all aliases for this image)
		if err := container.DeleteImage(img.Fingerprint); err != nil {
			return deleted, kept, fmt.Errorf("failed to delete image %s: %w", img.Fingerprint, err)
		}

		deleted = append(deleted, img.Aliases...)
	}

	// Collect kept aliases
	for i := deleteCount; i < len(images); i++ {
		kept = append(kept, images[i].Aliases...)
	}

	return deleted, kept, nil
}

// ListAllImages returns all images with optional prefix filter
func ListAllImages(prefix string) ([]ImageInfo, error) {
	// Get all images
	output, err := container.IncusOutput("image", "list", "--format=json")
	if err != nil {
		return nil, fmt.Errorf("failed to list images: %w", err)
	}

	var rawImages []struct {
		Fingerprint string `json:"fingerprint"`
		Aliases     []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"aliases"`
		Size      int64     `json:"size"`
		CreatedAt time.Time `json:"created_at"`
	}

	if err := json.Unmarshal([]byte(output), &rawImages); err != nil {
		return nil, fmt.Errorf("failed to parse images: %w", err)
	}

	var images []ImageInfo
	for _, img := range rawImages {
		// Extract alias names
		var aliases []string
		for _, alias := range img.Aliases {
			// Apply prefix filter if specified
			if prefix == "" || strings.HasPrefix(alias.Name, prefix) {
				aliases = append(aliases, alias.Name)
			}
		}

		// Only include if has matching aliases
		if len(aliases) > 0 {
			images = append(images, ImageInfo{
				Fingerprint: img.Fingerprint,
				Aliases:     aliases,
				Size:        img.Size,
				CreatedAt:   img.CreatedAt,
			})
		}
	}

	return images, nil
}
