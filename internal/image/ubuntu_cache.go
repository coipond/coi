package image

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/coipond/coi/internal/container"
)

// ubuntuCacheAlias matches the aliases EnsureLocalUbuntuImage creates.
var ubuntuCacheAlias = regexp.MustCompile(`^coi-ubuntu-(\d+\.\d+)$`)

type cachedImage struct {
	Fingerprint string
	Aliases     []string
}

// ubuntuCachePrune is what PruneUbuntuCache removes: whole images (by one of
// their aliases) and aliases alone, where the image has other aliases.
type ubuntuCachePrune struct {
	Images  []string
	Aliases []string
}

// PruneUbuntuCache removes coi-ubuntu-<ver> base caches that no build needs
// any more: kept are the default BaseImage version and every ubuntu:<ver>
// base recorded in coiDir/image-meta.json for an image that still exists.
// An image an instance was created from is kept; one with aliases of its own
// loses only the cache alias. Failures are logged; it never fails a build.
func PruneUbuntuCache(coiDir string, logger func(string)) {
	if logger == nil {
		logger = func(string) {}
	}
	images, err := listCachedImages()
	if err != nil {
		logger(fmt.Sprintf("Warning: could not list images to prune Ubuntu base caches: %v", err))
		return
	}
	inUse, err := instanceBaseImages()
	if err != nil {
		logger(fmt.Sprintf("Warning: could not list instances to prune Ubuntu base caches: %v", err))
		return
	}

	keep := keptUbuntuVersions(loadMeta(filepath.Join(coiDir, metaFileName)), images)
	plan := planUbuntuCachePrune(images, keep, inUse)
	for _, alias := range plan.Images {
		if err := container.DeleteImage(alias); err != nil {
			logger(fmt.Sprintf("Warning: could not remove unused Ubuntu base image '%s': %v", alias, err))
			continue
		}
		logger(fmt.Sprintf("Removed unused Ubuntu base image '%s'", alias))
	}
	for _, alias := range plan.Aliases {
		if err := container.DeleteImageAlias(alias); err != nil {
			logger(fmt.Sprintf("Warning: could not remove unused alias '%s': %v", alias, err))
			continue
		}
		logger(fmt.Sprintf("Removed unused alias '%s'", alias))
	}
}

// keptUbuntuVersions returns the Ubuntu versions whose cache a later build
// may need: the default base, and the base of each recorded build whose
// image still exists.
func keptUbuntuVersions(meta map[string]BuildMeta, images []cachedImage) map[string]bool {
	keep := map[string]bool{}
	if v, ok := strings.CutPrefix(BaseImage, "ubuntu:"); ok {
		keep[v] = true
	}
	present := map[string]bool{}
	for _, img := range images {
		for _, a := range img.Aliases {
			present[a] = true
		}
	}
	for alias, m := range meta {
		if v, ok := strings.CutPrefix(m.BaseImage, "ubuntu:"); ok && present[alias] {
			keep[v] = true
		}
	}
	return keep
}

// planUbuntuCachePrune picks the coi-ubuntu-<ver> aliases whose version is
// not in keep. An image goes whole only when all its aliases go and no
// instance uses it (inUse holds fingerprints); an image with other aliases
// loses just the stale ones; an image an instance uses is left alone.
func planUbuntuCachePrune(images []cachedImage, keep, inUse map[string]bool) ubuntuCachePrune {
	var plan ubuntuCachePrune
	for _, img := range images {
		var stale []string
		for _, a := range img.Aliases {
			if m := ubuntuCacheAlias.FindStringSubmatch(a); m != nil && !keep[m[1]] {
				stale = append(stale, a)
			}
		}
		switch {
		case len(stale) == 0 || inUse[img.Fingerprint]:
		case len(stale) == len(img.Aliases):
			plan.Images = append(plan.Images, stale[0])
		default:
			plan.Aliases = append(plan.Aliases, stale...)
		}
	}
	return plan
}

func listCachedImages() ([]cachedImage, error) {
	output, err := container.IncusOutput("image", "list", "--format=json")
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Fingerprint string `json:"fingerprint"`
		Aliases     []struct {
			Name string `json:"name"`
		} `json:"aliases"`
	}
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		return nil, err
	}
	images := make([]cachedImage, 0, len(raw))
	for _, r := range raw {
		img := cachedImage{Fingerprint: r.Fingerprint}
		for _, a := range r.Aliases {
			img.Aliases = append(img.Aliases, a.Name)
		}
		images = append(images, img)
	}
	return images, nil
}

// instanceBaseImages returns the fingerprints of the images instances in any
// project were created from.
func instanceBaseImages() (map[string]bool, error) {
	output, err := container.IncusOutputAllProjects("list", "--format=json")
	if err != nil {
		return nil, err
	}
	var instances []struct {
		Config map[string]string `json:"config"`
	}
	if err := json.Unmarshal([]byte(output), &instances); err != nil {
		return nil, err
	}
	inUse := map[string]bool{}
	for _, inst := range instances {
		if fp := inst.Config["volatile.base_image"]; fp != "" {
			inUse[fp] = true
		}
	}
	return inUse, nil
}
