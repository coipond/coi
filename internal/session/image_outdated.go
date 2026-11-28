package session

import (
	"fmt"

	"github.com/coipond/coi/internal/container"
)

// WarnOutdatedImage logs a warning when a reused persistent container was
// created from an older build of its image: a persistent container keeps its
// image until it is recreated.
func WarnOutdatedImage(containerName string, logger func(string)) {
	alias := container.OutdatedImageAlias(containerName)
	if alias == "" {
		return
	}
	logger(fmt.Sprintf(
		"Warning: container %s runs an older build of image %s (the image was rebuilt after the container was created); "+
			"to use the new image, run 'coi shutdown %s', then start again to recreate it",
		containerName, alias, containerName))
}
