package image

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/mensfeld/coi/internal/container"
)

const (
	canonicalSimplestreamsURL = "https://cloud-images.ubuntu.com/releases/streams/v1/com.ubuntu.cloud:released:download.json"
	canonicalBaseURL          = "https://cloud-images.ubuntu.com/"
)

// metaClient is used for small, latency-sensitive requests (simplestreams JSON,
// lxd.tar.xz metadata). A 60-second timeout is generous for files that are
// typically a few hundred bytes to a few KB.
var metaClient = &http.Client{Timeout: 60 * time.Second}

// downloadClient is used for large file transfers (squashfs rootfs, ~450 MB).
// No overall Timeout so a slow-but-active connection isn't killed mid-download;
// ResponseHeaderTimeout prevents a hung server from blocking forever.
// Clones DefaultTransport so proxy settings (HTTP_PROXY/HTTPS_PROXY) and
// default dial/TLS behaviour are inherited.
var downloadClient = func() *http.Client {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// DefaultTransport is always *http.Transport; fall back to a safe default.
		return &http.Client{
			Transport: &http.Transport{ResponseHeaderTimeout: 60 * time.Second},
		}
	}
	t := base.Clone()
	t.ResponseHeaderTimeout = 60 * time.Second
	return &http.Client{Transport: t}
}()

type canonicalStreams struct {
	Products map[string]canonicalProduct `json:"products"`
}

type canonicalProduct struct {
	Versions map[string]canonicalVersion `json:"versions"`
}

type canonicalVersion struct {
	Items map[string]canonicalItem `json:"items"`
}

type canonicalItem struct {
	Ftype  string `json:"ftype"`
	Path   string `json:"path"`
	Sha256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// progressReader wraps an io.Reader and logs download progress every 5%.
type progressReader struct {
	r          io.Reader
	total      int64
	downloaded int64
	lastPct    int
	start      time.Time
	logger     func(string)
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	pr.downloaded += int64(n)

	if pr.total > 0 {
		pct := int(pr.downloaded * 100 / pr.total)
		// Log at every 5% boundary, plus 100% exactly once.
		if pct/5 > pr.lastPct/5 || (pct == 100 && pr.lastPct < 100) {
			pr.lastPct = pct
			mb := pr.downloaded / (1024 * 1024)
			totalMB := pr.total / (1024 * 1024)
			elapsed := time.Since(pr.start).Seconds()
			speed := ""
			if elapsed > 0 {
				mbps := float64(pr.downloaded) / (1024 * 1024) / elapsed
				speed = fmt.Sprintf(" — %.1f MB/s", mbps)
			}
			pr.logger(fmt.Sprintf("  %3d%% (%d / %d MB%s)", pct, mb, totalMB, speed))
		}
	}
	return n, err
}

// EnsureLocalUbuntuImage downloads an Ubuntu image directly from Canonical's CDN
// and imports it into Incus as a local alias. This bypasses Incus's simplestreams
// client, which is incompatible with cloud-images.ubuntu.com. Returns the local
// alias name suitable for use with incus launch.
func EnsureLocalUbuntuImage(version string, logger func(string)) (string, error) {
	if logger == nil {
		logger = func(string) {}
	}
	arch := canonicalArch()
	localAlias := fmt.Sprintf("coi-ubuntu-%s", version)

	exists, err := container.ImageExists(localAlias)
	if err != nil {
		return "", fmt.Errorf("failed to check image: %w", err)
	}
	if exists {
		logger(fmt.Sprintf("Using cached Ubuntu %s image (%s)", version, localAlias))
		return localAlias, nil
	}

	logger(fmt.Sprintf("Fetching Ubuntu %s image index from cloud-images.ubuntu.com...", version))
	lxdURL, squashfsURL, lxdSha256, squashfsSha256, err := fetchUbuntuImageURLs(version, arch)
	if err != nil {
		return "", fmt.Errorf("failed to locate Ubuntu %s image: %w", version, err)
	}

	// Download metadata tarball (small — a few hundred bytes, no progress needed)
	lxdFile, err := downloadToTemp(lxdURL, lxdSha256, metaClient, nil)
	if err != nil {
		return "", fmt.Errorf("failed to download Ubuntu metadata: %w", err)
	}
	defer os.Remove(lxdFile)

	// Download rootfs squashfs (large — several hundred MB)
	logger(fmt.Sprintf("Downloading Ubuntu %s rootfs from cloud-images.ubuntu.com...", version))
	squashfsFile, err := downloadToTemp(squashfsURL, squashfsSha256, downloadClient, logger)
	if err != nil {
		return "", fmt.Errorf("failed to download Ubuntu rootfs: %w", err)
	}
	defer os.Remove(squashfsFile)

	logger(fmt.Sprintf("Importing Ubuntu %s into Incus as '%s'...", version, localAlias))
	if err := container.ImportImage(lxdFile, squashfsFile, localAlias); err != nil {
		return "", fmt.Errorf("failed to import Ubuntu image: %w", err)
	}

	logger(fmt.Sprintf("Ubuntu %s image ready as local alias '%s'", version, localAlias))
	return localAlias, nil
}

func fetchUbuntuImageURLs(version, arch string) (lxdURL, squashfsURL, lxdSha256, squashfsSha256 string, err error) {
	resp, err := metaClient.Get(canonicalSimplestreamsURL) //nolint:gosec // URL is a hardcoded Canonical constant
	if err != nil {
		return "", "", "", "", fmt.Errorf("could not reach cloud-images.ubuntu.com: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", "", "", fmt.Errorf("simplestreams returned HTTP %d", resp.StatusCode)
	}

	var streams canonicalStreams
	if err := json.NewDecoder(resp.Body).Decode(&streams); err != nil {
		return "", "", "", "", fmt.Errorf("failed to parse simplestreams: %w", err)
	}

	productKey := fmt.Sprintf("com.ubuntu.cloud:server:%s:%s", version, arch)
	product, ok := streams.Products[productKey]
	if !ok {
		return "", "", "", "", fmt.Errorf("ubuntu %s (%s) not found in Canonical simplestreams", version, arch)
	}

	if len(product.Versions) == 0 {
		return "", "", "", "", fmt.Errorf("ubuntu %s (%s): no versions found in Canonical simplestreams", version, arch)
	}

	// Pick the latest version by sorted key
	keys := make([]string, 0, len(product.Versions))
	for k := range product.Versions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	latest := product.Versions[keys[len(keys)-1]]

	for _, item := range latest.Items {
		switch item.Ftype {
		case "lxd.tar.xz":
			lxdURL = canonicalBaseURL + item.Path
			lxdSha256 = item.Sha256
		case "squashfs":
			squashfsURL = canonicalBaseURL + item.Path
			squashfsSha256 = item.Sha256
		}
	}

	if lxdURL == "" || squashfsURL == "" {
		return "", "", "", "", fmt.Errorf("ubuntu %s (%s): lxd.tar.xz or squashfs not found in latest release", version, arch)
	}

	return lxdURL, squashfsURL, lxdSha256, squashfsSha256, nil
}

// downloadToTemp downloads url to a temporary file, optionally reporting progress
// via logger (pass nil to suppress progress output). The download is verified
// against expectedSha256 if non-empty.
func downloadToTemp(url, expectedSha256 string, client *http.Client, logger func(string)) (string, error) {
	resp, err := client.Get(url) //nolint:gosec // URL is always cloud-images.ubuntu.com from our simplestreams parser
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d downloading %s", resp.StatusCode, url)
	}

	tmp, err := os.CreateTemp("", "coi-ubuntu-*.tmp")
	if err != nil {
		return "", err
	}

	var src io.Reader = resp.Body
	if logger != nil && resp.ContentLength > 0 {
		src = &progressReader{
			r:      resp.Body,
			total:  resp.ContentLength,
			start:  time.Now(),
			logger: logger,
		}
	}

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), src); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", fmt.Errorf("write failed: %w", err)
	}
	tmp.Close()

	if expectedSha256 != "" {
		got := hex.EncodeToString(h.Sum(nil))
		if got != expectedSha256 {
			os.Remove(tmp.Name())
			return "", fmt.Errorf("sha256 mismatch for %s: expected %s, got %s", url, expectedSha256, got)
		}
	}

	return tmp.Name(), nil
}

// canonicalArch maps Go's GOARCH to the architecture name used in Canonical's
// simplestreams product keys.
func canonicalArch() string {
	switch runtime.GOARCH {
	case "arm64":
		return "arm64"
	case "386":
		return "i386"
	case "ppc64le":
		return "ppc64el"
	case "s390x":
		return "s390x"
	default:
		return "amd64"
	}
}
