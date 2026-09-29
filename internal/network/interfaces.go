package network

import (
	"context"

	"github.com/mensfeld/coi/internal/config"
)

// NetworkManager is the interface implemented by *Manager.
// Defining it here enables session and cli packages to accept a stub
// in tests without requiring nftables or a live container network.
type NetworkManager interface {
	SetupForContainer(ctx context.Context, containerName string) error
	Teardown(ctx context.Context, containerName string) error
}

// Compile-time assertion: *Manager must satisfy NetworkManager.
var _ NetworkManager = (*Manager)(nil)

// nftRuler is the subset of NftManager behaviour required by Manager.
// It is unexported so that only this package can produce implementations;
// callers outside the package always receive a *Manager via NewManager.
// Tests inside the package may substitute a stub to exercise Manager logic
// without invoking the real nft binary.
type nftRuler interface {
	ApplyAllowlist(cfg *config.NetworkConfig, allowedIPs []string) error
	ApplyRestricted(cfg *config.NetworkConfig) error
	RemoveRules() error
	ReplaceAllowlist(cfg *config.NetworkConfig, allowedIPs []string) error
}

// Compile-time assertion: *NftManager must satisfy nftRuler.
var _ nftRuler = (*NftManager)(nil)
