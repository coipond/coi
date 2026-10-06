package session

import "context"

// setupState is the shared state threaded through the Setup pipeline. Each
// phase reads and mutates it in place; splitting Setup's former ~600-line body
// into phase methods keeps them small without changing the sequential data
// flow (result is built up field by field; the handful of intermediate values
// the monolith kept as locals — the resolved image, the reuse decision, the
// probed user, the port plan — live here instead).
type setupState struct {
	opts   SetupOptions
	result *SetupResult

	image         string
	skipLaunch    bool
	hasCodeUser   bool
	resolvedPorts []PublishedPort

	// pendingGuestOps are small in-container steps from earlier phases that
	// ride along with phaseInjectContext's exec instead of paying their own
	// incus round trip.
	pendingGuestOps []guestOp
}

// phase adapts a setupState method to the Phase interface.
func phase(name string, fn func(context.Context) (Teardown, error)) Phase {
	return PhaseFunc{PhaseName: name, RunFn: fn}
}
