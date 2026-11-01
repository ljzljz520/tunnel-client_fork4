package runtimeharpoon

import (
	"context"
	"io"
	"log/slog"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
	"github.com/openai/tunnel-client/pkg/runtimeharpoon/hostbus"
	"github.com/openai/tunnel-client/pkg/runtimeharpoon/internal/hostclassifier"
)

func snapshotTestRegistry(t *testing.T, limit int, seeds ...Target) *Registry {
	t.Helper()
	var (
		registry *Registry
		err      error
	)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if limit > 0 {
		registry, err = NewRegistryWithLimit(logger, false, seeds, limit)
	} else {
		registry, err = NewRegistry(logger, false, seeds)
	}
	require.NoError(t, err)
	return registry
}

func snapshotRecordForTest(t *testing.T, rawURL, role, index string) hostbus.URLRecord {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)
	return hostbus.URLRecord{
		URL: parsed,
		Tags: []hostbus.Tag{
			{Key: hostbus.TagKeySource, Value: hostbus.SourceOAuth},
			{Key: hostbus.TagKeyRole, Value: role},
			{Key: hostbus.TagKeyIndex, Value: index},
		},
	}
}

func snapshotBundleForTest(generation uint64, records ...hostbus.URLRecord) hostbus.URLBundle {
	return hostbus.URLBundle{
		Snapshot: &hostbus.BundleSnapshot{Source: hostbus.SourceOAuth, Generation: generation},
		URLs:     records,
	}
}

func privateHostClassifier() *hostclassifier.HostClassifier {
	return hostclassifier.NewHostClassifier(runtimeconfig.HarpoonHostClassifierConfig{IncludePrivate: true})
}

func TestRegisterHostBundleSnapshotReconcilesGenerationsAndStabilizesLabels(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	registry := reconcileRegistry(t, Target{
		Label:    "manual-api",
		Category: "config",
		Source:   "config",
		BaseURL:  reconcileExactTarget(t, "", "https://manual.example.test").BaseURL,
	})
	classifier := privateHostClassifier()

	first := snapshotBundleForTest(1,
		snapshotRecordForTest(t, "https://10.0.0.1/", "issuer", "0"),
		snapshotRecordForTest(t, "https://10.0.0.2/token", "token-endpoint", "0"),
	)
	require.NoError(t, registerHostBundle(first, classifier, registry, logger))
	require.True(t, registry.Count() >= 3)
	_, ok := registry.Lookup("oauth-issuer-0")
	require.True(t, ok)
	_, ok = registry.Lookup("oauth-token-endpoint-0")
	require.True(t, ok)

	// Repeated identical discovery must not add numeric-suffixed labels.
	require.NoError(t, registerHostBundle(snapshotBundleForTest(2, first.URLs...), classifier, registry, logger))
	require.Equal(t, 3, registry.Count())
	for _, target := range registry.Targets() {
		if target.Source == "oauth" {
			require.NotContains(t, target.Label, "-1")
		}
	}

	// Generation 3 drops the issuer; the retained endpoint keeps its label.
	require.NoError(t, registerHostBundle(snapshotBundleForTest(3,
		snapshotRecordForTest(t, "https://10.0.0.2/token", "token-endpoint", "0"),
		snapshotRecordForTest(t, "https://10.0.0.3/jwks", "jwks-uri", "0"),
	), classifier, registry, logger))

	_, ok = registry.Lookup("oauth-issuer-0")
	require.False(t, ok, "missing endpoint must be revoked from invocation")
	issuerURL := snapshotRecordForTest(t, "https://10.0.0.1/", "issuer", "0").URL
	require.False(t, registry.AllowsURL(issuerURL), "missing endpoint must lose redirect permission")
	rewriter := newURLRewriter(registry.Targets())
	_, ok = rewriter.RewriteURLString("https://10.0.0.1/")
	require.False(t, ok, "missing endpoint must stop address rewriting")

	_, ok = registry.Lookup("oauth-token-endpoint-0")
	require.True(t, ok, "repeated endpoint keeps a stable label")
	_, ok = registry.Lookup("oauth-jwks-uri-0")
	require.True(t, ok)
	_, ok = registry.Lookup("manual-api")
	require.True(t, ok, "manual targets are retained across reconciliation")
}

func TestRegisterHostBundleSnapshotReverseOrderIsIgnored(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	registry := snapshotTestRegistry(t, 0)
	classifier := privateHostClassifier()

	require.NoError(t, registerHostBundle(snapshotBundleForTest(2,
		snapshotRecordForTest(t, "https://10.0.0.2/", "issuer", "0"),
	), classifier, registry, logger))
	// Older snapshot arriving after the newer one must not change the catalog.
	require.NoError(t, registerHostBundle(snapshotBundleForTest(1,
		snapshotRecordForTest(t, "https://10.0.0.1/", "issuer", "0"),
	), classifier, registry, logger))
	// Re-delivering the applied generation is likewise a no-op.
	require.NoError(t, registerHostBundle(snapshotBundleForTest(2,
		snapshotRecordForTest(t, "https://10.0.0.9/", "issuer", "0"),
	), classifier, registry, logger))

	require.Equal(t, 1, registry.Count())
	_, ok := registry.Lookup("oauth-issuer-0")
	require.True(t, ok)
	target, ok := registry.TargetForURL(snapshotRecordForTest(t, "https://10.0.0.2/", "issuer", "0").URL)
	require.True(t, ok)
	require.Equal(t, "oauth-issuer-0", target.Label)
	require.False(t, registry.AllowsURL(snapshotRecordForTest(t, "https://10.0.0.1/", "issuer", "0").URL))
	require.False(t, registry.AllowsURL(snapshotRecordForTest(t, "https://10.0.0.9/", "issuer", "0").URL))
}

func TestRegisterHostBundleSnapshotFailureAndBarrierBundlesDoNotRevoke(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	registry := snapshotTestRegistry(t, 1)
	classifier := privateHostClassifier()

	require.NoError(t, registerHostBundle(snapshotBundleForTest(1,
		snapshotRecordForTest(t, "https://10.0.0.1/", "issuer", "0"),
	), classifier, registry, logger))
	require.Equal(t, 1, registry.Count())

	// A second snapshot that would exceed the registry limit fails globally and
	// leaves the previous complete catalog in place.
	require.NoError(t, registerHostBundle(snapshotBundleForTest(2,
		snapshotRecordForTest(t, "https://10.0.0.1/", "issuer", "0"),
		snapshotRecordForTest(t, "https://10.0.0.2/token", "token-endpoint", "0"),
	), classifier, registry, logger))
	require.Equal(t, 1, registry.Count(), "failed reconciliation must not partially mutate the catalog")
	_, ok := registry.Lookup("oauth-issuer-0")
	require.True(t, ok)
	require.True(t, registry.AllowsURL(snapshotRecordForTest(t, "https://10.0.0.1/", "issuer", "0").URL))

	// Plain bundles without a snapshot are startup barrier ticks: they never
	// revoke discovered targets.
	require.NoError(t, registerHostBundle(hostbus.URLBundle{}, classifier, registry, logger))
	require.Equal(t, 1, registry.Count())
}

func TestRegisterHostBundleSnapshotEmptyAdmissionRevokesPreviousGeneration(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	registry := snapshotTestRegistry(t, 0)
	admitting := privateHostClassifier()
	rejecting := hostclassifier.NewHostClassifier(runtimeconfig.HarpoonHostClassifierConfig{IncludePrivate: false})

	require.NoError(t, registerHostBundle(snapshotBundleForTest(1,
		snapshotRecordForTest(t, "https://10.0.0.1/", "issuer", "0"),
	), admitting, registry, logger))
	require.Equal(t, 1, registry.Count())

	// Every record rejected by policy is an authoritative empty result, not a
	// discovery failure: the previous generation is fully revoked.
	rejected := snapshotRecordForTest(t, "https://10.0.0.9/register", "registration-endpoint", "0")
	rejected.DisallowPrivateHostRegistration = true
	require.NoError(t, registerHostBundle(snapshotBundleForTest(2, rejected), rejecting, registry, logger))
	require.Equal(t, 0, registry.Count())
	_, ok := registry.Lookup("oauth-issuer-0")
	require.False(t, ok)
	require.False(t, registry.AllowsURL(snapshotRecordForTest(t, "https://10.0.0.1/", "issuer", "0").URL))

	// An explicit empty snapshot has the same revocation semantics.
	require.NoError(t, registerHostBundle(snapshotBundleForTest(3,
		snapshotRecordForTest(t, "https://10.0.0.3/", "issuer", "0"),
	), admitting, registry, logger))
	require.Equal(t, 1, registry.Count())
	require.NoError(t, registerHostBundle(snapshotBundleForTest(4), admitting, registry, logger))
	require.Equal(t, 0, registry.Count())
}

func TestStartHostRegistrationAcksSnapshotAfterAtomicSwap(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	registry := snapshotTestRegistry(t, 0)
	subscriber := make(chan hostbus.URLBundle, 4)
	bus, err := hostbus.New(subscriber)
	require.NoError(t, err)
	lifecycle := &hostRegistrationCaptureLifecycle{}

	require.NoError(t, StartHostRegistration(HostRegistrationParams{
		Lifecycle:  lifecycle,
		Logger:     logger,
		Registry:   registry,
		Config:     &runtimeconfig.HarpoonConfig{HostClassifier: runtimeconfig.HarpoonHostClassifierConfig{IncludePrivate: true}},
		Bus:        bus,
		Subscriber: subscriber,
	}))
	require.NoError(t, lifecycle.hooks[0].OnStart(context.Background()))
	defer func() {
		require.NoError(t, lifecycle.hooks[0].OnStop(context.Background()))
	}()

	// Deliver generation 2 first; acknowledgement only returns once the atomic
	// catalog swap has completed, then deliver an older generation that must be
	// discarded.
	gen2 := snapshotBundleForTest(2,
		snapshotRecordForTest(t, "https://10.0.0.2/", "issuer", "0"),
		snapshotRecordForTest(t, "https://10.0.0.2/token", "token-endpoint", "0"),
	)
	require.NoError(t, hostbus.PublishAndWait(context.Background(), bus, gen2))
	require.Equal(t, 2, registry.Count())

	gen1 := snapshotBundleForTest(1,
		snapshotRecordForTest(t, "https://10.0.0.1/", "issuer", "0"),
	)
	require.NoError(t, hostbus.PublishAndWait(context.Background(), bus, gen1))
	require.Equal(t, 2, registry.Count(), "older generation must not overwrite the newer catalog")
	_, ok := registry.Lookup("oauth-issuer-0")
	require.True(t, ok)
	require.True(t, registry.AllowsURL(snapshotRecordForTest(t, "https://10.0.0.2/", "issuer", "0").URL))
	require.False(t, registry.AllowsURL(snapshotRecordForTest(t, "https://10.0.0.1/", "issuer", "0").URL))

	// A queued snapshot is observed promptly after acknowledgement.
	require.Eventually(t, func() bool {
		return registry.Count() == 2
	}, time.Second, 5*time.Millisecond)
}
