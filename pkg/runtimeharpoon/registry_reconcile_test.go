package runtimeharpoon

import (
	"io"
	"log/slog"
	"net/url"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func reconcileExactTarget(t *testing.T, label, rawURL string) Target {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)
	return Target{Label: label, Category: "oauth", Source: "oauth", BaseURL: parsed}
}

func reconcileRegistry(t *testing.T, seeds ...Target) *Registry {
	t.Helper()
	registry, err := NewRegistry(slog.New(slog.NewTextHandler(io.Discard, nil)), false, seeds)
	require.NoError(t, err)
	return registry
}

func reconcileTargetLabels(targets []Target, source string) []string {
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		if target.Source == source {
			out = append(out, target.Label)
		}
	}
	sort.Strings(out)
	return out
}

func TestReplaceSourceTargetsRevokesEndpointsAcrossInvocationRedirectAndRewriting(t *testing.T) {
	t.Parallel()

	manualURL, err := url.Parse("https://manual.example.test/api")
	require.NoError(t, err)
	registry := reconcileRegistry(t, Target{Label: "manual-api", Category: "config", Source: "config", BaseURL: manualURL})

	first, err := registry.ReplaceSourceTargets("oauth", 1, []Target{
		reconcileExactTarget(t, "snap-a", "https://a.example.test/v1"),
		reconcileExactTarget(t, "snap-b", "https://b.example.test/v1"),
	})
	require.NoError(t, err)
	require.True(t, first.Applied)
	require.ElementsMatch(t, []string{"snap-a", "snap-b"}, first.Labels)
	require.ElementsMatch(t, []string{"snap-a", "snap-b"}, first.AddedLabels)
	require.Empty(t, first.RevokedLabels)

	aURL := reconcileExactTarget(t, "", "https://a.example.test/v1").BaseURL
	bURL := reconcileExactTarget(t, "", "https://b.example.test/v1").BaseURL
	_, ok := registry.Lookup("snap-a")
	require.True(t, ok)
	require.True(t, registry.AllowsURL(aURL))
	rewriter := newURLRewriter(registry.Targets())
	rewritten, ok := rewriter.RewriteURLString("https://a.example.test/v1")
	require.True(t, ok)
	require.Equal(t, "harpoon://snap-a", rewritten)

	// Generation 2 drops snap-a, keeps snap-b at the identical label, adds snap-c.
	second, err := registry.ReplaceSourceTargets("oauth", 2, []Target{
		reconcileExactTarget(t, "snap-b", "https://b.example.test/v1"),
		reconcileExactTarget(t, "snap-c", "https://c.example.test/v1"),
	})
	require.NoError(t, err)
	require.True(t, second.Applied)
	require.ElementsMatch(t, []string{"snap-b", "snap-c"}, second.Labels)
	require.ElementsMatch(t, []string{"snap-c"}, second.AddedLabels)
	require.ElementsMatch(t, []string{"snap-a"}, second.RevokedLabels)

	// Invocation gate.
	_, ok = registry.Lookup("snap-a")
	require.False(t, ok, "revoked endpoint must exit invocation lookup")
	_, err = registry.Resolve("snap-a")
	require.Error(t, err)
	_, ok = registry.Lookup("snap-b")
	require.True(t, ok, "retained endpoint keeps its label across generations")

	// Redirect allowlist gate.
	require.False(t, registry.AllowsURL(aURL), "revoked endpoint must exit redirect permission")
	require.True(t, registry.AllowsURL(bURL))

	// Response address-rewriting gate.
	rewriter = newURLRewriter(registry.Targets())
	rewritten, ok = rewriter.RewriteURLString("https://a.example.test/v1")
	require.False(t, ok, "revoked endpoint must stop response URL rewriting")
	require.Equal(t, "https://a.example.test/v1", rewritten)
	rewritten, ok = rewriter.RewriteURLString("https://b.example.test/v1")
	require.True(t, ok)
	require.Equal(t, "harpoon://snap-b", rewritten, "retained endpoint must keep a stable label")
	rewritten, ok = rewriter.RewriteURLString("https://c.example.test/v1")
	require.True(t, ok)
	require.Equal(t, "harpoon://snap-c", rewritten)

	// Operator-config targets survive every reconciliation.
	manual, ok := registry.Lookup("manual-api")
	require.True(t, ok)
	require.Equal(t, "config", manual.Source)
	require.True(t, registry.AllowsURL(manualURL))
}

func TestReplaceSourceTargetsDuplicateResultsKeepStableLabels(t *testing.T) {
	t.Parallel()

	registry := reconcileRegistry(t)
	candidates := []Target{
		reconcileExactTarget(t, "oauth-issuer-0", "https://issuer.example.test"),
		reconcileExactTarget(t, "oauth-token-endpoint-0", "https://issuer.example.test/token"),
	}

	first, err := registry.ReplaceSourceTargets("oauth", 1, candidates)
	require.NoError(t, err)
	require.True(t, first.Applied)
	require.Equal(t, 2, registry.Count())

	// An identical later snapshot must not grow numeric label suffixes.
	second, err := registry.ReplaceSourceTargets("oauth", 2, candidates)
	require.NoError(t, err)
	require.True(t, second.Applied)
	require.Equal(t, first.Labels, second.Labels)
	require.Empty(t, second.AddedLabels)
	require.Empty(t, second.RevokedLabels)
	require.Equal(t, 2, registry.Count())

	labels := reconcileTargetLabels(registry.Targets(), "oauth")
	require.Equal(t, []string{"oauth-issuer-0", "oauth-token-endpoint-0"}, labels)
}

func TestReplaceSourceTargetsIgnoresOlderAndEqualGenerations(t *testing.T) {
	t.Parallel()

	registry := reconcileRegistry(t)

	gen1, err := registry.ReplaceSourceTargets("oauth", 1, []Target{
		reconcileExactTarget(t, "snap-a", "https://a.example.test"),
	})
	require.NoError(t, err)
	require.True(t, gen1.Applied)

	gen3, err := registry.ReplaceSourceTargets("oauth", 3, []Target{
		reconcileExactTarget(t, "snap-c1", "https://c1.example.test"),
		reconcileExactTarget(t, "snap-c2", "https://c2.example.test"),
	})
	require.NoError(t, err)
	require.True(t, gen3.Applied)

	// Reverse-order delivery: an older snapshot cannot overwrite newer results.
	stale, err := registry.ReplaceSourceTargets("oauth", 2, []Target{
		reconcileExactTarget(t, "snap-b", "https://b.example.test"),
	})
	require.NoError(t, err)
	require.False(t, stale.Applied)
	require.True(t, stale.Stale)

	// Re-delivering the already-applied generation is ignored as well.
	redelivered, err := registry.ReplaceSourceTargets("oauth", 3, []Target{
		reconcileExactTarget(t, "snap-c1", "https://c1.example.test"),
	})
	require.NoError(t, err)
	require.True(t, redelivered.Stale)

	require.ElementsMatch(t, []string{"snap-c1", "snap-c2"}, reconcileTargetLabels(registry.Targets(), "oauth"))
	_, ok := registry.Lookup("snap-b")
	require.False(t, ok, "stale snapshot must not admit any endpoint")
	require.True(t, registry.AllowsURL(reconcileExactTarget(t, "", "https://c1.example.test").BaseURL))
	require.False(t, registry.AllowsURL(reconcileExactTarget(t, "", "https://a.example.test").BaseURL))
}

func TestReplaceSourceTargetsEmptySnapshotRevokesOnlyOwnedSource(t *testing.T) {
	t.Parallel()

	otherURL, err := url.Parse("https://other.example.test/z")
	require.NoError(t, err)
	registry, err := NewRegistryWithLimit(slog.New(slog.NewTextHandler(io.Discard, nil)), false, []Target{
		{Label: "manual-api", Category: "config", Source: "config", BaseURL: otherURL},
	}, 10)
	require.NoError(t, err)

	_, err = registry.ReplaceSourceTargets("oauth", 1, []Target{
		reconcileExactTarget(t, "snap-a", "https://a.example.test"),
		reconcileExactTarget(t, "snap-b", "https://b.example.test"),
	})
	require.NoError(t, err)
	_, err = registry.ReplaceSourceTargets("plugin", 1, []Target{{
		Label: "plugin-a", Category: "plugin", Source: "plugin",
		BaseURL: reconcileExactTarget(t, "", "https://plugin.example.test").BaseURL,
	}})
	require.NoError(t, err)
	require.Equal(t, 4, registry.Count())

	empty, err := registry.ReplaceSourceTargets("oauth", 2, nil)
	require.NoError(t, err)
	require.True(t, empty.Applied)
	require.ElementsMatch(t, []string{"snap-a", "snap-b"}, empty.RevokedLabels)
	require.Empty(t, empty.Labels)

	require.Equal(t, 2, registry.Count(), "empty snapshot revokes only its own source")
	_, ok := registry.Lookup("snap-a")
	require.False(t, ok)
	_, ok = registry.Lookup("manual-api")
	require.True(t, ok, "manual targets are retained")
	_, ok = registry.Lookup("plugin-a")
	require.True(t, ok, "other-source targets are retained")

	// A later generation still applies after an empty one.
	again, err := registry.ReplaceSourceTargets("oauth", 3, []Target{
		reconcileExactTarget(t, "snap-d", "https://d.example.test"),
	})
	require.NoError(t, err)
	require.True(t, again.Applied)
	_, ok = registry.Lookup("snap-d")
	require.True(t, ok)
}

func TestReplaceSourceTargetsKeepsManualLabelCollisionAndOtherSources(t *testing.T) {
	t.Parallel()

	manualURL := reconcileExactTarget(t, "", "https://manual-issuer.example.test").BaseURL
	registry := reconcileRegistry(t, Target{
		Label: "snap-issuer", Category: "config", Source: "config", BaseURL: manualURL,
	})

	result, err := registry.ReplaceSourceTargets("oauth", 1, []Target{
		reconcileExactTarget(t, "snap-issuer", "https://discovered-issuer.example.test"),
	})
	require.NoError(t, err)
	require.True(t, result.Applied)
	require.Equal(t, []string{"snap-issuer-1"}, result.Labels, "manual label wins; auto target gets a suffix")

	manual, ok := registry.Lookup("snap-issuer")
	require.True(t, ok)
	require.Equal(t, "config", manual.Source)
	auto, ok := registry.Lookup("snap-issuer-1")
	require.True(t, ok)
	require.Equal(t, "oauth", auto.Source)

	// Reconciliation never removes the operator target occupying the base label.
	result, err = registry.ReplaceSourceTargets("oauth", 2, []Target{
		reconcileExactTarget(t, "snap-issuer", "https://discovered-issuer.example.test"),
	})
	require.NoError(t, err)
	require.Equal(t, []string{"snap-issuer-1"}, result.Labels)
	_, ok = registry.Lookup("snap-issuer")
	require.True(t, ok)
}

func TestReplaceSourceTargetsGlobalFailureKeepsPreviousCompleteVersion(t *testing.T) {
	t.Parallel()

	registry, err := NewRegistryWithLimit(slog.New(slog.NewTextHandler(io.Discard, nil)), false, []Target{
		reconcileExactTarget(t, "manual-api", "https://manual.example.test"),
	}, 2)
	require.NoError(t, err)

	// Exceeding the registry limit is a global failure: no partial removal.
	_, err = registry.ReplaceSourceTargets("oauth", 1, []Target{
		reconcileExactTarget(t, "snap-a", "https://a.example.test"),
		reconcileExactTarget(t, "snap-b", "https://b.example.test"),
	})
	require.ErrorContains(t, err, "registry limit")
	require.Equal(t, 1, registry.Count())

	// The rejected attempt must not consume the generation.
	applied, err := registry.ReplaceSourceTargets("oauth", 1, []Target{
		reconcileExactTarget(t, "snap-a", "https://a.example.test"),
	})
	require.NoError(t, err)
	require.True(t, applied.Applied)
	require.Equal(t, 2, registry.Count())
}

func TestReplaceSourceTargetsSkipsInvalidCandidateButAppliesSiblingAtomically(t *testing.T) {
	t.Parallel()

	registry := reconcileRegistry(t)
	result, err := registry.ReplaceSourceTargets("oauth", 1, []Target{
		reconcileExactTarget(t, "plain", "http://plaintext.example.test"),
		reconcileExactTarget(t, "secure", "https://secure.example.test"),
	})
	require.NoError(t, err)
	require.True(t, result.Applied)
	require.Len(t, result.Skipped, 1)
	require.Equal(t, 0, result.Skipped[0].Index)
	require.Contains(t, result.Skipped[0].Err.Error(), "must use https")
	require.Equal(t, []string{"secure"}, result.Labels)

	targets := registry.Targets()
	require.Len(t, targets, 1, "the catalog only ever shows the admitted complete version")
	require.Equal(t, "secure", targets[0].Label)
}

func TestReplaceSourceTargetsRequiresSource(t *testing.T) {
	t.Parallel()

	registry := reconcileRegistry(t)
	_, err := registry.ReplaceSourceTargets("  ", 1, nil)
	require.ErrorContains(t, err, "snapshot source is required")
}

// TestReplaceSourceTargetsReadersOnlyObserveCompleteVersions verifies the
// atomic visibility contract under -race: a concurrent call may observe the
// old complete catalog or the new complete catalog, never a partially
// reconciled mix while endpoints are revoked and re-admitted.
func TestReplaceSourceTargetsReadersOnlyObserveCompleteVersions(t *testing.T) {
	t.Parallel()

	registry := reconcileRegistry(t)

	versionA := []Target{
		reconcileExactTarget(t, "snap-a1", "https://a1.example.test"),
		reconcileExactTarget(t, "snap-a2", "https://a2.example.test"),
		reconcileExactTarget(t, "snap-a3", "https://a3.example.test"),
	}
	versionB := []Target{
		reconcileExactTarget(t, "snap-b1", "https://b1.example.test"),
		reconcileExactTarget(t, "snap-b2", "https://b2.example.test"),
		reconcileExactTarget(t, "snap-b3", "https://b3.example.test"),
		reconcileExactTarget(t, "snap-b4", "https://b4.example.test"),
	}

	const iterations = 200
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			expectedA := map[string]struct{}{"snap-a1": {}, "snap-a2": {}, "snap-a3": {}}
			expectedB := map[string]struct{}{"snap-b1": {}, "snap-b2": {}, "snap-b3": {}, "snap-b4": {}}
			for {
				select {
				case <-stop:
					return
				default:
				}
				snapshot := registry.Targets()
				labels := reconcileTargetLabels(snapshot, "oauth")
				set := make(map[string]struct{}, len(labels))
				for _, label := range labels {
					set[label] = struct{}{}
				}
				switch len(set) {
				case 0, len(expectedA), len(expectedB):
				default:
					t.Errorf("reader observed partial catalog: %v", labels)
					return
				}
				if len(set) == len(expectedA) {
					for label := range expectedA {
						if _, ok := set[label]; !ok {
							t.Errorf("reader observed mixed catalog: %v", labels)
							return
						}
					}
				}
				if len(set) == len(expectedB) {
					for label := range expectedB {
						if _, ok := set[label]; !ok {
							t.Errorf("reader observed mixed catalog: %v", labels)
							return
						}
					}
				}
				// The rewriter built for one catalog snapshot must rewrite every
				// URL of that snapshot, i.e. invocation-time address rewriting
				// uses the same complete version.
				rewriter := newURLRewriter(snapshot)
				for _, target := range snapshot {
					if target.Source != "oauth" || target.BaseURL == nil {
						continue
					}
					if _, ok := rewriter.RewriteURLString(target.BaseURL.String()); !ok {
						t.Errorf("catalog snapshot cannot rewrite %q", target.BaseURL.String())
						return
					}
				}
			}
		}()
	}

	for i := uint64(1); i <= iterations; i++ {
		var version []Target
		if i%2 == 1 {
			version = versionA
		} else {
			version = versionB
		}
		result, err := registry.ReplaceSourceTargets("oauth", i, version)
		require.NoError(t, err)
		require.True(t, result.Applied)
	}
	close(stop)
	wg.Wait()
}
