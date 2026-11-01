package runtimeharpoon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"

	tclog "github.com/openai/tunnel-client/pkg/log"
	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

var labelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

const defaultRegistryLimit = 10000
const defaultRedirectExplainCacheLimit = 256
const maxRedirectExplainCacheKeyBytes = 2048

// Target describes a registered outbound HTTP target.
type Target struct {
	Label           string
	Description     string
	Category        string
	Source          string
	Tags            []string
	InclusionReason string
	BaseURL         *url.URL
	UnixSocketPath  string
	// Template is accepted only on registration and compiled into private policy.
	Template *runtimeconfig.HarpoonTargetTemplate
	template *TargetTemplate

	// originalURL preserves discovery spelling for package-owned adapters;
	// BaseURL remains normalized for routing and allowlist checks.
	originalURL *url.URL
}

// IsTemplate identifies operations that require parameters before dispatch.
func (t Target) IsTemplate() bool { return t.template != nil || t.Template != nil }

// IsLoopbackHTTPTemplate reports a compiled template authorized for direct
// loopback HTTP. Uncompiled input does not satisfy this policy.
func (t Target) IsLoopbackHTTPTemplate() bool { return t.template != nil && t.template.loopbackHTTP }

// Registry stores allowed targets keyed by label.
type Registry struct {
	logger            *slog.Logger
	allowPlaintext    bool
	limit             int
	mu                sync.RWMutex
	targets           map[string]Target
	ordered           []Target
	targetURLKeys     map[string]struct{}
	explainCacheLimit int
	explainCache      map[string]redirectExplainCacheEntry
	explainCacheOrder []string
	stateCh           chan struct{}
	discoveryBytes    int
	hasRichTemplates  bool

	// dynamicOwners maps labels introduced through source snapshot
	// reconciliation to their owning source. Only these labels are revoked by
	// a newer snapshot; operator config and other additive registrations stay
	// outside the map and survive every reconciliation.
	dynamicOwners map[string]string
	// sourceGenerations records the last applied snapshot generation per
	// source. Older or equal generations arriving out of order are ignored.
	sourceGenerations map[string]uint64
}

// RegistryCounter is the minimal cross-package contract needed by polling and
// dispatch code to decide whether the Harpoon channel is routable.
type RegistryCounter interface {
	Count() int
}

type redirectMismatchDetails struct {
	Kind           redirectMismatchKind
	ExpectedURL    string
	ExpectedScheme string
	ActualScheme   string
	Reason         string
}

type redirectMismatchKind string

// RedirectMismatchDetails describes why a redirect does not match an allowed target.
//
// Exported aliases let thin adapters preserve their existing package-local
// names without copying registry behavior.
type RedirectMismatchDetails = redirectMismatchDetails
type RedirectMismatchKind = redirectMismatchKind

const (
	redirectMismatchSchemeHTTPToHTTPS redirectMismatchKind = "scheme_mismatch_http_to_https"
	redirectMismatchSchemeHTTPSToHTTP redirectMismatchKind = "scheme_mismatch_https_to_http"
	redirectMismatchPath              redirectMismatchKind = "path_mismatch"
	redirectMismatchQuery             redirectMismatchKind = "query_mismatch"
	redirectMismatchHost              redirectMismatchKind = "host_mismatch"
	redirectMismatchOther             redirectMismatchKind = "not_allowlisted_other"
)

const (
	RedirectMismatchSchemeHTTPToHTTPS = redirectMismatchSchemeHTTPToHTTPS
	RedirectMismatchSchemeHTTPSToHTTP = redirectMismatchSchemeHTTPSToHTTP
	RedirectMismatchPath              = redirectMismatchPath
	RedirectMismatchQuery             = redirectMismatchQuery
	RedirectMismatchHost              = redirectMismatchHost
	RedirectMismatchOther             = redirectMismatchOther
)

type redirectExplainCacheEntry struct {
	hasDetails bool
	details    redirectMismatchDetails
}

// NewRegistry constructs a registry seeded with the provided targets and a default limit.
func NewRegistry(logger *slog.Logger, allowPlaintext bool, targets []Target) (*Registry, error) {
	return NewRegistryWithLimit(logger, allowPlaintext, targets, defaultRegistryLimit)
}

// NewRegistryWithLimit constructs a registry with a maximum number of targets.
func NewRegistryWithLimit(logger *slog.Logger, allowPlaintext bool, targets []Target, limit int) (*Registry, error) {
	if logger == nil {
		return nil, errors.New("harpoon: logger is required")
	}
	if limit <= 0 {
		return nil, errors.New("harpoon: registry limit must be positive")
	}
	registry := &Registry{
		logger:            logger,
		allowPlaintext:    allowPlaintext,
		limit:             limit,
		targets:           make(map[string]Target, len(targets)),
		ordered:           make([]Target, 0, len(targets)),
		targetURLKeys:     make(map[string]struct{}, len(targets)),
		explainCacheLimit: defaultRedirectExplainCacheLimit,
		explainCache:      make(map[string]redirectExplainCacheEntry),
		explainCacheOrder: make([]string, 0, defaultRedirectExplainCacheLimit),
		stateCh:           make(chan struct{}),
		dynamicOwners:     make(map[string]string),
		sourceGenerations: make(map[string]uint64),
	}
	for _, target := range targets {
		if err := registry.RegisterTarget(target); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

// SourceTargetSkip describes a snapshot candidate that could not join a
// reconciled catalog. The remainder of the snapshot is still admitted; skips
// mirror the per-record admission policy of additive registration.
type SourceTargetSkip struct {
	Index int
	Label string
	Err   error
}

// SourceReplacementResult reports the outcome of a snapshot reconciliation.
type SourceReplacementResult struct {
	// Applied reports whether the generation became the live catalog version.
	// It is false for stale generations, in which case all other fields are
	// empty.
	Applied bool
	// Stale identifies a generation at or below the source's already-applied
	// generation. Stale snapshots never mutate the catalog.
	Stale      bool
	Source     string
	Generation uint64
	// Labels lists admitted labels in snapshot candidate order, including
	// collision-resolved spellings.
	Labels []string
	// AddedLabels lists admitted labels that were not owned by this source in
	// the previous catalog version.
	AddedLabels []string
	// RevokedLabels lists labels this source previously owned but the new
	// snapshot no longer admits.
	RevokedLabels []string
	// Skipped lists candidates rejected during validation or collision checks.
	Skipped []SourceTargetSkip
}

// ReplaceSourceTargets atomically reconciles the reconcile-managed targets
// owned by source with the complete candidate set carried by one discovery
// snapshot.
//
// Generation ordering: a generation at or below the source's already-applied
// generation is ignored without touching the catalog, so an older discovery
// arriving out of order can never overwrite newer results.
//
// On application every target previously introduced for source is revoked
// and replaced by the snapshot's admitted targets in a single locked
// transition. Invocation lookup, redirect allowlisting, and response URL
// rewriting therefore never observe a half-rebuilt catalog. Targets created
// through RegisterTarget (including operator config) and targets owned by
// other sources are retained. A successful snapshot with no admitted targets
// revokes every target the source previously owned.
func (r *Registry) ReplaceSourceTargets(source string, generation uint64, candidates []Target) (SourceReplacementResult, error) {
	if r == nil {
		return SourceReplacementResult{}, errors.New("harpoon: registry is nil")
	}
	source = normalizeToken(source)
	if source == "" {
		return SourceReplacementResult{}, errors.New("harpoon: snapshot source is required")
	}
	result := SourceReplacementResult{Source: source, Generation: generation}

	type preparedTarget struct {
		index          int
		target         Target
		discoveryBytes int
	}
	prepared := make([]preparedTarget, 0, len(candidates))
	// Validate every candidate outside the catalog lock. No catalog state
	// changes until the whole replacement version is known to be constructible.
	for idx, candidate := range candidates {
		clean, discoveryBytes, err := r.prepareTarget(candidate)
		if err != nil {
			result.Skipped = append(result.Skipped, SourceTargetSkip{Index: idx, Label: strings.TrimSpace(candidate.Label), Err: err})
			continue
		}
		prepared = append(prepared, preparedTarget{index: idx, target: clean, discoveryBytes: discoveryBytes})
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if previous, ok := r.sourceGenerations[source]; ok && generation <= previous {
		result.Stale = true
		return result, nil
	}

	previousOwned := make(map[string]struct{})
	for label, owner := range r.dynamicOwners {
		if owner == source {
			previousOwned[label] = struct{}{}
		}
	}

	// Retain everything this source does not own, preserving catalog order.
	retained := make([]Target, 0, len(r.ordered))
	occupiedLabels := make(map[string]struct{}, len(r.targets))
	urlTransports := make(map[string]string)
	retainedDiscoveryBytes := 0
	retainedHasRichTemplates := false
	for _, target := range r.ordered {
		if owner, owned := r.dynamicOwners[target.Label]; owned && owner == source {
			// Owned labels are provisionally released; labels the new
			// snapshot re-admits are removed from the revoked set below.
			continue
		}
		retained = append(retained, target)
		occupiedLabels[target.Label] = struct{}{}
		if target.template == nil && target.BaseURL != nil {
			if key, err := normalizedURLKey(target.BaseURL); err == nil {
				urlTransports[key] = target.UnixSocketPath
			}
		}
		bytes, err := targetDiscoveryBytes(target)
		if err != nil {
			return SourceReplacementResult{}, errors.New("harpoon: cannot encode public target discovery")
		}
		retainedDiscoveryBytes += bytes
		if target.template != nil && target.template.HasRichHeaderRules() {
			retainedHasRichTemplates = true
		}
	}

	// Resolve base labels only against retained targets and already-admitted
	// snapshot members. Previously owned labels were released above, so a
	// repeated discovery reuses the same labels instead of growing suffixes.
	admitted := make([]preparedTarget, 0, len(prepared))
	for _, candidate := range prepared {
		base := candidate.target.Label
		label, _ := resolveLabelAgainstOccupied(base, occupiedLabels)
		if label == "" {
			result.Skipped = append(result.Skipped, SourceTargetSkip{Index: candidate.index, Label: base, Err: errors.New("harpoon: no available target label")})
			continue
		}
		candidate.target.Label = label
		if candidate.target.template == nil {
			key, err := normalizedURLKey(candidate.target.BaseURL)
			if err != nil {
				result.Skipped = append(result.Skipped, SourceTargetSkip{Index: candidate.index, Label: label, Err: fmt.Errorf("harpoon: target %q base URL is invalid: %w", label, err)})
				continue
			}
			if existing, exists := urlTransports[key]; exists && existing != candidate.target.UnixSocketPath {
				result.Skipped = append(result.Skipped, SourceTargetSkip{Index: candidate.index, Label: label, Err: fmt.Errorf("harpoon: duplicate target url %q uses a different transport", tclog.RedactURL(candidate.target.BaseURL))})
				continue
			}
			urlTransports[key] = candidate.target.UnixSocketPath
		}
		occupiedLabels[label] = struct{}{}
		admitted = append(admitted, candidate)
		result.Labels = append(result.Labels, label)
		if _, existed := previousOwned[label]; !existed {
			result.AddedLabels = append(result.AddedLabels, label)
		}
	}

	// A previously owned label is revoked only when the new snapshot does
	// not re-admit it; re-admitted labels stay stable across generations.
	admittedSet := make(map[string]struct{}, len(admitted))
	for _, candidate := range admitted {
		admittedSet[candidate.target.Label] = struct{}{}
	}
	for label := range previousOwned {
		if _, ok := admittedSet[label]; !ok {
			result.RevokedLabels = append(result.RevokedLabels, label)
		}
	}
	slices.Sort(result.RevokedLabels)

	if len(retained)+len(admitted) > r.limit {
		return SourceReplacementResult{}, fmt.Errorf("harpoon: registry limit %d exceeded", r.limit)
	}
	discoveryBytes := retainedDiscoveryBytes
	hasRichTemplates := retainedHasRichTemplates
	for _, candidate := range admitted {
		discoveryBytes += candidate.discoveryBytes
		if candidate.target.template != nil && candidate.target.template.HasRichHeaderRules() {
			hasRichTemplates = true
		}
	}
	discoveryBytes = min(maxTemplateCatalogBytes+1, discoveryBytes)
	if hasRichTemplates && discoveryBytes > maxTemplateCatalogBytes {
		return SourceReplacementResult{}, errors.New("harpoon: structured-header discovery exceeds the 512 KiB catalog budget; reduce target metadata or split the catalog")
	}

	// All checks passed: publish one complete replacement version. Readers
	// holding the read lock see either the previous catalog or this one.
	newTargets := make(map[string]Target, len(retained)+len(admitted))
	newOrdered := make([]Target, 0, len(retained)+len(admitted))
	newURLKeys := make(map[string]struct{}, len(r.targetURLKeys))
	newOwners := make(map[string]string, len(r.dynamicOwners)+len(admitted))
	for label, owner := range r.dynamicOwners {
		if owner != source {
			newOwners[label] = owner
		}
	}
	for _, target := range retained {
		newTargets[target.Label] = target
		newOrdered = append(newOrdered, target)
		if target.template == nil {
			if key, err := normalizedURLKey(target.BaseURL); err == nil {
				newURLKeys[key] = struct{}{}
			}
		}
	}
	for _, candidate := range admitted {
		target := candidate.target
		newTargets[target.Label] = target
		newOrdered = append(newOrdered, target)
		newOwners[target.Label] = source
		if target.template == nil {
			if key, err := normalizedURLKey(target.BaseURL); err == nil {
				newURLKeys[key] = struct{}{}
			}
		}
	}

	r.targets = newTargets
	r.ordered = newOrdered
	r.targetURLKeys = newURLKeys
	r.dynamicOwners = newOwners
	r.sourceGenerations[source] = generation
	r.discoveryBytes = discoveryBytes
	r.hasRichTemplates = hasRichTemplates
	r.clearExplainCacheLocked()
	r.signalStateChangeLocked()
	result.Applied = true
	return result, nil
}

// prepareTarget validates and normalizes one target without changing registry
// state. It is shared by additive registration and snapshot reconciliation.
func (r *Registry) prepareTarget(target Target) (Target, int, error) {
	label := strings.TrimSpace(target.Label)
	if label == "" {
		return Target{}, 0, errors.New("harpoon: target label is required")
	}
	if !labelPattern.MatchString(label) {
		return Target{}, 0, fmt.Errorf("harpoon: invalid target label %q", label)
	}
	template := target.template
	if target.Template != nil {
		if target.BaseURL != nil || target.UnixSocketPath != "" {
			return Target{}, 0, fmt.Errorf("harpoon: target %q cannot combine a template with an exact URL or socket", label)
		}
		var err error
		template, err = CompileTargetTemplate(target.Template)
		if err != nil {
			return Target{}, 0, fmt.Errorf("harpoon: target %q: %w", label, err)
		}
		// Origin is metadata only; template targets never enter exact routing.
		origin := template.origin
		target.BaseURL = &origin
	}
	if target.BaseURL == nil {
		return Target{}, 0, fmt.Errorf("harpoon: target %q base URL is required", label)
	}
	if target.BaseURL.Scheme == "" || target.BaseURL.Host == "" {
		return Target{}, 0, fmt.Errorf("harpoon: target %q base URL must include scheme and host", label)
	}
	if !r.allowPlaintext && !isHTTPS(target.BaseURL) && (template == nil || !template.loopbackHTTP) {
		return Target{}, 0, fmt.Errorf("harpoon: target %q base URL must use https", label)
	}
	escapedPath := target.BaseURL.EscapedPath()
	if escapedPath != "" && !strings.HasPrefix(escapedPath, "/") {
		return Target{}, 0, fmt.Errorf("harpoon: target %q base URL path must be absolute", label)
	}
	if hasTraversal(target.BaseURL.Path) {
		return Target{}, 0, fmt.Errorf("harpoon: target %q base URL contains invalid path segments", label)
	}

	normalized, err := normalizeURL(target.BaseURL)
	if err != nil {
		return Target{}, 0, fmt.Errorf("harpoon: target %q base URL is invalid: %w", label, err)
	}
	original := *target.BaseURL

	category, source := normalizeCategorySource(target.Category, target.Source)
	cleanTarget := Target{
		Label:           label,
		Description:     strings.TrimSpace(target.Description),
		Category:        category,
		Source:          source,
		Tags:            normalizeTags(target.Tags),
		InclusionReason: strings.TrimSpace(target.InclusionReason),
		BaseURL:         normalized,
		UnixSocketPath:  strings.TrimSpace(target.UnixSocketPath),
		originalURL:     &original,
		template:        template,
	}
	discoveryBytes, err := targetDiscoveryBytes(cleanTarget)
	if err != nil {
		return Target{}, 0, errors.New("harpoon: cannot encode public target discovery")
	}
	return cleanTarget, discoveryBytes, nil
}

// RegisterTarget adds a target to the registry after validation.
func (r *Registry) RegisterTarget(target Target) error {
	if r == nil {
		return errors.New("harpoon: registry is nil")
	}
	cleanTarget, discoveryBytes, err := r.prepareTarget(target)
	if err != nil {
		return err
	}
	label := cleanTarget.Label

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.targets[label]; exists {
		return fmt.Errorf("harpoon: duplicate target label %q", label)
	}
	if _, exists := r.targetURLKeys[cleanTarget.BaseURL.String()]; cleanTarget.template == nil && exists && r.hasDifferentTransportForURLLocked(cleanTarget.BaseURL, cleanTarget.UnixSocketPath) {
		return fmt.Errorf("harpoon: duplicate target url %q uses a different transport", tclog.RedactURL(cleanTarget.BaseURL))
	}
	if len(r.targets) >= r.limit {
		return fmt.Errorf("harpoon: registry limit %d exceeded", r.limit)
	}
	// Enforce the aggregate bound before changing registry state, including
	// legacy targets that share discovery with a rich-header template. Catalogs
	// without structured rules retain their existing limits; saturated
	// accounting prevents a later rich rule from activating an oversized one.
	hasRichTemplates := r.hasRichTemplates || (cleanTarget.template != nil && cleanTarget.template.HasRichHeaderRules())
	if hasRichTemplates && discoveryBytes > maxTemplateCatalogBytes-r.discoveryBytes {
		return errors.New("harpoon: structured-header discovery exceeds the 512 KiB catalog budget; reduce target metadata or split the catalog")
	}
	r.discoveryBytes = min(maxTemplateCatalogBytes+1, r.discoveryBytes+discoveryBytes)
	r.hasRichTemplates = hasRichTemplates
	r.targets[label] = cleanTarget
	r.ordered = append(r.ordered, cleanTarget)
	if cleanTarget.template == nil {
		r.targetURLKeys[cleanTarget.BaseURL.String()] = struct{}{}
	}
	r.clearExplainCacheLocked()
	r.signalStateChangeLocked()
	return nil
}

func (r *Registry) hasDifferentTransportForURLLocked(candidate *url.URL, unixSocketPath string) bool {
	if r == nil || candidate == nil {
		return false
	}
	candidateKey, err := normalizedURLKey(candidate)
	if err != nil {
		return false
	}
	for _, target := range r.targets {
		if target.BaseURL == nil || target.template != nil {
			continue
		}
		targetKey, keyErr := normalizedURLKey(target.BaseURL)
		if keyErr != nil || targetKey != candidateKey {
			continue
		}
		if target.UnixSocketPath != unixSocketPath {
			return true
		}
	}
	return false
}

// Targets returns a copy of the registered targets in registration order.
func (r *Registry) Targets() []Target {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Target, len(r.ordered))
	for i, target := range r.ordered {
		out[i] = targetSnapshot(target)
	}
	return out
}

// Public metadata must not be mutable after its discovery size is budgeted.
func targetSnapshot(target Target) Target {
	target.Tags = slices.Clone(target.Tags)
	return target
}

// Count reports the number of registered targets.
func (r *Registry) Count() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.targets)
}

// Lookup returns the target for a label.
func (r *Registry) Lookup(label string) (Target, bool) {
	if r == nil {
		return Target{}, false
	}
	label = strings.TrimSpace(label)
	r.mu.RLock()
	defer r.mu.RUnlock()
	target, ok := r.targets[label]
	return targetSnapshot(target), ok
}

// ExactURL returns the pre-normalization URL for a registered target. Thin
// adapters use this for capabilities whose protocol contract requires exact
// URL spelling rather than the normalized routing form.
func (r *Registry) ExactURL(label string) (*url.URL, bool) {
	target, ok := r.Lookup(label)
	if !ok || target.template != nil {
		return nil, false
	}
	if target.originalURL != nil {
		out := *target.originalURL
		return &out, true
	}
	if target.BaseURL == nil {
		return nil, false
	}
	out := *target.BaseURL
	return &out, true
}

// WaitForTarget blocks until a target with the provided label is registered or ctx expires.
func (r *Registry) WaitForTarget(ctx context.Context, label string) (Target, error) {
	if r == nil {
		return Target{}, errors.New("harpoon: registry is nil")
	}
	if ctx == nil {
		return Target{}, errors.New("harpoon: context is required")
	}
	label = strings.TrimSpace(label)
	if label == "" {
		return Target{}, errors.New("harpoon: target label is required")
	}

	for {
		r.mu.RLock()
		target, ok := r.targets[label]
		state := r.stateCh
		r.mu.RUnlock()
		if ok {
			return targetSnapshot(target), nil
		}

		select {
		case <-ctx.Done():
			return Target{}, ctx.Err()
		case <-state:
		}
	}
}

// Resolve returns the target URL for a label.
func (r *Registry) Resolve(label string) (*url.URL, error) {
	target, ok := r.Lookup(label)
	if !ok {
		return nil, fmt.Errorf("unknown target label %q", label)
	}
	if target.template != nil {
		return nil, errors.New("template target requires its discovered invocation schema")
	}
	if target.BaseURL == nil {
		return nil, fmt.Errorf("target %q has empty url", label)
	}
	resolved := *target.BaseURL
	return &resolved, nil
}

func (r *Registry) signalStateChangeLocked() {
	if r.stateCh == nil {
		r.stateCh = make(chan struct{})
		return
	}
	close(r.stateCh)
	r.stateCh = make(chan struct{})
}

// AllowsURL reports whether the URL exactly matches any registered target after
// normalization.
func (r *Registry) AllowsURL(candidate *url.URL) bool {
	if r == nil || candidate == nil {
		return false
	}
	if candidate.Scheme == "" || candidate.Host == "" {
		return false
	}
	if !r.allowPlaintext && !isHTTPS(candidate) {
		return false
	}
	if hasTraversal(candidate.Path) {
		return false
	}
	candidateKey, err := normalizedURLKey(candidate)
	if err != nil {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, target := range r.targets {
		if target.BaseURL == nil || target.template != nil {
			continue
		}
		targetKey, keyErr := normalizedURLKey(target.BaseURL)
		if keyErr != nil {
			continue
		}
		if candidateKey == targetKey {
			return true
		}
	}
	return false
}

// TargetForURL returns the configured target whose URL exactly matches candidate.
func (r *Registry) TargetForURL(candidate *url.URL) (Target, bool) {
	if r == nil || candidate == nil {
		return Target{}, false
	}
	if candidate.Scheme == "" || candidate.Host == "" {
		return Target{}, false
	}
	if !r.allowPlaintext && !isHTTPS(candidate) {
		return Target{}, false
	}
	if hasTraversal(candidate.Path) {
		return Target{}, false
	}
	candidateKey, err := normalizedURLKey(candidate)
	if err != nil {
		return Target{}, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, target := range r.targets {
		if target.BaseURL == nil || target.template != nil {
			continue
		}
		targetKey, keyErr := normalizedURLKey(target.BaseURL)
		if keyErr != nil {
			continue
		}
		if candidateKey == targetKey {
			return targetSnapshot(target), true
		}
	}
	return Target{}, false
}

// ExplainBlockedRedirect classifies why a redirect target missed the allow list.
func (r *Registry) ExplainBlockedRedirect(candidate *url.URL) *redirectMismatchDetails {
	if r == nil || candidate == nil {
		return nil
	}
	if candidate.Scheme == "" || candidate.Host == "" {
		return &redirectMismatchDetails{Kind: redirectMismatchOther, Reason: "redirect target not in allow list"}
	}
	if hasTraversal(candidate.Path) {
		return &redirectMismatchDetails{Kind: redirectMismatchOther, Reason: "redirect target not in allow list"}
	}

	candidateKey, err := normalizedURLKey(candidate)
	if err != nil {
		return &redirectMismatchDetails{Kind: redirectMismatchOther, Reason: "redirect target not in allow list"}
	}
	candidateMatch := analyzeRedirectURL(candidate)
	cacheKey := redirectExplainCacheKey(candidateKey)

	r.mu.RLock()
	if _, ok := r.targetURLKeys[candidateKey]; ok {
		r.mu.RUnlock()
		r.storeRedirectExplanation(cacheKey, nil)
		return nil
	}
	if cached, ok := r.explainCache[cacheKey]; ok {
		r.mu.RUnlock()
		return cloneRedirectMismatchDetails(cached)
	}

	var pathMismatch *Target
	var queryMismatch *Target
	var hostMismatch *Target
	hostMismatchCount := 0
	var result *redirectMismatchDetails

	for _, target := range r.ordered {
		if target.BaseURL == nil || target.template != nil {
			continue
		}
		targetMatch := analyzeRedirectURL(target.BaseURL)
		if targetMatch.host == candidateMatch.host &&
			targetMatch.comparablePath == candidateMatch.comparablePath &&
			targetMatch.query == candidateMatch.query &&
			targetMatch.scheme != candidateMatch.scheme {
			result = &redirectMismatchDetails{
				Kind:           schemeMismatchKind(targetMatch.scheme, candidateMatch.scheme),
				ExpectedURL:    target.BaseURL.String(),
				ExpectedScheme: targetMatch.scheme,
				ActualScheme:   candidateMatch.scheme,
				Reason:         "redirect target not in allow list",
			}
			break
		}

		if pathMismatch == nil &&
			targetMatch.host == candidateMatch.host &&
			targetMatch.scheme == candidateMatch.scheme &&
			targetMatch.query == candidateMatch.query &&
			targetMatch.exactPath != candidateMatch.exactPath {
			targetCopy := target
			pathMismatch = &targetCopy
		}

		if queryMismatch == nil &&
			targetMatch.host == candidateMatch.host &&
			targetMatch.scheme == candidateMatch.scheme &&
			targetMatch.comparablePath == candidateMatch.comparablePath &&
			targetMatch.query != candidateMatch.query {
			targetCopy := target
			queryMismatch = &targetCopy
		}

		if targetMatch.host != candidateMatch.host &&
			targetMatch.scheme == candidateMatch.scheme &&
			targetMatch.comparablePath == candidateMatch.comparablePath &&
			targetMatch.query == candidateMatch.query {
			targetCopy := target
			hostMismatch = &targetCopy
			hostMismatchCount++
		}
	}
	r.mu.RUnlock()

	if result == nil && pathMismatch != nil {
		result = &redirectMismatchDetails{
			Kind:        redirectMismatchPath,
			ExpectedURL: pathMismatch.BaseURL.String(),
			Reason:      "redirect target not in allow list",
		}
	}
	if result == nil && queryMismatch != nil {
		result = &redirectMismatchDetails{
			Kind:        redirectMismatchQuery,
			ExpectedURL: queryMismatch.BaseURL.String(),
			Reason:      "redirect target not in allow list",
		}
	}
	if result == nil && hostMismatch != nil && hostMismatchCount == 1 {
		result = &redirectMismatchDetails{
			Kind:        redirectMismatchHost,
			ExpectedURL: hostMismatch.BaseURL.String(),
			Reason:      "redirect target not in allow list",
		}
	}
	if result == nil {
		result = &redirectMismatchDetails{
			Kind:   redirectMismatchOther,
			Reason: "redirect target not in allow list",
		}
	}
	r.storeRedirectExplanation(cacheKey, result)
	return result
}

func isHTTPS(u *url.URL) bool {
	return strings.EqualFold(u.Scheme, "https")
}

type redirectURLMatch struct {
	scheme         string
	host           string
	exactPath      string
	comparablePath string
	query          string
}

func analyzeRedirectURL(raw *url.URL) redirectURLMatch {
	exactPath := raw.EscapedPath()
	if exactPath == "" {
		exactPath = "/"
	}
	return redirectURLMatch{
		scheme:         strings.ToLower(raw.Scheme),
		host:           strings.ToLower(raw.Host),
		exactPath:      exactPath,
		comparablePath: comparableRedirectPath(exactPath),
		query:          raw.RawQuery,
	}
}

func comparableRedirectPath(path string) string {
	if path == "" {
		return "/"
	}
	trimmed := strings.TrimRight(path, "/")
	if trimmed == "" {
		return "/"
	}
	return trimmed
}

func schemeMismatchKind(expectedScheme, actualScheme string) redirectMismatchKind {
	switch {
	case expectedScheme == "http" && actualScheme == "https":
		return redirectMismatchSchemeHTTPToHTTPS
	case expectedScheme == "https" && actualScheme == "http":
		return redirectMismatchSchemeHTTPSToHTTP
	default:
		return redirectMismatchOther
	}
}

func redirectExplainCacheKey(candidateKey string) string {
	if len(candidateKey) <= maxRedirectExplainCacheKeyBytes {
		return candidateKey
	}
	sum := sha256.Sum256([]byte(candidateKey))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (r *Registry) storeRedirectExplanation(cacheKey string, details *redirectMismatchDetails) {
	if r == nil || cacheKey == "" {
		return
	}
	entry := redirectExplainCacheEntry{}
	if details != nil {
		entry.hasDetails = true
		entry.details = *details
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.explainCache[cacheKey]; !exists {
		r.explainCacheOrder = append(r.explainCacheOrder, cacheKey)
		for len(r.explainCacheOrder) > r.effectiveExplainCacheLimit() {
			evictedKey := r.explainCacheOrder[0]
			r.explainCacheOrder = r.explainCacheOrder[1:]
			delete(r.explainCache, evictedKey)
		}
	}
	r.explainCache[cacheKey] = entry
}

func cloneRedirectMismatchDetails(entry redirectExplainCacheEntry) *redirectMismatchDetails {
	if !entry.hasDetails {
		return nil
	}
	details := entry.details
	return &details
}

func (r *Registry) effectiveExplainCacheLimit() int {
	if r == nil || r.explainCacheLimit <= 0 {
		return defaultRedirectExplainCacheLimit
	}
	return r.explainCacheLimit
}

func (r *Registry) clearExplainCacheLocked() {
	clear(r.explainCache)
	r.explainCacheOrder = r.explainCacheOrder[:0]
}

func normalizeURL(raw *url.URL) (*url.URL, error) {
	if raw == nil {
		return nil, errors.New("url is required")
	}
	if raw.Scheme == "" || raw.Host == "" {
		return nil, errors.New("url must include scheme and host")
	}

	normalized := *raw
	normalized.Scheme = strings.ToLower(normalized.Scheme)
	normalized.Host = strings.ToLower(normalized.Host)
	return &normalized, nil
}

func normalizedURLKey(raw *url.URL) (string, error) {
	normalized, err := normalizeURL(raw)
	if err != nil {
		return "", err
	}
	if normalized.Scheme == "" || normalized.Host == "" {
		return "", errors.New("url must include scheme and host")
	}
	return normalized.String(), nil
}

func hasTraversal(rawPath string) bool {
	for segment := range strings.SplitSeq(rawPath, "/") {
		if segment == "" {
			continue
		}
		unescaped, err := url.PathUnescape(segment)
		if err != nil {
			return true
		}
		if unescaped == "." || unescaped == ".." {
			return true
		}
	}
	return false
}

// SummarizeTargets returns a stable, log-friendly projection of targets.
func (r *Registry) SummarizeTargets() []map[string]string {
	if r == nil {
		return nil
	}
	targets := r.Targets()
	out := make([]map[string]string, 0, len(targets))
	for _, t := range targets {
		base := ""
		if t.BaseURL != nil && !t.IsTemplate() {
			base = tclog.RedactURL(t.BaseURL)
		}
		out = append(out, map[string]string{
			"label": t.Label,
			"url":   base,
			"desc":  t.Description,
		})
	}
	return out
}
