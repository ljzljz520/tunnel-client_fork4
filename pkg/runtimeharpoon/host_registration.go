package runtimeharpoon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"go.uber.org/fx"
	"golang.org/x/net/publicsuffix"

	tclog "github.com/openai/tunnel-client/pkg/log"
	"github.com/openai/tunnel-client/pkg/runtimeconfig"
	"github.com/openai/tunnel-client/pkg/runtimeharpoon/hostbus"
	"github.com/openai/tunnel-client/pkg/runtimeharpoon/internal/hostclassifier"
)

const autoRegistrationPrefix = "oauth"

const (
	oauthSource       = hostbus.SourceOAuth
	rolePRMDResource  = "prmd-resource"
	rolePRMDSource    = "prmd-source"
	registrationScope = "oauth-protected-resource-host"

	loopbackPlaintextRemediation = "use HTTPS, or for trusted local HTTP MCP servers set --harpoon.allow-plaintext-http or HARPOON_ALLOW_PLAINTEXT_HTTP=true"
)

// HostBusSubscriberOut provides the named URL-bundle subscriber used by both
// runtime and full-client Harpoon Fx graphs.
type HostBusSubscriberOut struct {
	fx.Out

	Subscriber chan hostbus.URLBundle `name:"harpoon_hostbus_subscriber"`
}

// HostBusSubscriberIn consumes the named URL-bundle subscriber.
type HostBusSubscriberIn struct {
	fx.In

	Subscriber chan hostbus.URLBundle `name:"harpoon_hostbus_subscriber"`
}

// NewHostBusSubscriber creates the bounded named subscriber channel.
func NewHostBusSubscriber() HostBusSubscriberOut {
	return HostBusSubscriberOut{Subscriber: make(chan hostbus.URLBundle, 16)}
}

// NewHostBus constructs the canonical host-registration bus.
func NewHostBus(p HostBusSubscriberIn) (hostbus.HostRegistrationBus, error) {
	return hostbus.New(p.Subscriber)
}

// HostRegistrationParams contains the shared dependencies for OAuth-discovered
// Harpoon target registration.
type HostRegistrationParams struct {
	fx.In

	Lifecycle      fx.Lifecycle
	Logger         *slog.Logger
	Registry       *Registry
	Config         *runtimeconfig.HarpoonConfig
	ControlPlane   *runtimeconfig.ControlPlaneConfig `optional:"true"`
	DigestState    *startupCatalogDigestState        `optional:"true"`
	StartupCatalog *hostbus.StartupCatalogState      `optional:"true"`
	Bus            hostbus.HostRegistrationBus
	Subscriber     chan hostbus.URLBundle `name:"harpoon_hostbus_subscriber"`
}

// StartHostRegistration wires canonical OAuth host auto-registration.
func StartHostRegistration(p HostRegistrationParams) error {
	if p.Registry == nil || p.Config == nil || p.Lifecycle == nil {
		return nil
	}
	if p.Subscriber == nil {
		return errors.New("harpoon host registration: subscriber channel is required")
	}
	if p.Logger == nil {
		return errors.New("harpoon host registration: logger is required")
	}
	logger := p.Logger.With(tclog.FieldComponent, tclog.ComponentHarpoon)
	classifier := hostclassifier.NewHostClassifier(p.Config.HostClassifier)

	ctx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(fx.Hook{
		OnStart: func(context.Context) error {
			go func() {
				startupPending := p.StartupCatalog != nil
				var startupDone <-chan struct{}
				if startupPending {
					settled := make(chan struct{})
					startupDone = settled
					go func() {
						_ = p.StartupCatalog.Wait(ctx)
						if ctx.Err() != nil {
							return
						}
						close(settled)
					}()
				}

				pending := make([]hostbus.URLBundle, 0)
				processBundle := func(bundle hostbus.URLBundle, captureStartup bool) {
					if ctx.Err() != nil {
						bundle.Acknowledge(ctx.Err())
						return
					}
					err := registerHostBundle(bundle, classifier, p.Registry, logger)
					if ctx.Err() != nil {
						bundle.Acknowledge(ctx.Err())
						return
					}
					if captureStartup {
						bundle.AcknowledgeAfter(err, func() error {
							if ctx.Err() != nil {
								return ctx.Err()
							}
							if p.DigestState == nil {
								return nil
							}
							// Capture while this single consumer still owns the
							// registration boundary. No later bundle can be
							// processed until the startup digest is immutable.
							return p.DigestState.Capture(ctx, p.Registry, p.ControlPlane)
						})
					} else {
						bundle.Acknowledge(err)
					}
					if err != nil {
						logger.Warn("harpoon host auto-registration skipped", slog.String("error", err.Error()))
					}
				}
				flushPending := func() {
					for _, bundle := range pending {
						processBundle(bundle, false)
					}
					pending = pending[:0]
				}

				for {
					select {
					case <-ctx.Done():
						return
					case <-startupDone:
						if ctx.Err() != nil {
							return
						}
						// A hard startup failure never publishes an
						// acknowledgement bundle. Let ordinary later
						// registrations proceed, but leave the digest unset.
						startupPending = false
						startupDone = nil
						flushPending()
					case bundle, ok := <-p.Subscriber:
						if !ok {
							return
						}
						if ctx.Err() != nil {
							bundle.Acknowledge(ctx.Err())
							return
						}
						if startupPending && !bundle.RequiresAcknowledgement() {
							// Preserve startup semantics even if a later OAuth
							// command races ahead of startup discovery.
							pending = append(pending, bundle)
							continue
						}
						if startupPending {
							processBundle(bundle, true)
							startupPending = false
							startupDone = nil
							flushPending()
							continue
						}
						processBundle(bundle, false)
					}
				}
			}()
			return nil
		},
		OnStop: func(context.Context) error {
			cancel()
			if p.Bus != nil {
				_ = p.Bus.Close()
			}
			return nil
		},
	})
	return nil
}

// RegisterHostBundleForConfig applies one discovered URL bundle using the
// canonical runtime classifier. It is primarily a compatibility seam for
// full-client tests and adapters that must not duplicate registration logic.
func RegisterHostBundleForConfig(bundle hostbus.URLBundle, cfg runtimeconfig.HarpoonHostClassifierConfig, registry *Registry, logger *slog.Logger) error {
	return registerHostBundle(bundle, hostclassifier.NewHostClassifier(cfg), registry, logger)
}

func registerHostBundle(bundle hostbus.URLBundle, classifier *hostclassifier.HostClassifier, registry *Registry, logger *slog.Logger) error {
	if registry == nil || classifier == nil {
		return nil
	}
	if logger == nil {
		return errors.New("logger is required")
	}
	if bundle.Snapshot == nil {
		// Bundles without a snapshot keep the historical additive behavior so
		// startup barrier ticks and legacy publishers never revoke targets.
		return registerHostBundleAdditive(bundle, classifier, registry, logger)
	}
	return reconcileHostBundleSnapshot(bundle, classifier, registry, logger)
}

func registerHostBundleAdditive(bundle hostbus.URLBundle, classifier *hostclassifier.HostClassifier, registry *Registry, logger *slog.Logger) error {
	oauthPolicy := newOAuthProtectedResourceHostPolicy(bundle)
	for idx, record := range bundle.URLs {
		if record.URL == nil {
			logger.Info("harpoon host auto-registration skipped: missing url")
			continue
		}
		role := tagValue(record.Tags, hostbus.TagKeyRole)
		source := tagValue(record.Tags, hostbus.TagKeySource)
		group := tagValue(record.Tags, hostbus.TagKeyGroup)
		allowed, reason := shouldRegisterURLRecord(record, classifier, oauthPolicy)
		if !allowed {
			logger.Info("harpoon host auto-registration skipped: not allowed",
				slog.String("url", tclog.RedactURL(record.URL)),
				slog.String("host", record.URL.Hostname()),
				slog.String("source", source),
				slog.String("role", role),
				slog.String("group", group),
				slog.String("exclusion_reason", reason),
			)
			continue
		}
		baseLabel := buildAutoLabel(record, idx)
		if baseLabel == "" {
			logger.Warn("harpoon host auto-registration skipped: empty label",
				slog.String("url", tclog.RedactURL(record.URL)),
				slog.String("source", source),
				slog.String("role", role),
				slog.String("group", group),
				slog.String("inclusion_reason", reason),
			)
			continue
		}
		label, collisionCount := resolveAutoLabelCollision(baseLabel, registry)
		if label == "" {
			logger.Warn("harpoon host auto-registration skipped: no available label",
				slog.String("base_label", baseLabel),
				slog.String("url", tclog.RedactURL(record.URL)),
				slog.String("source", source),
				slog.String("role", role),
				slog.String("group", group),
				slog.String("inclusion_reason", reason),
			)
			continue
		}
		if collisionCount > 0 {
			logger.Info("harpoon host auto-registration resolved label collision",
				slog.String("base_label", baseLabel),
				slog.String("label", label),
				slog.Int("collision_count", collisionCount),
			)
		}
		tags := roleTags(role)
		if normalizedGroup := normalizeToken(group); normalizedGroup != "" {
			tags = append(tags, "group="+normalizedGroup)
		}

		target := Target{
			Label:           label,
			Description:     record.Description,
			Category:        source,
			Source:          source,
			Tags:            tags,
			InclusionReason: reason,
			BaseURL:         record.URL,
			UnixSocketPath:  record.UnixSocketPath,
		}
		if err := registry.RegisterTarget(target); err != nil {
			attrs := []any{
				slog.String("label", label),
				slog.String("url", tclog.RedactURL(record.URL)),
				slog.String("source", source),
				slog.String("role", role),
				slog.String("group", group),
				slog.String("inclusion_reason", reason),
				slog.String("error", err.Error()),
			}
			if reason == "loopback" && strings.EqualFold(record.URL.Scheme, "http") && !registry.allowPlaintext {
				attrs = append(attrs, slog.String("remediation", loopbackPlaintextRemediation))
			}
			logger.Warn("harpoon host auto-registration failed", attrs...)
			continue
		}
		logger.Info("harpoon host auto-registered",
			slog.String("label", label),
			slog.String("url", tclog.RedactURL(record.URL)),
			slog.String("source", target.Source),
			slog.String("role", role),
			slog.String("group", group),
			slog.String("inclusion_reason", reason),
		)
	}
	return nil
}

// admittedHostRecord pairs a snapshot candidate with the logging context of
// the bundle record it was derived from.
type admittedHostRecord struct {
	record    hostbus.URLRecord
	target    Target
	baseLabel string
	role      string
	source    string
	group     string
	reason    string
}

// reconcileHostBundleSnapshot applies one complete generation-ordered catalog
// snapshot. The registry swap is atomic: callers only ever see the previous
// complete catalog or the new one, endpoints missing from the snapshot lose
// invocation, redirect, and rewriting eligibility, while operator targets and
// other sources survive. Older generations are ignored without mutating the
// catalog. A snapshot whose records admit no targets still revokes every
// target the source previously owned; failed discoveries never reach this
// point because publishers send no snapshot for them.
func reconcileHostBundleSnapshot(
	bundle hostbus.URLBundle,
	classifier *hostclassifier.HostClassifier,
	registry *Registry,
	logger *slog.Logger,
) error {
	snapshot := bundle.Snapshot
	oauthPolicy := newOAuthProtectedResourceHostPolicy(bundle)
	admitted := admitHostBundleRecords(bundle, classifier, oauthPolicy, logger)

	candidates := make([]Target, 0, len(admitted))
	for _, entry := range admitted {
		candidates = append(candidates, entry.target)
	}

	result, err := registry.ReplaceSourceTargets(snapshot.Source, snapshot.Generation, candidates)
	if err != nil {
		// The swap is all-or-nothing: the previous complete catalog stays
		// live, and the publisher's acknowledgement only proves processing,
		// not admission, so report and keep serving the retained generation.
		logger.Error("harpoon host snapshot reconciliation failed; previous catalog retained",
			slog.String("source", normalizeToken(snapshot.Source)),
			slog.Uint64("generation", snapshot.Generation),
			slog.String("error", err.Error()),
		)
		return nil
	}
	if result.Stale {
		logger.Info("harpoon host snapshot ignored: older or equal generation",
			slog.String("source", result.Source),
			slog.Uint64("generation", snapshot.Generation),
		)
		return nil
	}

	skipped := make(map[int]struct{}, len(result.Skipped))
	for _, skip := range result.Skipped {
		skipped[skip.Index] = struct{}{}
		entry := admitted[skip.Index]
		attrs := []any{
			slog.String("label", skip.Label),
			slog.String("url", tclog.RedactURL(entry.record.URL)),
			slog.String("source", entry.source),
			slog.String("role", entry.role),
			slog.String("group", entry.group),
			slog.String("inclusion_reason", entry.reason),
			slog.String("error", skip.Err.Error()),
		}
		if entry.reason == "loopback" && strings.EqualFold(entry.record.URL.Scheme, "http") && !registry.allowPlaintext {
			attrs = append(attrs, slog.String("remediation", loopbackPlaintextRemediation))
		}
		logger.Warn("harpoon host auto-registration failed", attrs...)
	}

	added := make(map[string]struct{}, len(result.AddedLabels))
	for _, label := range result.AddedLabels {
		added[label] = struct{}{}
	}
	labelIdx := 0
	for candidateIdx, entry := range admitted {
		if _, isSkipped := skipped[candidateIdx]; isSkipped {
			continue
		}
		label := result.Labels[labelIdx]
		labelIdx++
		if label != entry.baseLabel {
			logger.Info("harpoon host auto-registration resolved label collision",
				slog.String("base_label", entry.baseLabel),
				slog.String("label", label),
			)
		}
		attrs := []any{
			slog.String("label", label),
			slog.String("url", tclog.RedactURL(entry.record.URL)),
			slog.String("source", entry.target.Source),
			slog.String("role", entry.role),
			slog.String("group", entry.group),
			slog.String("inclusion_reason", entry.reason),
		}
		if _, isAdded := added[label]; isAdded {
			logger.Info("harpoon host auto-registered", attrs...)
		} else {
			logger.Debug("harpoon host auto-registration retained across snapshot", attrs...)
		}
	}
	for _, label := range result.RevokedLabels {
		logger.Info("harpoon host auto-registration revoked",
			slog.String("label", label),
			slog.String("source", result.Source),
		)
	}
	logger.Info("harpoon host snapshot reconciled",
		slog.String("source", result.Source),
		slog.Uint64("generation", result.Generation),
		slog.Int("target_count", registry.Count()),
		slog.Int("admitted", len(result.Labels)),
		slog.Int("added", len(result.AddedLabels)),
		slog.Int("revoked", len(result.RevokedLabels)),
		slog.Int("skipped", len(result.Skipped)),
	)
	return nil
}

// admitHostBundleRecords runs the shared classifier and OAuth protected-
// resource host policy over a bundle, logging records that cannot be admitted
// exactly like the additive registration path. Candidate labels are base
// labels; the registry resolves collisions against the post-revocation catalog.
func admitHostBundleRecords(
	bundle hostbus.URLBundle,
	classifier *hostclassifier.HostClassifier,
	oauthPolicy oauthProtectedResourceHostPolicy,
	logger *slog.Logger,
) []admittedHostRecord {
	admitted := make([]admittedHostRecord, 0, len(bundle.URLs))
	for idx, record := range bundle.URLs {
		if record.URL == nil {
			logger.Info("harpoon host auto-registration skipped: missing url")
			continue
		}
		role := tagValue(record.Tags, hostbus.TagKeyRole)
		source := tagValue(record.Tags, hostbus.TagKeySource)
		group := tagValue(record.Tags, hostbus.TagKeyGroup)
		allowed, reason := shouldRegisterURLRecord(record, classifier, oauthPolicy)
		if !allowed {
			logger.Info("harpoon host auto-registration skipped: not allowed",
				slog.String("url", tclog.RedactURL(record.URL)),
				slog.String("host", record.URL.Hostname()),
				slog.String("source", source),
				slog.String("role", role),
				slog.String("group", group),
				slog.String("exclusion_reason", reason),
			)
			continue
		}
		baseLabel := buildAutoLabel(record, idx)
		if baseLabel == "" {
			logger.Warn("harpoon host auto-registration skipped: empty label",
				slog.String("url", tclog.RedactURL(record.URL)),
				slog.String("source", source),
				slog.String("role", role),
				slog.String("group", group),
				slog.String("inclusion_reason", reason),
			)
			continue
		}
		tags := roleTags(role)
		if normalizedGroup := normalizeToken(group); normalizedGroup != "" {
			tags = append(tags, "group="+normalizedGroup)
		}
		admitted = append(admitted, admittedHostRecord{
			record: record,
			target: Target{
				Label:           baseLabel,
				Description:     record.Description,
				Category:        source,
				Source:          source,
				Tags:            tags,
				InclusionReason: reason,
				BaseURL:         record.URL,
				UnixSocketPath:  record.UnixSocketPath,
			},
			baseLabel: baseLabel,
			role:      role,
			source:    source,
			group:     group,
			reason:    reason,
		})
	}
	return admitted
}

type oauthProtectedResourceHostPolicy struct {
	hosts        []oauthProtectedResourceHost
	exactOrigins map[oauthProtectedResourceOrigin]struct{}
}

type oauthProtectedResourceHost struct {
	host           string
	allowSubdomain bool
}

type oauthProtectedResourceOrigin struct {
	scheme string
	host   string
	port   string
}

func newOAuthProtectedResourceHostPolicy(bundle hostbus.URLBundle) oauthProtectedResourceHostPolicy {
	seen := make(map[oauthProtectedResourceHost]struct{})
	hosts := make([]oauthProtectedResourceHost, 0, len(bundle.URLs))
	exactOrigins := make(map[oauthProtectedResourceOrigin]struct{})
	for _, record := range bundle.URLs {
		if !isOAuthURLRecord(record) {
			continue
		}
		if record.DisallowPrivateHostRegistration {
			continue
		}
		switch normalizeToken(tagValue(record.Tags, hostbus.TagKeyRole)) {
		case rolePRMDResource, rolePRMDSource:
		default:
			continue
		}
		if origin, ok := newOAuthProtectedResourceOrigin(record.URL); ok {
			exactOrigins[origin] = struct{}{}
		}
		host := normalizedHostname(record.URL)
		policyHost, ok := newOAuthProtectedResourceHost(host)
		if !ok {
			continue
		}
		if _, ok := seen[policyHost]; ok {
			continue
		}
		seen[policyHost] = struct{}{}
		hosts = append(hosts, policyHost)
	}
	return oauthProtectedResourceHostPolicy{hosts: hosts, exactOrigins: exactOrigins}
}

func newOAuthProtectedResourceHost(host string) (oauthProtectedResourceHost, bool) {
	if host == "" {
		return oauthProtectedResourceHost{}, false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return oauthProtectedResourceHost{host: host}, true
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(host); err != nil {
		return oauthProtectedResourceHost{}, false
	}
	return oauthProtectedResourceHost{host: host, allowSubdomain: true}, true
}

func newOAuthProtectedResourceOrigin(raw *url.URL) (oauthProtectedResourceOrigin, bool) {
	if raw == nil {
		return oauthProtectedResourceOrigin{}, false
	}
	scheme := strings.ToLower(strings.TrimSpace(raw.Scheme))
	if scheme != "http" && scheme != "https" {
		return oauthProtectedResourceOrigin{}, false
	}
	host := normalizedHostname(raw)
	if host == "" {
		return oauthProtectedResourceOrigin{}, false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		host = addr.String()
	}
	port := raw.Port()
	if port != "" {
		if parsedPort, err := strconv.Atoi(port); err == nil {
			port = strconv.Itoa(parsedPort)
		}
	} else if scheme == "http" {
		port = "80"
	} else {
		port = "443"
	}
	return oauthProtectedResourceOrigin{scheme: scheme, host: host, port: port}, true
}

func shouldRegisterURLRecord(record hostbus.URLRecord, classifier *hostclassifier.HostClassifier, oauthPolicy oauthProtectedResourceHostPolicy) (bool, string) {
	if record.URL == nil {
		return false, ""
	}
	private, reason := classifier.IsPrivateHost(record.URL.Hostname())
	if record.DisallowPrivateHostRegistration {
		if oauthPolicy.allows(record) {
			return true, registrationScope
		}
		if private {
			return false, "private-host-registration-disabled"
		}
		return false, reason
	}
	if private {
		return true, reason
	}
	if oauthPolicy.allows(record) {
		return true, registrationScope
	}
	return false, reason
}

func (p oauthProtectedResourceHostPolicy) allows(record hostbus.URLRecord) bool {
	if !isOAuthURLRecord(record) {
		return false
	}
	if record.DisallowPrivateHostRegistration {
		origin, ok := newOAuthProtectedResourceOrigin(record.URL)
		if !ok {
			return false
		}
		_, ok = p.exactOrigins[origin]
		return ok
	}
	if len(p.hosts) == 0 {
		return false
	}
	host := normalizedHostname(record.URL)
	if host == "" {
		return false
	}
	for _, protectedResourceHost := range p.hosts {
		if host == protectedResourceHost.host {
			return true
		}
		if protectedResourceHost.allowSubdomain && strings.HasSuffix(host, "."+protectedResourceHost.host) {
			return true
		}
	}
	return false
}

func isOAuthURLRecord(record hostbus.URLRecord) bool {
	return normalizeToken(tagValue(record.Tags, hostbus.TagKeySource)) == oauthSource
}

func normalizedHostname(u *url.URL) string {
	if u == nil {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(u.Hostname())), ".")
}

func buildAutoLabel(record hostbus.URLRecord, fallbackIndex int) string {
	role := tagValue(record.Tags, hostbus.TagKeyRole)
	index := tagValue(record.Tags, hostbus.TagKeyIndex)
	parts := []string{autoRegistrationPrefix}
	if role != "" {
		parts = append(parts, role)
	}
	if index == "" && fallbackIndex >= 0 {
		index = fmt.Sprintf("%d", fallbackIndex)
	}
	if index != "" {
		parts = append(parts, index)
	}
	return sanitizeLabel(strings.Join(parts, "-"))
}

func resolveAutoLabelCollision(baseLabel string, registry *Registry) (string, int) {
	if baseLabel == "" || registry == nil {
		return "", 0
	}
	registry.mu.RLock()
	occupied := make(map[string]struct{}, len(registry.targets))
	for label := range registry.targets {
		occupied[label] = struct{}{}
	}
	registry.mu.RUnlock()
	return resolveLabelAgainstOccupied(baseLabel, occupied)
}

// resolveLabelAgainstOccupied assigns baseLabel when free and otherwise
// baseLabel-1, baseLabel-2, ... matching the historical collision scheme. The
// reconcile path releases the source's previous labels before building the
// occupied set, so identical snapshots keep identical labels instead of
// accumulating numeric suffixes.
func resolveLabelAgainstOccupied(baseLabel string, occupied map[string]struct{}) (string, int) {
	if baseLabel == "" {
		return "", 0
	}
	for i := range 10_000 {
		candidate := baseLabel
		if i > 0 {
			candidate = labelWithNumericSuffix(baseLabel, i)
		}
		if candidate == "" {
			continue
		}
		if _, exists := occupied[candidate]; exists {
			continue
		}
		return candidate, i
	}
	return "", 0
}

func labelWithNumericSuffix(baseLabel string, suffix int) string {
	if baseLabel == "" || suffix <= 0 {
		return baseLabel
	}

	suffixPart := fmt.Sprintf("-%d", suffix)
	maxBaseLen := 64 - len(suffixPart)
	if maxBaseLen < 1 {
		return ""
	}

	trimmed := baseLabel
	if len(trimmed) > maxBaseLen {
		trimmed = strings.TrimRight(trimmed[:maxBaseLen], "-_")
		if trimmed == "" {
			trimmed = "x"
		}
	}
	return trimmed + suffixPart
}

func tagValue(tags []hostbus.Tag, key hostbus.TagKey) string {
	for _, tag := range tags {
		if tag.Key == key {
			return tag.Value
		}
	}
	return ""
}

var labelSanitizePattern = regexp.MustCompile(`[^a-z0-9_-]+`)

func sanitizeLabel(raw string) string {
	label := strings.ToLower(strings.TrimSpace(raw))
	label = labelSanitizePattern.ReplaceAllString(label, "-")
	label = strings.Trim(label, "-_")
	if label == "" {
		return ""
	}
	if !isLabelStartValid(label[0]) {
		label = "x" + label
	}
	if len(label) > 64 {
		label = label[:64]
	}
	return label
}

func isLabelStartValid(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}
