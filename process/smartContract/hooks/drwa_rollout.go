package hooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	errDRWANilRolloutManifest          = errors.New("nil DRWA rollout manifest")
	errDRWAEmptyRolloutTokenID         = errors.New("empty DRWA rollout token id")
	errDRWAEmptyRolloutIssuer          = errors.New("empty DRWA rollout issuer")
	errDRWAInvalidRolloutStage         = errors.New("invalid DRWA rollout stage")
	errDRWANilRolloutStateReader       = errors.New("nil DRWA rollout state reader")
	errDRWARolloutPolicyMissing        = errors.New("DRWA rollout token policy missing")
	errDRWARolloutNotCanaryReady       = errors.New("DRWA rollout not canary ready")
	errDRWARolloutSafeModeRequired     = errors.New("DRWA rollout requires safe mode clearance")
	errDRWANilRolloutEvidenceSink      = errors.New("nil DRWA rollout evidence sink")
	errDRWANilRolloutVerificationSink  = errors.New("nil DRWA rollout verification sink")
	errDRWANilRolloutPreflightReport   = errors.New("nil DRWA rollout preflight report")
	errDRWANilRolloutMetrics           = errors.New("nil DRWA rollout metrics")
	errDRWANilRolloutVerification      = errors.New("nil DRWA rollout verification report")
	errDRWARolloutVerificationRequired = errors.New("DRWA rollout verification required")
	errDRWARolloutVerificationRejected = errors.New("DRWA rollout verification rejected")
	errDRWARolloutReportTokenMismatch  = errors.New("DRWA rollout report token mismatch")
	errDRWARolloutReportStageMismatch  = errors.New("DRWA rollout report stage mismatch")
	errDRWAInvalidRolloutThresholds    = errors.New("invalid DRWA rollout thresholds")
	errDRWALegacyDenialMismatchCountThreshold = errors.New("legacy DRWA denial mismatch count threshold is no longer supported")
	errDRWARolloutStageNotMonotonic    = errors.New("DRWA rollout stage must progress monotonically: canary → limited → production")
)

const (
	drwaRolloutStageCanary     = "canary"
	drwaRolloutStageLimited    = "limited"
	drwaRolloutStageProduction = "production"

	// SM-5: drwaRolloutMaxFailureRateBpsUpperBound matches the default config
	// value from drwaRolloutDefaultThresholdConfig().MaxFailureRateBpsUpperBound.
	// Defined as a named constant for use in validation and documentation.
	drwaRolloutMaxFailureRateBpsUpperBound uint64 = 100
)

// drwaRolloutThresholdConfig holds the upper-bound caps for rollout verification
// thresholds. Operators supply per-token thresholds in the manifest; these caps
// prevent unreasonably lax values. Loaded from governance state at rollout time.
type drwaRolloutThresholdConfig struct {
	MaxFailureRateBpsUpperBound  uint64 `json:"max_failure_rate_bps_upper_bound"`
	MaxAPIErrorRateBpsUpperBound uint64 `json:"max_api_error_rate_bps_upper_bound"`
	MaxDenialMismatchRateBpsUpperBound uint64 `json:"max_denial_mismatch_rate_bps_upper_bound"`
}

// drwaRolloutDefaultThresholdConfig returns the built-in defaults, used when
// governance has not yet published custom thresholds. These are conservative
// values suitable for initial deployment.
func drwaRolloutDefaultThresholdConfig() drwaRolloutThresholdConfig {
	return drwaRolloutThresholdConfig{
		MaxFailureRateBpsUpperBound:  100,
		MaxAPIErrorRateBpsUpperBound: 100,
		MaxDenialMismatchRateBpsUpperBound: 100,
	}
}

// drwaRolloutConfigReader abstracts governance storage so rollout threshold
// configuration can be loaded from on-chain state during validation.
type drwaRolloutConfigReader interface {
	GetRolloutThresholdConfig(tokenID string) (*drwaRolloutThresholdConfig, error)
}

type drwaRolloutManifest struct {
	TokenID                string   `json:"token_id"`
	Issuer                 string   `json:"issuer"`
	Stage                  string   `json:"stage"`
	ExpectedPolicyVersion  uint64   `json:"expected_policy_version"`
	RequiredHolders        []string `json:"required_holders"`
	AllowSafeModeRollout   bool     `json:"allow_safe_mode_rollout"`
	MaxSyncFailureRateBps  uint64   `json:"max_sync_failure_rate_bps"`
	MaxAPIErrorRateBps     uint64   `json:"max_api_error_rate_bps"`
	MaxDenialMismatchRateBps uint64 `json:"max_denial_mismatch_rate_bps"`
}

func (m *drwaRolloutManifest) UnmarshalJSON(data []byte) error {
	type alias drwaRolloutManifest
	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if _, hasLegacyField := raw["max_denial_mismatch_count"]; hasLegacyField {
		return errDRWALegacyDenialMismatchCountThreshold
	}

	*m = drwaRolloutManifest(decoded)
	return nil
}

type drwaRolloutStateReader interface {
	GetTokenPolicyStored(tokenID string) (*drwaSyncStoredValue, error)
	GetHolderMirrorStored(tokenID, holder string) (*drwaSyncStoredValue, error)
}

type drwaRolloutPreflightReport struct {
	TokenID            string   `json:"token_id"`
	Stage              string   `json:"stage"`
	Checks             []string `json:"checks"`
	MissingHolders     []string `json:"missing_holders"`
	Warnings           []string `json:"warnings"`
	Ready              bool     `json:"ready"`
	RequiresCanaryOnly bool     `json:"requires_canary_only"`
}

type drwaRolloutObservedMetrics struct {
	SyncFailureRateBps  uint64 `json:"sync_failure_rate_bps"`
	APIErrorRateBps     uint64 `json:"api_error_rate_bps"`
	DenialMismatchCount uint64 `json:"denial_mismatch_count"`
	DenialComparisonsTotal uint64 `json:"denial_comparisons_total"`
}

type drwaRolloutVerificationReport struct {
	TokenID      string   `json:"token_id"`
	Stage        string   `json:"stage"`
	PassedChecks []string `json:"passed_checks"`
	FailedChecks []string `json:"failed_checks"`
	Accepted     bool     `json:"accepted"`
}

type drwaRolloutEvidenceSink interface {
	PersistRolloutEvidence(tokenID string, payload []byte) error
}

type drwaRolloutVerificationSink interface {
	PersistRolloutVerification(tokenID string, payload []byte) error
}

// SM-4: drwaRolloutStageStore abstracts on-chain persistence of the last
// completed rollout stage per token. validateDRWARolloutAdmission reads from
// state instead of trusting the caller-supplied lastCompletedStage parameter.
type drwaRolloutStageStore interface {
	GetLastCompletedRolloutStage(tokenID string) (string, error)
	PutLastCompletedRolloutStage(tokenID string, stage string) error
}

// buildDRWARolloutStageKey returns the system account key for persisting the
// last completed rollout stage for a token.
func buildDRWARolloutStageKey(tokenID string) []byte {
	return []byte("drwa:rollout:stage:" + tokenID)
}

func computeDRWADenialMismatchRateBps(mismatchCount, comparisonsTotal uint64) uint64 {
	if comparisonsTotal == 0 {
		return 0
	}
	if mismatchCount >= comparisonsTotal {
		return 10000
	}

	return (mismatchCount * 10000) / comparisonsTotal
}

func validateDRWARolloutManifest(manifest *drwaRolloutManifest, thresholds ...drwaRolloutThresholdConfig) error {
	if manifest == nil {
		return errDRWANilRolloutManifest
	}
	if strings.TrimSpace(manifest.TokenID) == "" {
		return errDRWAEmptyRolloutTokenID
	}
	if strings.TrimSpace(manifest.Issuer) == "" {
		return errDRWAEmptyRolloutIssuer
	}
	switch manifest.Stage {
	case drwaRolloutStageCanary, drwaRolloutStageLimited, drwaRolloutStageProduction:
	default:
		return errDRWAInvalidRolloutStage
	}

	cfg := drwaRolloutDefaultThresholdConfig()
	if len(thresholds) > 0 {
		cfg = thresholds[0]
	}

	// Allow 0 as valid "zero tolerance" threshold.
	// Only reject values exceeding the governance-configured upper bound cap.
	if manifest.MaxSyncFailureRateBps > cfg.MaxFailureRateBpsUpperBound ||
		manifest.MaxAPIErrorRateBps > cfg.MaxAPIErrorRateBpsUpperBound ||
		manifest.MaxDenialMismatchRateBps > cfg.MaxDenialMismatchRateBpsUpperBound {
		return errDRWAInvalidRolloutThresholds
	}

	return nil
}

func inspectDRWARolloutPreflight(reader drwaRolloutStateReader, manifest *drwaRolloutManifest, recoveryReport *drwaRecoveryReport, thresholds ...drwaRolloutThresholdConfig) (*drwaRolloutPreflightReport, error) {
	if reader == nil {
		return nil, errDRWANilRolloutStateReader
	}

	err := validateDRWARolloutManifest(manifest, thresholds...)
	if err != nil {
		return nil, err
	}

	report := &drwaRolloutPreflightReport{
		TokenID: manifest.TokenID,
		Stage:   manifest.Stage,
	}

	policy, err := reader.GetTokenPolicyStored(manifest.TokenID)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, errDRWARolloutPolicyMissing
	}
	if policy.Version != manifest.ExpectedPolicyVersion {
		report.Warnings = append(report.Warnings, fmt.Sprintf("policy version mismatch: expected=%d observed=%d", manifest.ExpectedPolicyVersion, policy.Version))
		report.RequiresCanaryOnly = true
	}
	report.Checks = append(report.Checks, "token policy present")

	for _, holder := range manifest.RequiredHolders {
		holder = strings.TrimSpace(holder)
		if holder == "" {
			continue
		}
		stored, readErr := reader.GetHolderMirrorStored(manifest.TokenID, holder)
		if readErr != nil {
			return nil, readErr
		}
		if stored == nil {
			report.MissingHolders = append(report.MissingHolders, holder)
			continue
		}
		report.Checks = append(report.Checks, "holder mirror present:"+holder)
	}

	if recoveryReport != nil && recoveryReport.RequiresSafeMode {
		if !manifest.AllowSafeModeRollout {
			return nil, errDRWARolloutSafeModeRequired
		}
		report.Warnings = append(report.Warnings, "safe mode still required by latest recovery report")
	}

	if manifest.MaxSyncFailureRateBps > 0 {
		report.Checks = append(report.Checks, fmt.Sprintf("sync failure threshold configured:%d", manifest.MaxSyncFailureRateBps))
	}
	if manifest.MaxAPIErrorRateBps > 0 {
		report.Checks = append(report.Checks, fmt.Sprintf("api error threshold configured:%d", manifest.MaxAPIErrorRateBps))
	}
	if manifest.MaxDenialMismatchRateBps > 0 {
		report.Checks = append(report.Checks, fmt.Sprintf("denial mismatch rate threshold configured:%d bps", manifest.MaxDenialMismatchRateBps))
	}

	switch manifest.Stage {
	case drwaRolloutStageCanary:
		report.Ready = len(report.MissingHolders) == 0
	case drwaRolloutStageLimited, drwaRolloutStageProduction:
		if report.RequiresCanaryOnly {
			return nil, errDRWARolloutNotCanaryReady
		}
		report.Ready = len(report.MissingHolders) == 0
	}

	sort.Strings(report.Checks)
	sort.Strings(report.MissingHolders)
	sort.Strings(report.Warnings)

	return report, nil
}

func marshalDRWARolloutEvidence(report *drwaRolloutPreflightReport) ([]byte, error) {
	if report == nil {
		return nil, errDRWANilRolloutPreflightReport
	}

	return json.MarshalIndent(report, "", "  ")
}

func persistDRWARolloutEvidence(sink drwaRolloutEvidenceSink, tokenID string, payload []byte) error {
	if sink == nil {
		return errDRWANilRolloutEvidenceSink
	}

	return sink.PersistRolloutEvidence(tokenID, payload)
}

func buildDRWARolloutVerificationReport(manifest *drwaRolloutManifest, metrics *drwaRolloutObservedMetrics, thresholds ...drwaRolloutThresholdConfig) (*drwaRolloutVerificationReport, error) {
	if metrics == nil {
		return nil, errDRWANilRolloutMetrics
	}
	err := validateDRWARolloutManifest(manifest, thresholds...)
	if err != nil {
		return nil, err
	}

	report := &drwaRolloutVerificationReport{
		TokenID: manifest.TokenID,
		Stage:   manifest.Stage,
	}

	if metrics.SyncFailureRateBps <= manifest.MaxSyncFailureRateBps {
		report.PassedChecks = append(report.PassedChecks, "sync failure rate within threshold")
	} else {
		report.FailedChecks = append(report.FailedChecks, fmt.Sprintf("sync failure rate exceeded: observed=%d threshold=%d", metrics.SyncFailureRateBps, manifest.MaxSyncFailureRateBps))
	}

	if metrics.APIErrorRateBps <= manifest.MaxAPIErrorRateBps {
		report.PassedChecks = append(report.PassedChecks, "api error rate within threshold")
	} else {
		report.FailedChecks = append(report.FailedChecks, fmt.Sprintf("api error rate exceeded: observed=%d threshold=%d", metrics.APIErrorRateBps, manifest.MaxAPIErrorRateBps))
	}

	observedDenialMismatchRateBps := computeDRWADenialMismatchRateBps(metrics.DenialMismatchCount, metrics.DenialComparisonsTotal)
	if observedDenialMismatchRateBps <= manifest.MaxDenialMismatchRateBps {
		report.PassedChecks = append(report.PassedChecks, fmt.Sprintf("denial mismatch rate within threshold: observed=%d threshold=%d", observedDenialMismatchRateBps, manifest.MaxDenialMismatchRateBps))
	} else {
		report.FailedChecks = append(report.FailedChecks, fmt.Sprintf("denial mismatch rate exceeded: observed=%d threshold=%d", observedDenialMismatchRateBps, manifest.MaxDenialMismatchRateBps))
	}

	sort.Strings(report.PassedChecks)
	sort.Strings(report.FailedChecks)
	report.Accepted = len(report.FailedChecks) == 0
	if report.Accepted {
		recordDRWAMetric(drwaMetricRolloutVerificationPass)
	} else {
		recordDRWAMetric(drwaMetricRolloutVerificationReject)
	}

	return report, nil
}

func marshalDRWARolloutVerificationReport(report *drwaRolloutVerificationReport) ([]byte, error) {
	if report == nil {
		return nil, errDRWANilRolloutVerification
	}

	return json.MarshalIndent(report, "", "  ")
}

func persistDRWARolloutVerification(sink drwaRolloutVerificationSink, tokenID string, payload []byte) error {
	if sink == nil {
		return errDRWANilRolloutVerificationSink
	}

	return sink.PersistRolloutVerification(tokenID, payload)
}

// drwaRolloutStageOrdinal returns the monotonic order of a rollout stage.
// Used to enforce canary → limited → production progression.
func drwaRolloutStageOrdinal(stage string) (int, error) {
	switch stage {
	case drwaRolloutStageCanary:
		return 1, nil
	case drwaRolloutStageLimited:
		return 2, nil
	case drwaRolloutStageProduction:
		return 3, nil
	default:
		return 0, fmt.Errorf("%w: %s", errDRWAInvalidRolloutStage, stage)
	}
}

func validateDRWARolloutAdmission(
	manifest *drwaRolloutManifest,
	preflight *drwaRolloutPreflightReport,
	verification *drwaRolloutVerificationReport,
	lastCompletedStage string,
	thresholds ...drwaRolloutThresholdConfig,
) error {
	err := validateDRWARolloutManifest(manifest, thresholds...)
	if err != nil {
		return err
	}

	// Enforce monotonic stage progression.
	// If a stage has been completed, the next must be strictly higher.
	if lastCompletedStage != "" {
		lastOrd, lastErr := drwaRolloutStageOrdinal(lastCompletedStage)
		if lastErr != nil {
			return lastErr
		}
		nextOrd, nextErr := drwaRolloutStageOrdinal(manifest.Stage)
		if nextErr != nil {
			return nextErr
		}
		if nextOrd <= lastOrd {
			return errDRWARolloutStageNotMonotonic
		}
	}

	if preflight == nil {
		return errDRWANilRolloutPreflightReport
	}
	if preflight.TokenID != manifest.TokenID {
		return errDRWARolloutReportTokenMismatch
	}
	if preflight.Stage != manifest.Stage {
		return errDRWARolloutReportStageMismatch
	}
	if !preflight.Ready {
		return errDRWARolloutNotCanaryReady
	}

	switch manifest.Stage {
	case drwaRolloutStageCanary:
		return nil
	case drwaRolloutStageLimited, drwaRolloutStageProduction:
		if verification == nil {
			return errDRWARolloutVerificationRequired
		}
		if verification.TokenID != manifest.TokenID {
			return errDRWARolloutReportTokenMismatch
		}
		if verification.Stage != manifest.Stage {
			return errDRWARolloutReportStageMismatch
		}
		if !verification.Accepted {
			return errDRWARolloutVerificationRejected
		}
		return nil
	default:
		return errDRWAInvalidRolloutStage
	}
}

// loadRolloutThresholdConfig loads governance-configured threshold caps for a
// token. If the config reader is nil or returns nil config, the built-in
// defaults are used. This allows gradual rollout of governance configuration
// without breaking existing deployments.
//
// DESIGN NOTE: The fallback to defaults on error/nil is intentional — this is
// a non-critical read path. Governance thresholds are advisory caps, and the
// built-in defaults are conservative (100 bps failure/API error, 10 mismatch).
// Failing hard here would block all rollout operations when governance storage
// is temporarily unavailable, which is worse than applying conservative defaults.
// The metric below ensures operators can detect when the fallback is active.
func loadRolloutThresholdConfig(configReader drwaRolloutConfigReader, tokenID string) drwaRolloutThresholdConfig {
	if configReader == nil {
		return drwaRolloutDefaultThresholdConfig()
	}
	cfg, err := configReader.GetRolloutThresholdConfig(tokenID)
	if err != nil {
		recordDRWAMetric(drwaMetricRolloutThresholdConfigFallback)
		return drwaRolloutDefaultThresholdConfig()
	}
	if cfg == nil {
		recordDRWAMetric(drwaMetricRolloutThresholdConfigFallback)
		return drwaRolloutDefaultThresholdConfig()
	}
	return *cfg
}

// inspectDRWARolloutPreflightWithGovernance is the governance-aware entry point
// that loads per-token threshold configuration before running preflight.
func inspectDRWARolloutPreflightWithGovernance(
	reader drwaRolloutStateReader,
	configReader drwaRolloutConfigReader,
	manifest *drwaRolloutManifest,
	recoveryReport *drwaRecoveryReport,
) (*drwaRolloutPreflightReport, error) {
	if manifest == nil {
		return nil, errDRWANilRolloutManifest
	}
	cfg := loadRolloutThresholdConfig(configReader, manifest.TokenID)
	return inspectDRWARolloutPreflight(reader, manifest, recoveryReport, cfg)
}

// buildDRWARolloutVerificationReportWithGovernance is the governance-aware
// entry point for building verification reports with per-token thresholds.
func buildDRWARolloutVerificationReportWithGovernance(
	configReader drwaRolloutConfigReader,
	manifest *drwaRolloutManifest,
	metrics *drwaRolloutObservedMetrics,
) (*drwaRolloutVerificationReport, error) {
	if manifest == nil {
		return nil, errDRWANilRolloutManifest
	}
	cfg := loadRolloutThresholdConfig(configReader, manifest.TokenID)
	return buildDRWARolloutVerificationReport(manifest, metrics, cfg)
}

// SM-4: validateDRWARolloutAdmissionWithState is the state-aware entry point
// for rollout admission. It reads the last completed stage from on-chain state
// (via drwaRolloutStageStore) rather than trusting the caller-supplied parameter.
// After successful admission, it persists the new stage to state.
func validateDRWARolloutAdmissionWithState(
	stageStore drwaRolloutStageStore,
	manifest *drwaRolloutManifest,
	preflight *drwaRolloutPreflightReport,
	verification *drwaRolloutVerificationReport,
	thresholds ...drwaRolloutThresholdConfig,
) error {
	if stageStore == nil {
		return fmt.Errorf("nil DRWA rollout stage store")
	}
	if manifest == nil {
		return errDRWANilRolloutManifest
	}

	// Read last completed stage from on-chain state instead of trusting caller.
	lastCompletedStage, err := stageStore.GetLastCompletedRolloutStage(manifest.TokenID)
	if err != nil {
		return fmt.Errorf("reading last rollout stage: %w", err)
	}

	err = validateDRWARolloutAdmission(manifest, preflight, verification, lastCompletedStage, thresholds...)
	if err != nil {
		return err
	}

	// Persist the newly completed stage to on-chain state.
	return stageStore.PutLastCompletedRolloutStage(manifest.TokenID, manifest.Stage)
}
