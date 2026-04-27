package hooks

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmmock "github.com/multiversx/mx-chain-vm-common-go/mock"
)

func TestValidateDRWARolloutManifestRejectsInvalidStage(t *testing.T) {
	t.Parallel()

	err := validateDRWARolloutManifest(&drwaRolloutManifest{
		TokenID: "CARBON-1",
		Issuer:  "issuer-1",
		Stage:   "invalid",
	})
	if err == nil {
		t.Fatalf("expected invalid stage rejection")
	}
}

// Zero thresholds are valid (zero-tolerance policy).
// Verifies that zero thresholds pass validation.
func TestValidateDRWARolloutManifestAcceptsZeroThresholds(t *testing.T) {
	t.Parallel()

	err := validateDRWARolloutManifest(&drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		MaxSyncFailureRateBps:  0,
		MaxAPIErrorRateBps:     0,
		MaxDenialMismatchRateBps: 0,
	})
	if err != nil {
		t.Fatalf("zero thresholds should be valid (zero-tolerance), got %v", err)
	}
}

func TestValidateDRWARolloutManifestRejectsLegacyDenialMismatchCountField(t *testing.T) {
	t.Parallel()

	payload := []byte(`{
		"token_id":"CARBON-1",
		"issuer":"issuer-1",
		"stage":"canary",
		"max_denial_mismatch_count":1
	}`)

	var manifest drwaRolloutManifest
	err := json.Unmarshal(payload, &manifest)
	if err != errDRWALegacyDenialMismatchCountThreshold {
		t.Fatalf("expected legacy denial threshold rejection, got %v", err)
	}
}

func TestValidateDRWARolloutManifestRejectsThresholdsAboveUpperBounds(t *testing.T) {
	t.Parallel()

	err := validateDRWARolloutManifest(&drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		MaxSyncFailureRateBps:  drwaRolloutMaxFailureRateBpsUpperBound + 1,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	})
	if err != errDRWAInvalidRolloutThresholds {
		t.Fatalf("expected upper-bound rejection, got %v", err)
	}
}

func TestInspectDRWARolloutPreflightRequiresPolicy(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()
	_, err := inspectDRWARolloutPreflight(adapter, &drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		ExpectedPolicyVersion:  2,
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	}, nil)
	if err != errDRWARolloutPolicyMissing {
		t.Fatalf("expected policy missing, got %v", err)
	}
}

func TestInspectDRWARolloutPreflightFlagsMissingHolders(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["CARBON-1"] = 2
	adapter.tokenBodies["CARBON-1"] = []byte(`{"regulated":true}`)
	adapter.holderVersions["CARBON-1|erd1a"] = 1
	adapter.holderBodies["CARBON-1|erd1a"] = []byte(`{"kyc":"approved"}`)

	report, err := inspectDRWARolloutPreflight(adapter, &drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		ExpectedPolicyVersion:  2,
		RequiredHolders:        []string{"erd1a", "erd1b"},
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	}, nil)
	if err != nil {
		t.Fatalf("inspect rollout: %v", err)
	}
	if len(report.MissingHolders) != 1 || report.MissingHolders[0] != "erd1b" {
		t.Fatalf("unexpected missing holders: %+v", report.MissingHolders)
	}
	if report.Ready {
		t.Fatalf("expected rollout not ready with missing holders")
	}
}

func TestInspectDRWARolloutPreflightBlocksLimitedWhenCanaryRequired(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["CARBON-1"] = 1
	adapter.tokenBodies["CARBON-1"] = []byte(`{"regulated":true}`)

	_, err := inspectDRWARolloutPreflight(adapter, &drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageLimited,
		ExpectedPolicyVersion:  2,
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	}, nil)
	if err != errDRWARolloutNotCanaryReady {
		t.Fatalf("expected canary-ready rejection, got %v", err)
	}
}

func TestMarshalDRWARolloutEvidenceAndPersist(t *testing.T) {
	t.Parallel()

	report := &drwaRolloutPreflightReport{
		TokenID: "CARBON-1",
		Stage:   drwaRolloutStageCanary,
		Checks:  []string{"token policy present"},
		Ready:   true,
	}

	payload, err := marshalDRWARolloutEvidence(report)
	if err != nil {
		t.Fatalf("marshal rollout evidence: %v", err)
	}
	if len(payload) == 0 {
		t.Fatalf("expected rollout evidence payload")
	}

	adapter := newMockDRWASyncStateAdapter()
	err = persistDRWARolloutEvidence(adapter, "CARBON-1", payload)
	if err != nil {
		t.Fatalf("persist rollout evidence: %v", err)
	}
	if len(adapter.rolloutEvidence["CARBON-1"]) == 0 {
		t.Fatalf("expected persisted rollout evidence")
	}
}

func TestBuildDRWARolloutVerificationReportAcceptsHealthyMetrics(t *testing.T) {
	t.Parallel()

	report, err := buildDRWARolloutVerificationReport(&drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     20,
		MaxDenialMismatchRateBps: 100,
	}, &drwaRolloutObservedMetrics{
		SyncFailureRateBps:  5,
		APIErrorRateBps:     10,
		DenialMismatchCount: 0,
		DenialComparisonsTotal: 100,
	})
	if err != nil {
		t.Fatalf("build verification report: %v", err)
	}
	if !report.Accepted {
		t.Fatalf("expected verification acceptance, got %+v", report)
	}
}

func TestBuildDRWARolloutVerificationReportRejectsBadMetrics(t *testing.T) {
	t.Parallel()

	report, err := buildDRWARolloutVerificationReport(&drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageLimited,
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     20,
		MaxDenialMismatchRateBps: 100,
	}, &drwaRolloutObservedMetrics{
		SyncFailureRateBps:  50,
		APIErrorRateBps:     21,
		DenialMismatchCount: 2,
		DenialComparisonsTotal: 100,
	})
	if err != nil {
		t.Fatalf("build verification report: %v", err)
	}
	if report.Accepted {
		t.Fatalf("expected verification rejection, got %+v", report)
	}
	if len(report.FailedChecks) != 3 {
		t.Fatalf("expected 3 failed checks, got %+v", report.FailedChecks)
	}
}

func TestBuildDRWARolloutVerificationReportSupportsDenialMismatchRateThreshold(t *testing.T) {
	t.Parallel()

	payload := []byte(`{
		"token_id":"CARBON-1",
		"issuer":"issuer-1",
		"stage":"limited",
		"max_sync_failure_rate_bps":10,
		"max_api_error_rate_bps":20,
		"max_denial_mismatch_rate_bps":100
	}`)

	var manifest drwaRolloutManifest
	err := json.Unmarshal(payload, &manifest)
	if err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}

	report, err := buildDRWARolloutVerificationReport(&manifest, &drwaRolloutObservedMetrics{
		SyncFailureRateBps:    5,
		APIErrorRateBps:       10,
		DenialMismatchCount:   1,
		DenialComparisonsTotal: 100,
	})
	if err != nil {
		t.Fatalf("build verification report: %v", err)
	}
	if !report.Accepted {
		t.Fatalf("expected verification acceptance, got %+v", report)
	}
}

func TestBuildDRWARolloutVerificationReportRejectsWhenDenialMismatchRateExceedsThreshold(t *testing.T) {
	t.Parallel()

	payload := []byte(`{
		"token_id":"CARBON-1",
		"issuer":"issuer-1",
		"stage":"limited",
		"max_sync_failure_rate_bps":10,
		"max_api_error_rate_bps":20,
		"max_denial_mismatch_rate_bps":50
	}`)

	var manifest drwaRolloutManifest
	err := json.Unmarshal(payload, &manifest)
	if err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}

	report, err := buildDRWARolloutVerificationReport(&manifest, &drwaRolloutObservedMetrics{
		SyncFailureRateBps:    5,
		APIErrorRateBps:       10,
		DenialMismatchCount:   3,
		DenialComparisonsTotal: 100,
	})
	if err != nil {
		t.Fatalf("build verification report: %v", err)
	}
	if report.Accepted {
		t.Fatalf("expected verification rejection, got %+v", report)
	}
}

func TestMarshalDRWARolloutVerificationReport(t *testing.T) {
	t.Parallel()

	payload, err := marshalDRWARolloutVerificationReport(&drwaRolloutVerificationReport{
		TokenID:      "CARBON-1",
		Stage:        drwaRolloutStageProduction,
		PassedChecks: []string{"api error rate within threshold"},
		Accepted:     true,
	})
	if err != nil {
		t.Fatalf("marshal verification report: %v", err)
	}
	if len(payload) == 0 {
		t.Fatalf("expected verification payload")
	}
}

func TestPersistDRWARolloutVerification(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()
	payload, err := marshalDRWARolloutVerificationReport(&drwaRolloutVerificationReport{
		TokenID:      "CARBON-1",
		Stage:        drwaRolloutStageLimited,
		FailedChecks: []string{"sync failure rate exceeded: observed=50 threshold=10"},
		Accepted:     false,
	})
	if err != nil {
		t.Fatalf("marshal verification report: %v", err)
	}

	err = persistDRWARolloutVerification(adapter, "CARBON-1", payload)
	if err != nil {
		t.Fatalf("persist verification report: %v", err)
	}
	if len(adapter.rolloutVerification["CARBON-1"]) == 0 {
		t.Fatalf("expected persisted verification report")
	}
}

func TestValidateDRWARolloutAdmissionRequiresVerificationBeyondCanary(t *testing.T) {
	t.Parallel()

	err := validateDRWARolloutAdmission(&drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageLimited,
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	}, &drwaRolloutPreflightReport{
		TokenID: "CARBON-1",
		Stage:   drwaRolloutStageLimited,
		Ready:   true,
	}, nil, "")
	if err != errDRWARolloutVerificationRequired {
		t.Fatalf("expected verification-required error, got %v", err)
	}
}

func TestValidateDRWARolloutAdmissionRejectsFailedVerification(t *testing.T) {
	t.Parallel()

	err := validateDRWARolloutAdmission(&drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageProduction,
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	}, &drwaRolloutPreflightReport{
		TokenID: "CARBON-1",
		Stage:   drwaRolloutStageProduction,
		Ready:   true,
	}, &drwaRolloutVerificationReport{
		TokenID:  "CARBON-1",
		Stage:    drwaRolloutStageProduction,
		Accepted: false,
	}, "")
	if err != errDRWARolloutVerificationRejected {
		t.Fatalf("expected verification-rejected error, got %v", err)
	}
}

func TestValidateDRWARolloutAdmissionRejectsPreflightTokenMismatch(t *testing.T) {
	t.Parallel()

	err := validateDRWARolloutAdmission(&drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	}, &drwaRolloutPreflightReport{
		TokenID: "OTHER-1",
		Stage:   drwaRolloutStageCanary,
		Ready:   true,
	}, nil, "")
	if err != errDRWARolloutReportTokenMismatch {
		t.Fatalf("expected token-mismatch error, got %v", err)
	}
}

func TestValidateDRWARolloutAdmissionRejectsVerificationStageMismatch(t *testing.T) {
	t.Parallel()

	err := validateDRWARolloutAdmission(&drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageProduction,
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	}, &drwaRolloutPreflightReport{
		TokenID: "CARBON-1",
		Stage:   drwaRolloutStageProduction,
		Ready:   true,
	}, &drwaRolloutVerificationReport{
		TokenID:  "CARBON-1",
		Stage:    drwaRolloutStageLimited,
		Accepted: true,
	}, "")
	if err != errDRWARolloutReportStageMismatch {
		t.Fatalf("expected stage-mismatch error, got %v", err)
	}
}

func TestValidateDRWARolloutAdmissionAllowsCanaryWithoutVerification(t *testing.T) {
	t.Parallel()

	err := validateDRWARolloutAdmission(&drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	}, &drwaRolloutPreflightReport{
		TokenID: "CARBON-1",
		Stage:   drwaRolloutStageCanary,
		Ready:   true,
	}, nil, "")
	if err != nil {
		t.Fatalf("expected canary admission, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Governance-configurable threshold tests
// ---------------------------------------------------------------------------

func TestValidateDRWARolloutManifestUsesDefaultThresholdsWhenNoneProvided(t *testing.T) {
	t.Parallel()

	// Manifest within default bounds (100 bps failure, 100 bps API, 10 denial)
	err := validateDRWARolloutManifest(&drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		MaxSyncFailureRateBps:  100,
		MaxAPIErrorRateBps:     100,
		MaxDenialMismatchRateBps: 100,
	})
	if err != nil {
		t.Fatalf("expected valid with default thresholds, got %v", err)
	}
}

func TestValidateDRWARolloutManifestRespectsCustomGovernanceThresholds(t *testing.T) {
	t.Parallel()

	custom := drwaRolloutThresholdConfig{
		MaxFailureRateBpsUpperBound:  500,
		MaxAPIErrorRateBpsUpperBound: 300,
		MaxDenialMismatchRateBpsUpperBound: 500,
	}

	// Value within custom bounds but above defaults — should pass with custom config
	err := validateDRWARolloutManifest(&drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		MaxSyncFailureRateBps:  200,
		MaxAPIErrorRateBps:     250,
		MaxDenialMismatchRateBps: 40,
	}, custom)
	if err != nil {
		t.Fatalf("expected valid with custom thresholds, got %v", err)
	}
}

func TestValidateDRWARolloutManifestRejectsAboveCustomGovernanceThresholds(t *testing.T) {
	t.Parallel()

	custom := drwaRolloutThresholdConfig{
		MaxFailureRateBpsUpperBound:  500,
		MaxAPIErrorRateBpsUpperBound: 300,
		MaxDenialMismatchRateBpsUpperBound: 500,
	}

	err := validateDRWARolloutManifest(&drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		MaxSyncFailureRateBps:  501,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	}, custom)
	if err != errDRWAInvalidRolloutThresholds {
		t.Fatalf("expected threshold rejection, got %v", err)
	}
}

func TestLoadRolloutThresholdConfigFallsBackToDefaults(t *testing.T) {
	t.Parallel()

	// nil reader
	cfg := loadRolloutThresholdConfig(nil, "CARBON-1")
	defaults := drwaRolloutDefaultThresholdConfig()
	if cfg != defaults {
		t.Fatalf("expected default config from nil reader, got %+v", cfg)
	}
}

type mockRolloutConfigReader struct {
	configs map[string]*drwaRolloutThresholdConfig
}

func (m *mockRolloutConfigReader) GetRolloutThresholdConfig(tokenID string) (*drwaRolloutThresholdConfig, error) {
	cfg, ok := m.configs[tokenID]
	if !ok {
		return nil, nil
	}
	return cfg, nil
}

func TestLoadRolloutThresholdConfigLoadsFromGovernance(t *testing.T) {
	t.Parallel()

	reader := &mockRolloutConfigReader{
		configs: map[string]*drwaRolloutThresholdConfig{
			"CARBON-1": {
				MaxFailureRateBpsUpperBound:  500,
				MaxAPIErrorRateBpsUpperBound: 400,
				MaxDenialMismatchRateBpsUpperBound: 250,
			},
		},
	}

	cfg := loadRolloutThresholdConfig(reader, "CARBON-1")
	if cfg.MaxFailureRateBpsUpperBound != 500 {
		t.Fatalf("expected 500, got %d", cfg.MaxFailureRateBpsUpperBound)
	}
	if cfg.MaxAPIErrorRateBpsUpperBound != 400 {
		t.Fatalf("expected 400, got %d", cfg.MaxAPIErrorRateBpsUpperBound)
	}
	if cfg.MaxDenialMismatchRateBpsUpperBound != 250 {
		t.Fatalf("expected 250, got %d", cfg.MaxDenialMismatchRateBpsUpperBound)
	}
}

func TestLoadRolloutThresholdConfigFallsBackForUnknownToken(t *testing.T) {
	t.Parallel()

	reader := &mockRolloutConfigReader{
		configs: map[string]*drwaRolloutThresholdConfig{},
	}

	cfg := loadRolloutThresholdConfig(reader, "UNKNOWN-1")
	defaults := drwaRolloutDefaultThresholdConfig()
	if cfg != defaults {
		t.Fatalf("expected default config for unknown token, got %+v", cfg)
	}
}

func TestLoadRolloutThresholdConfigLoadsFromGovernanceTrieStore(t *testing.T) {
	t.Parallel()

	systemAccount := vmmock.NewAccountWrapMock(core.SystemAccountAddress)
	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			if string(address) == string(core.SystemAccountAddress) {
				return systemAccount, nil
			}
			return vmmock.NewAccountWrapMock(address), nil
		},
		SaveAccountCalled:      func(account vmcommon.AccountHandler) error { return nil },
		JournalLenCalled:       func() int { return 1 },
		RevertToSnapshotCalled: func(snapshot int) error { return nil },
	}

	store, err := newDRWAGovernanceTrieStore(accountsStub)
	if err != nil {
		t.Fatalf("newDRWAGovernanceTrieStore: %v", err)
	}

	cfg := &DRWAGovernanceConfig{
		Threshold:   2,
		Signers:     [][]byte{[]byte("signer-1"), []byte("signer-2")},
		ProposalTTL: 2400,
		MaxSigners:  10,
		RolloutThresholds: &drwaRolloutThresholdConfig{
			MaxFailureRateBpsUpperBound:        400,
			MaxAPIErrorRateBpsUpperBound:       300,
			MaxDenialMismatchRateBpsUpperBound: 250,
		},
	}
	if err = store.SaveGovernanceConfig("CARBON-1", cfg); err != nil {
		t.Fatalf("SaveGovernanceConfig: %v", err)
	}

	loaded := loadRolloutThresholdConfig(store, "CARBON-1")
	if loaded.MaxFailureRateBpsUpperBound != 400 {
		t.Fatalf("expected 400, got %d", loaded.MaxFailureRateBpsUpperBound)
	}
	if loaded.MaxAPIErrorRateBpsUpperBound != 300 {
		t.Fatalf("expected 300, got %d", loaded.MaxAPIErrorRateBpsUpperBound)
	}
	if loaded.MaxDenialMismatchRateBpsUpperBound != 250 {
		t.Fatalf("expected 250, got %d", loaded.MaxDenialMismatchRateBpsUpperBound)
	}
}

func TestInspectDRWARolloutPreflightWithGovernanceUsesCustomConfig(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["CARBON-1"] = 1
	adapter.tokenBodies["CARBON-1"] = []byte(`{"regulated":true}`)

	configReader := &mockRolloutConfigReader{
		configs: map[string]*drwaRolloutThresholdConfig{
			"CARBON-1": {
				MaxFailureRateBpsUpperBound:  500,
				MaxAPIErrorRateBpsUpperBound: 500,
				MaxDenialMismatchRateBpsUpperBound: 500,
			},
		},
	}

	// 200 bps would fail default (100) but passes custom (500)
	report, err := inspectDRWARolloutPreflightWithGovernance(adapter, configReader, &drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		ExpectedPolicyVersion:  1,
		MaxSyncFailureRateBps:  200,
		MaxAPIErrorRateBps:     200,
		MaxDenialMismatchRateBps: 50,
	}, nil)
	if err != nil {
		t.Fatalf("expected success with governance config, got %v", err)
	}
	if !report.Ready {
		t.Fatalf("expected rollout ready")
	}
}

func TestBuildDRWARolloutVerificationReportWithGovernanceUsesCustomConfig(t *testing.T) {
	t.Parallel()

	configReader := &mockRolloutConfigReader{
		configs: map[string]*drwaRolloutThresholdConfig{
			"CARBON-1": {
				MaxFailureRateBpsUpperBound:  500,
				MaxAPIErrorRateBpsUpperBound: 500,
				MaxDenialMismatchRateBpsUpperBound: 500,
			},
		},
	}

	report, err := buildDRWARolloutVerificationReportWithGovernance(configReader, &drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		MaxSyncFailureRateBps:  200,
		MaxAPIErrorRateBps:     200,
		MaxDenialMismatchRateBps: 500,
	}, &drwaRolloutObservedMetrics{
		SyncFailureRateBps:  150,
		APIErrorRateBps:     100,
		DenialMismatchCount: 30,
		DenialComparisonsTotal: 1000,
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if !report.Accepted {
		t.Fatalf("expected verification acceptance with governance config")
	}
}

// ---------------------------------------------------------------------------
// mockDRWARolloutStageStore for validateDRWARolloutAdmissionWithState tests
// ---------------------------------------------------------------------------

type mockDRWARolloutStageStore struct {
	stages  map[string]string
	failGet bool
	failPut bool
}

func newMockDRWARolloutStageStore() *mockDRWARolloutStageStore {
	return &mockDRWARolloutStageStore{stages: make(map[string]string)}
}

func (m *mockDRWARolloutStageStore) GetLastCompletedRolloutStage(tokenID string) (string, error) {
	if m.failGet {
		return "", errors.New("stage store read failed")
	}
	return m.stages[tokenID], nil
}

func (m *mockDRWARolloutStageStore) PutLastCompletedRolloutStage(tokenID string, stage string) error {
	if m.failPut {
		return errors.New("stage store write failed")
	}
	m.stages[tokenID] = stage
	return nil
}

// ---------------------------------------------------------------------------
// validateDRWARolloutAdmissionWithState tests (0% → covered)
// ---------------------------------------------------------------------------

func TestValidateDRWARolloutAdmissionWithState_ValidCanaryAdmission(t *testing.T) {
	t.Parallel()

	store := newMockDRWARolloutStageStore()
	err := validateDRWARolloutAdmissionWithState(store, &drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	}, &drwaRolloutPreflightReport{
		TokenID: "CARBON-1",
		Stage:   drwaRolloutStageCanary,
		Ready:   true,
	}, nil)
	if err != nil {
		t.Fatalf("expected canary admission, got %v", err)
	}
	if store.stages["CARBON-1"] != drwaRolloutStageCanary {
		t.Fatalf("expected canary stage persisted, got %s", store.stages["CARBON-1"])
	}
}

func TestValidateDRWARolloutAdmissionWithState_RejectsNilStageStore(t *testing.T) {
	t.Parallel()

	err := validateDRWARolloutAdmissionWithState(nil, &drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	}, &drwaRolloutPreflightReport{
		TokenID: "CARBON-1",
		Stage:   drwaRolloutStageCanary,
		Ready:   true,
	}, nil)
	if err == nil {
		t.Fatal("expected nil stage store rejection")
	}
}

func TestValidateDRWARolloutAdmissionWithState_RejectsNonMonotonic(t *testing.T) {
	t.Parallel()

	store := newMockDRWARolloutStageStore()
	store.stages["CARBON-1"] = drwaRolloutStageCanary

	err := validateDRWARolloutAdmissionWithState(store, &drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	}, &drwaRolloutPreflightReport{
		TokenID: "CARBON-1",
		Stage:   drwaRolloutStageCanary,
		Ready:   true,
	}, nil)
	if err != errDRWARolloutStageNotMonotonic {
		t.Fatalf("expected stage-not-monotonic error, got %v", err)
	}
}

func TestValidateDRWARolloutAdmissionWithState_RejectsStageStoreReadError(t *testing.T) {
	t.Parallel()

	store := newMockDRWARolloutStageStore()
	store.failGet = true

	err := validateDRWARolloutAdmissionWithState(store, &drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	}, &drwaRolloutPreflightReport{
		TokenID: "CARBON-1",
		Stage:   drwaRolloutStageCanary,
		Ready:   true,
	}, nil)
	if err == nil {
		t.Fatal("expected stage store read error")
	}
}

func TestValidateDRWARolloutAdmissionWithState_MonotonicProgression(t *testing.T) {
	t.Parallel()

	store := newMockDRWARolloutStageStore()
	store.stages["CARBON-1"] = drwaRolloutStageCanary

	err := validateDRWARolloutAdmissionWithState(store, &drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageLimited,
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	}, &drwaRolloutPreflightReport{
		TokenID: "CARBON-1",
		Stage:   drwaRolloutStageLimited,
		Ready:   true,
	}, &drwaRolloutVerificationReport{
		TokenID:  "CARBON-1",
		Stage:    drwaRolloutStageLimited,
		Accepted: true,
	})
	if err != nil {
		t.Fatalf("expected limited admission after canary, got %v", err)
	}
	if store.stages["CARBON-1"] != drwaRolloutStageLimited {
		t.Fatalf("expected limited stage persisted, got %s", store.stages["CARBON-1"])
	}
}

func TestValidateDRWARolloutAdmissionRejectsNonMonotonicStage(t *testing.T) {
	t.Parallel()

	// Attempting canary again after canary already completed
	err := validateDRWARolloutAdmission(&drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	}, &drwaRolloutPreflightReport{
		TokenID: "CARBON-1",
		Stage:   drwaRolloutStageCanary,
		Ready:   true,
	}, nil, drwaRolloutStageCanary)
	if err != errDRWARolloutStageNotMonotonic {
		t.Fatalf("expected stage-not-monotonic error, got %v", err)
	}

	// Limited after production should fail
	err = validateDRWARolloutAdmission(&drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageLimited,
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	}, &drwaRolloutPreflightReport{
		TokenID: "CARBON-1",
		Stage:   drwaRolloutStageLimited,
		Ready:   true,
	}, nil, drwaRolloutStageProduction)
	if err != errDRWARolloutStageNotMonotonic {
		t.Fatalf("expected stage-not-monotonic error for limited after production, got %v", err)
	}
}
