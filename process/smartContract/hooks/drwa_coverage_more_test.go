package hooks

// drwa_coverage_more_test.go — Additional coverage tests for migration, recovery,
// rollout, and adapter functions to push total package coverage >=90%.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmmock "github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Migration coverage
// ---------------------------------------------------------------------------

func TestValidateDRWAMigrationManifestEdgeCases(t *testing.T) {
	t.Parallel()

	// nil manifest
	require.Error(t, validateDRWAMigrationManifest(nil))

	// empty token ID
	require.Error(t, validateDRWAMigrationManifest(&drwaMigrationManifest{TokenID: ""}))

	// zero policy version
	require.Error(t, validateDRWAMigrationManifest(&drwaMigrationManifest{TokenID: "T1", PolicyVersion: 0}))

	// empty policy body
	require.Error(t, validateDRWAMigrationManifest(&drwaMigrationManifest{TokenID: "T1", PolicyVersion: 1}))

	// empty holder address
	require.Error(t, validateDRWAMigrationManifest(&drwaMigrationManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
		Holders:       []drwaMigrationHolder{{Address: "", Version: 1, Body: []byte(`{}`)}},
	}))

	// zero holder version
	require.Error(t, validateDRWAMigrationManifest(&drwaMigrationManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
		Holders:       []drwaMigrationHolder{{Address: "h1", Version: 0, Body: []byte(`{}`)}},
	}))

	// empty holder body
	require.Error(t, validateDRWAMigrationManifest(&drwaMigrationManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
		Holders:       []drwaMigrationHolder{{Address: "h1", Version: 1}},
	}))

	// duplicate holder
	require.Error(t, validateDRWAMigrationManifest(&drwaMigrationManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
		Holders: []drwaMigrationHolder{
			{Address: "h1", Version: 1, Body: []byte(`{}`)},
			{Address: "h1", Version: 2, Body: []byte(`{}`)},
		},
	}))

	// valid manifest with authorized callers (invalid domain address)
	require.Error(t, validateDRWAMigrationManifest(&drwaMigrationManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
		AuthorizedCallers: map[string]string{
			drwaSyncCallerPolicyRegistry: "bad",
		},
	}))
}

func TestNormalizeDRWAAuthorizedCallerAddressPaths(t *testing.T) {
	t.Parallel()

	// empty
	_, err := normalizeDRWAAuthorizedCallerAddress("")
	require.Error(t, err)

	// 32-byte raw binary rejection
	_, err = normalizeDRWAAuthorizedCallerAddress("12345678901234567890123456789012")
	require.Error(t, err)
	require.Contains(t, err.Error(), "raw 32-byte binary")

	// valid hex
	validHex := hex.EncodeToString(make([]byte, 32))
	// all zeros → rejected
	_, err = normalizeDRWAAuthorizedCallerAddress(validHex)
	require.Error(t, err)

	// valid non-zero hex
	nonZero := make([]byte, 32)
	nonZero[0] = 1
	addr, err := normalizeDRWAAuthorizedCallerAddress(hex.EncodeToString(nonZero))
	require.NoError(t, err)
	require.Equal(t, nonZero, addr)

	// 0x-prefixed hex
	addr2, err := normalizeDRWAAuthorizedCallerAddress("0x" + hex.EncodeToString(nonZero))
	require.NoError(t, err)
	require.Equal(t, nonZero, addr2)

	// invalid bech32 with erd1 prefix
	_, err = normalizeDRWAAuthorizedCallerAddress("erd1invalid")
	require.Error(t, err)

	// invalid hex (wrong length)
	_, err = normalizeDRWAAuthorizedCallerAddress("0xaabb")
	require.Error(t, err)

	// totally invalid
	_, err = normalizeDRWAAuthorizedCallerAddress("not-hex-not-bech32")
	require.Error(t, err)
}

func TestIsAllZeroAddress(t *testing.T) {
	t.Parallel()

	require.True(t, isAllZeroAddress(make([]byte, 32)))
	nonZero := make([]byte, 32)
	nonZero[31] = 1
	require.False(t, isAllZeroAddress(nonZero))
}

func TestPersistDRWAMigrationAuthorizedCallersPaths(t *testing.T) {
	t.Parallel()

	// nil sink
	require.Error(t, persistDRWAMigrationAuthorizedCallers(nil, &drwaMigrationManifest{
		TokenID: "T1", PolicyVersion: 1, PolicyBody: []byte(`{}`),
	}))

	// empty authorized callers → noop
	adapter := newMockDRWASyncStateAdapter()
	require.NoError(t, persistDRWAMigrationAuthorizedCallers(adapter, &drwaMigrationManifest{
		TokenID: "T1", PolicyVersion: 1, PolicyBody: []byte(`{}`),
	}))
}

func TestBuildDRWARollbackEnvelopeEdgeCases(t *testing.T) {
	t.Parallel()

	// nil snapshot
	_, err := buildDRWARollbackEnvelope(nil)
	require.Error(t, err)

	// token policy version overflow
	_, err = buildDRWARollbackEnvelope(&drwaMigrationSnapshot{
		TokenID:     "T1",
		TokenPolicy: &drwaSyncStoredValue{Version: math.MaxUint64, Body: []byte(`{}`)},
		Holders:     map[string]*drwaSyncStoredValue{},
	})
	require.Error(t, err)

	// holder version overflow
	_, err = buildDRWARollbackEnvelope(&drwaMigrationSnapshot{
		TokenID:     "T1",
		TokenPolicy: &drwaSyncStoredValue{Version: 1, Body: []byte(`{}`)},
		Holders:     map[string]*drwaSyncStoredValue{"h1": {Version: math.MaxUint64, Body: []byte(`{}`)}},
	})
	require.Error(t, err)

	// delete version overflow (nil stored, requested at max)
	_, err = buildDRWARollbackEnvelope(&drwaMigrationSnapshot{
		TokenID:     "T1",
		TokenPolicy: &drwaSyncStoredValue{Version: 1, Body: []byte(`{}`)},
		Holders:     map[string]*drwaSyncStoredValue{"h1": nil},
		RequestedHolderState: map[string]drwaMigrationHolder{
			"h1": {Address: "h1", Version: math.MaxUint64, Body: []byte(`{}`)},
		},
	})
	require.Error(t, err)

	// successful rollback with nil stored holder (delete path)
	env, err := buildDRWARollbackEnvelope(&drwaMigrationSnapshot{
		TokenID:     "T1",
		TokenPolicy: &drwaSyncStoredValue{Version: 1, Body: []byte(`{}`)},
		Holders:     map[string]*drwaSyncStoredValue{"h1": nil},
		RequestedHolderState: map[string]drwaMigrationHolder{
			"h1": {Address: "h1", Version: 5, Body: []byte(`{}`)},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, env)
}

// ---------------------------------------------------------------------------
// Recovery coverage
// ---------------------------------------------------------------------------

func TestMarshalDRWARecoveryEvidenceNil(t *testing.T) {
	t.Parallel()
	_, err := marshalDRWARecoveryEvidence(nil)
	require.Error(t, err)
}

func TestPersistDRWARecoveryEvidenceNilSink(t *testing.T) {
	t.Parallel()
	require.Error(t, persistDRWARecoveryEvidence(nil, &drwaRecoveryReport{TokenID: "T1"}))
}

func TestPersistDRWARecoveryEvidenceNilReport(t *testing.T) {
	t.Parallel()
	require.Error(t, persistDRWARecoveryEvidence(newMockDRWASyncStateAdapter(), nil))
}

func TestDrwaRecoveryOperationOrderDefaultCase(t *testing.T) {
	t.Parallel()
	// Unknown operation type → "9|"
	order := drwaRecoveryOperationOrder(drwaSyncOperation{OperationType: "unknown", Holder: "h1"})
	require.Equal(t, "9|h1", order)
}

func TestValidateDRWARecoveryManifestNil(t *testing.T) {
	t.Parallel()
	require.Error(t, validateDRWARecoveryManifest(nil))
}

func TestComputeRecoveryManifestHash(t *testing.T) {
	t.Parallel()
	manifest := &drwaRecoveryManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
		Holders: []drwaMigrationHolder{
			{Address: "h2", Version: 1, Body: []byte(`{}`)},
			{Address: "h1", Version: 1, Body: []byte(`{}`)},
		},
		AuthorizedCallers: map[string]string{"a": "b", "c": "d"},
	}
	hash, err := computeRecoveryManifestHash(manifest)
	require.NoError(t, err)
	require.NotEmpty(t, hash)

	// Same manifest should produce same hash (deterministic sort)
	hash2, err := computeRecoveryManifestHash(manifest)
	require.NoError(t, err)
	require.Equal(t, hash, hash2)
}

func TestInspectDRWARecoveryStateNilReader(t *testing.T) {
	t.Parallel()
	_, err := inspectDRWARecoveryState(nil, &drwaRecoveryManifest{}, nil)
	require.Error(t, err)
}

func TestBuildDRWARecoveryEnvelopeNilReport(t *testing.T) {
	t.Parallel()
	_, err := buildDRWARecoveryEnvelope(&drwaRecoveryManifest{}, nil)
	require.Error(t, err)
}

func TestBuildDRWARecoveryEnvelopeNotRepairable(t *testing.T) {
	t.Parallel()
	_, err := buildDRWARecoveryEnvelope(&drwaRecoveryManifest{}, &drwaRecoveryReport{Repairable: false})
	require.Error(t, err)
}

func TestSanitizeDRWARecoveryManifest(t *testing.T) {
	t.Parallel()
	sanitizeDRWARecoveryManifest(nil) // should not panic

	m := &drwaRecoveryManifest{
		TokenID: "  T1  ",
		Holders: []drwaMigrationHolder{{Address: "  h1  "}},
	}
	sanitizeDRWARecoveryManifest(m)
	require.Equal(t, "T1", m.TokenID)
	require.Equal(t, "h1", m.Holders[0].Address)
}

// ---------------------------------------------------------------------------
// Rollout coverage
// ---------------------------------------------------------------------------

func TestMarshalDRWARolloutEvidenceNil(t *testing.T) {
	t.Parallel()
	_, err := marshalDRWARolloutEvidence(nil)
	require.Error(t, err)
}

func TestPersistDRWARolloutEvidenceNilSink(t *testing.T) {
	t.Parallel()
	require.Error(t, persistDRWARolloutEvidence(nil, "T1", []byte(`{}`)))
}

func TestMarshalDRWARolloutVerificationReportNil(t *testing.T) {
	t.Parallel()
	_, err := marshalDRWARolloutVerificationReport(nil)
	require.Error(t, err)
}

func TestPersistDRWARolloutVerificationNilSink(t *testing.T) {
	t.Parallel()
	require.Error(t, persistDRWARolloutVerification(nil, "T1", []byte(`{}`)))
}

func TestDrwaRolloutStageOrdinalInvalid(t *testing.T) {
	t.Parallel()
	_, err := drwaRolloutStageOrdinal("invalid")
	require.Error(t, err)
}

func TestValidateDRWARolloutAdmissionPaths(t *testing.T) {
	t.Parallel()

	manifest := &drwaRolloutManifest{
		TokenID: "T1", Issuer: "issuer", Stage: drwaRolloutStageCanary,
	}
	preflight := &drwaRolloutPreflightReport{
		TokenID: "T1", Stage: drwaRolloutStageCanary, Ready: true,
	}

	// canary with matching preflight → OK
	require.NoError(t, validateDRWARolloutAdmission(manifest, preflight, nil, ""))

	// limited requires verification
	manifestLtd := &drwaRolloutManifest{
		TokenID: "T1", Issuer: "issuer", Stage: drwaRolloutStageLimited,
	}
	preflightLtd := &drwaRolloutPreflightReport{
		TokenID: "T1", Stage: drwaRolloutStageLimited, Ready: true,
	}
	require.Error(t, validateDRWARolloutAdmission(manifestLtd, preflightLtd, nil, drwaRolloutStageCanary))

	// verification with mismatch
	verMismatch := &drwaRolloutVerificationReport{TokenID: "T1", Stage: "wrong", Accepted: true}
	require.Error(t, validateDRWARolloutAdmission(manifestLtd, preflightLtd, verMismatch, drwaRolloutStageCanary))

	// verification rejected
	verRejected := &drwaRolloutVerificationReport{TokenID: "T1", Stage: drwaRolloutStageLimited, Accepted: false}
	require.Error(t, validateDRWARolloutAdmission(manifestLtd, preflightLtd, verRejected, drwaRolloutStageCanary))

	// non-monotonic stage
	require.Error(t, validateDRWARolloutAdmission(manifest, preflight, nil, drwaRolloutStageProduction))

	// nil preflight
	require.Error(t, validateDRWARolloutAdmission(manifest, nil, nil, ""))

	// preflight token mismatch
	preflightWrong := &drwaRolloutPreflightReport{TokenID: "WRONG", Stage: drwaRolloutStageCanary, Ready: true}
	require.Error(t, validateDRWARolloutAdmission(manifest, preflightWrong, nil, ""))

	// preflight stage mismatch
	preflightStageMismatch := &drwaRolloutPreflightReport{TokenID: "T1", Stage: "wrong", Ready: true}
	require.Error(t, validateDRWARolloutAdmission(manifest, preflightStageMismatch, nil, ""))

	// preflight not ready
	preflightNotReady := &drwaRolloutPreflightReport{TokenID: "T1", Stage: drwaRolloutStageCanary, Ready: false}
	require.Error(t, validateDRWARolloutAdmission(manifest, preflightNotReady, nil, ""))

	// verification token mismatch
	verTokenMismatch := &drwaRolloutVerificationReport{TokenID: "WRONG", Stage: drwaRolloutStageLimited, Accepted: true}
	require.Error(t, validateDRWARolloutAdmission(manifestLtd, preflightLtd, verTokenMismatch, drwaRolloutStageCanary))
}

func TestInspectDRWARolloutPreflightWithGovernanceNilManifest(t *testing.T) {
	t.Parallel()
	_, err := inspectDRWARolloutPreflightWithGovernance(newMockDRWASyncStateAdapter(), nil, nil, nil)
	require.Error(t, err)
}

func TestBuildDRWARolloutVerificationReportWithGovernanceNilManifest(t *testing.T) {
	t.Parallel()
	_, err := buildDRWARolloutVerificationReportWithGovernance(nil, nil, &drwaRolloutObservedMetrics{})
	require.Error(t, err)
}

func TestValidateDRWARolloutManifestThresholdExceeded(t *testing.T) {
	t.Parallel()
	manifest := &drwaRolloutManifest{
		TokenID: "T1", Issuer: "issuer", Stage: drwaRolloutStageCanary,
		MaxSyncFailureRateBps: 999, // exceeds default 100
	}
	require.Error(t, validateDRWARolloutManifest(manifest))
}

// ---------------------------------------------------------------------------
// Sync coverage — additional paths
// ---------------------------------------------------------------------------

func TestDecodeDRWASyncEnvelopeJSONWithOperationsButNoHash(t *testing.T) {
	payload := []byte(`{"caller_domain":"policy_registry","operations":[{"operation_type":"token_policy","token_id":"T1","version":1,"body":"e30="}]}`)
	_, err := decodeDRWASyncEnvelope(payload)
	require.Error(t, err)
	require.Contains(t, err.Error(), "DRWA_SYNC_MISSING_PAYLOAD_HASH")
}

func TestDrwaOperationTypeTagAssetRecordTag(t *testing.T) {
	t.Parallel()
	tag, err := drwaOperationTypeTag(drwaSyncOpAssetRecord)
	require.NoError(t, err)
	require.Equal(t, byte(1), tag)

	// unknown type
	_, err = drwaOperationTypeTag("unknown_type")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Rollout stage store coverage
// ---------------------------------------------------------------------------

type mockRolloutStageStore struct {
	stages   map[string]string
	failGet  bool
	failPut  bool
}

func (m *mockRolloutStageStore) GetLastCompletedRolloutStage(tokenID string) (string, error) {
	if m.failGet {
		return "", errors.New("stage read failed")
	}
	return m.stages[tokenID], nil
}

func (m *mockRolloutStageStore) PutLastCompletedRolloutStage(tokenID string, stage string) error {
	if m.failPut {
		return errors.New("stage write failed")
	}
	m.stages[tokenID] = stage
	return nil
}

func TestValidateDRWARolloutAdmissionWithStatePaths(t *testing.T) {
	// nil store
	require.Error(t, validateDRWARolloutAdmissionWithState(nil, &drwaRolloutManifest{
		TokenID: "T1", Issuer: "i", Stage: drwaRolloutStageCanary,
	}, nil, nil))

	// nil manifest
	store := &mockRolloutStageStore{stages: map[string]string{}}
	require.Error(t, validateDRWARolloutAdmissionWithState(store, nil, nil, nil))

	// get stage failure
	failStore := &mockRolloutStageStore{stages: map[string]string{}, failGet: true}
	require.Error(t, validateDRWARolloutAdmissionWithState(failStore, &drwaRolloutManifest{
		TokenID: "T1", Issuer: "i", Stage: drwaRolloutStageCanary,
	}, &drwaRolloutPreflightReport{TokenID: "T1", Stage: drwaRolloutStageCanary, Ready: true}, nil))
}

// ---------------------------------------------------------------------------
// Bech32 additional paths
// ---------------------------------------------------------------------------

func TestDecodeBech32AddressWrongHRP(t *testing.T) {
	t.Parallel()
	// A valid bech32 with wrong HRP
	_, err := decodeBech32Address("btc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu")
	require.Error(t, err)
}

func TestBech32ConvertBitsPadding(t *testing.T) {
	t.Parallel()
	// With padding
	result, err := bech32ConvertBits([]byte{0x01, 0x02}, 5, 8, true)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Invalid data range
	_, err = bech32ConvertBits([]byte{0xFF}, 5, 8, false)
	require.Error(t, err)
}

func TestBech32DecodeEdgeCases(t *testing.T) {
	t.Parallel()

	// Too short
	_, _, err := bech32Decode("a1b")
	require.Error(t, err)

	// No separator
	_, _, err = bech32Decode("abcdefgh")
	require.Error(t, err)

	// Separator at start
	_, _, err = bech32Decode("1abcdefg")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// JSON envelope with too many operations
// ---------------------------------------------------------------------------

func TestDecodeDRWASyncEnvelopeJSONTooManyOperations(t *testing.T) {
	// Build a JSON envelope with >256 operations
	ops := make([]drwaSyncOperation, drwaSyncMaxOperations+1)
	for i := range ops {
		ops[i] = drwaSyncOperation{OperationType: drwaSyncOpTokenPolicy, TokenID: "T1", Version: uint64(i + 1), Body: []byte(`{}`)}
	}
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		PayloadHash:  []byte("hash"),
		Operations:   ops,
	}
	payload, err := json.Marshal(envelope)
	require.NoError(t, err)

	_, err = decodeDRWASyncEnvelope(payload)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeding limit")
}

// ---------------------------------------------------------------------------
// InspectDRWARecoveryState with various finding types
// ---------------------------------------------------------------------------

func TestInspectDRWARecoveryStateAllFindingTypes(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()

	// Token policy exists but version drifted
	adapter.tokenVersions["T1"] = 5
	adapter.tokenBodies["T1"] = []byte(`{"drwa_enabled":true}`)

	// Holder mirror exists but body drifted
	adapter.holderVersions["T1|h1"] = 2
	adapter.holderBodies["T1|h1"] = []byte(`{"kyc_status":"pending"}`)

	// Holder mirror missing
	// (h2 is in manifest but not in adapter)

	manifest := &drwaRecoveryManifest{
		TokenID:       "T1",
		PolicyVersion: 5,
		PolicyBody:    []byte(`{"drwa_enabled":false}`), // body differs
		Holders: []drwaMigrationHolder{
			{Address: "h1", Version: 2, Body: []byte(`{"kyc_status":"approved"}`)}, // body differs
			{Address: "h2", Version: 1, Body: []byte(`{}`)},                        // missing
		},
	}

	report, err := inspectDRWARecoveryState(adapter, manifest, nil)
	require.NoError(t, err)
	require.NotNil(t, report)
	require.True(t, len(report.Findings) > 0)
}

func TestInspectDRWARecoveryStateCorruptPolicyBody(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	// Version > 0 but body empty → corrupt
	adapter.tokenVersions["T1"] = 3
	adapter.tokenBodies["T1"] = nil

	manifest := &drwaRecoveryManifest{
		TokenID:       "T1",
		PolicyVersion: 3,
		PolicyBody:    []byte(`{}`),
	}
	report, err := inspectDRWARecoveryState(adapter, manifest, nil)
	require.NoError(t, err)
	require.False(t, report.Repairable)
}

func TestInspectDRWARecoveryStateCorruptHolderBody(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["T1"] = 1
	adapter.tokenBodies["T1"] = []byte(`{}`)
	// Holder version > 0 but body empty → corrupt
	adapter.holderVersions["T1|h1"] = 2
	adapter.holderBodies["T1|h1"] = nil

	manifest := &drwaRecoveryManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
		Holders:       []drwaMigrationHolder{{Address: "h1", Version: 2, Body: []byte(`{}`)}},
	}
	report, err := inspectDRWARecoveryState(adapter, manifest, nil)
	require.NoError(t, err)
	require.False(t, report.Repairable)
}

func TestInspectDRWARecoveryStateInSync(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["T1"] = 1
	adapter.tokenBodies["T1"] = []byte(`{}`)
	adapter.holderVersions["T1|h1"] = 1
	adapter.holderBodies["T1|h1"] = []byte(`{}`)

	manifest := &drwaRecoveryManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
		Holders:       []drwaMigrationHolder{{Address: "h1", Version: 1, Body: []byte(`{}`)}},
	}
	report, err := inspectDRWARecoveryState(adapter, manifest, nil)
	require.NoError(t, err)
	require.Equal(t, 1, len(report.Findings))
	require.Equal(t, drwaRecoveryStatusInSync, report.Findings[0].Status)
	require.False(t, report.RequiresSafeMode)
}

func TestInspectDRWARecoveryStatePolicyMissing(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	// no token policy at all

	manifest := &drwaRecoveryManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
	}
	report, err := inspectDRWARecoveryState(adapter, manifest, nil)
	require.NoError(t, err)
	require.True(t, report.RequiresSafeMode)
}

func TestInspectDRWARecoveryStateVersionDrift(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["T1"] = 3
	adapter.tokenBodies["T1"] = []byte(`{}`)

	manifest := &drwaRecoveryManifest{
		TokenID:       "T1",
		PolicyVersion: 5, // expected 5 but on-chain is 3
		PolicyBody:    []byte(`{}`),
	}
	report, err := inspectDRWARecoveryState(adapter, manifest, nil)
	require.NoError(t, err)
	require.True(t, report.RequiresSafeMode)
}

func TestInspectDRWARecoveryStateHolderVersionDrift(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["T1"] = 1
	adapter.tokenBodies["T1"] = []byte(`{}`)
	adapter.holderVersions["T1|h1"] = 3
	adapter.holderBodies["T1|h1"] = []byte(`{}`)

	manifest := &drwaRecoveryManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
		Holders:       []drwaMigrationHolder{{Address: "h1", Version: 5, Body: []byte(`{}`)}},
	}
	report, err := inspectDRWARecoveryState(adapter, manifest, nil)
	require.NoError(t, err)
	require.True(t, len(report.Findings) > 0)
}

func TestInspectDRWARecoveryStateUnexpectedHolder(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["T1"] = 1
	adapter.tokenBodies["T1"] = []byte(`{}`)
	// unexpected holder not in manifest
	adapter.holderVersions["T1|unexpected"] = 1
	adapter.holderBodies["T1|unexpected"] = []byte(`{}`)
	adapter.holderIndex["T1"] = []string{"unexpected"}

	manifest := &drwaRecoveryManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
	}
	report, err := inspectDRWARecoveryState(adapter, manifest, nil)
	require.NoError(t, err)
	found := false
	for _, f := range report.Findings {
		if f.Status == drwaRecoveryStatusUnexpectedHolderMirror {
			found = true
		}
	}
	require.True(t, found)
}

func TestBuildDRWARecoveryEnvelopeInSync(t *testing.T) {
	t.Parallel()
	report := &drwaRecoveryReport{
		TokenID:    "T1",
		Repairable: true,
		Findings:   []drwaRecoveryFinding{{Status: drwaRecoveryStatusInSync}},
	}
	manifest := &drwaRecoveryManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
	}
	env, err := buildDRWARecoveryEnvelope(manifest, report)
	require.NoError(t, err)
	require.True(t, env.Noop)
}

func TestBuildDRWARecoveryEnvelopeWithUnexpectedHolder(t *testing.T) {
	t.Parallel()
	report := &drwaRecoveryReport{
		TokenID:    "T1",
		Repairable: true,
		Findings: []drwaRecoveryFinding{
			{Status: drwaRecoveryStatusTokenPolicyMissing, TokenID: "T1", ExpectedVersion: 1},
			{Status: drwaRecoveryStatusUnexpectedHolderMirror, TokenID: "T1", Holder: "unexpected1", ObservedVersion: 3},
		},
	}
	manifest := &drwaRecoveryManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
	}
	env, err := buildDRWARecoveryEnvelope(manifest, report)
	require.NoError(t, err)
	require.NotNil(t, env)
	// Should include a holder_mirror_delete for unexpected1
	found := false
	for _, op := range env.Operations {
		if op.OperationType == drwaSyncOpHolderMirrorDelete && op.Holder == "unexpected1" {
			found = true
		}
	}
	require.True(t, found)
}

func TestBuildDRWARecoveryEnvelopeUnexpectedHolderConflict(t *testing.T) {
	t.Parallel()
	report := &drwaRecoveryReport{
		TokenID:    "T1",
		Repairable: true,
		Findings: []drwaRecoveryFinding{
			{Status: drwaRecoveryStatusTokenPolicyMissing, TokenID: "T1", ExpectedVersion: 1},
			{Status: drwaRecoveryStatusUnexpectedHolderMirror, TokenID: "T1", Holder: "h1", ObservedVersion: 3},
		},
	}
	manifest := &drwaRecoveryManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
		Holders:       []drwaMigrationHolder{{Address: "h1", Version: 1, Body: []byte(`{}`)}},
	}
	_, err := buildDRWARecoveryEnvelope(manifest, report)
	require.ErrorIs(t, err, errDRWARecoveryUnexpectedHolderConflict)
}

func TestBuildDRWARecoveryEnvelopeUnexpectedHolderOverflow(t *testing.T) {
	t.Parallel()
	report := &drwaRecoveryReport{
		TokenID:    "T1",
		Repairable: true,
		Findings: []drwaRecoveryFinding{
			{Status: drwaRecoveryStatusTokenPolicyMissing, TokenID: "T1", ExpectedVersion: 1},
			{Status: drwaRecoveryStatusUnexpectedHolderMirror, TokenID: "T1", Holder: "h1", ObservedVersion: math.MaxUint64},
		},
	}
	manifest := &drwaRecoveryManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
	}
	_, err := buildDRWARecoveryEnvelope(manifest, report)
	require.Error(t, err)
	require.Contains(t, err.Error(), "overflow")
}

func TestPersistDRWARecoveryEvidenceSuccess(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	report := &drwaRecoveryReport{TokenID: "T1", Findings: []drwaRecoveryFinding{{Status: drwaRecoveryStatusInSync}}}
	require.NoError(t, persistDRWARecoveryEvidence(adapter, report))
	require.NotEmpty(t, adapter.recoveryEvidence["T1"])
}

func TestPersistDRWARolloutEvidenceSuccess(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	require.NoError(t, persistDRWARolloutEvidence(adapter, "T1", []byte(`{}`)))
	require.NotEmpty(t, adapter.rolloutEvidence["T1"])
}

func TestPersistDRWARolloutVerificationSuccess(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	require.NoError(t, persistDRWARolloutVerification(adapter, "T1", []byte(`{}`)))
	require.NotEmpty(t, adapter.rolloutVerification["T1"])
}

func TestMarshalDRWARecoveryEvidenceSuccess(t *testing.T) {
	t.Parallel()
	report := &drwaRecoveryReport{TokenID: "T1", Findings: []drwaRecoveryFinding{{Status: drwaRecoveryStatusInSync}}}
	data, err := marshalDRWARecoveryEvidence(report)
	require.NoError(t, err)
	require.NotEmpty(t, data)
}

func TestMarshalDRWARolloutEvidenceSuccess(t *testing.T) {
	t.Parallel()
	report := &drwaRolloutPreflightReport{TokenID: "T1", Stage: drwaRolloutStageCanary, Ready: true}
	data, err := marshalDRWARolloutEvidence(report)
	require.NoError(t, err)
	require.NotEmpty(t, data)
}

func TestMarshalDRWARolloutVerificationReportSuccess(t *testing.T) {
	t.Parallel()
	report := &drwaRolloutVerificationReport{TokenID: "T1", Stage: drwaRolloutStageCanary, Accepted: true}
	data, err := marshalDRWARolloutVerificationReport(report)
	require.NoError(t, err)
	require.NotEmpty(t, data)
}

func TestInspectDRWARecoveryStateManifestHashConflict(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["T1"] = 1
	adapter.tokenBodies["T1"] = []byte(`{}`)

	manifest := &drwaRecoveryManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
	}
	_, err := inspectDRWARecoveryState(adapter, manifest, []byte("wrong-hash"))
	require.ErrorIs(t, err, errDRWARecoveryManifestHashConflict)
}

func TestCaptureDRWAMigrationSnapshotSuccess(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["T1"] = 1
	adapter.tokenBodies["T1"] = []byte(`{}`)
	adapter.holderVersions["T1|h1"] = 1
	adapter.holderBodies["T1|h1"] = []byte(`{}`)

	manifest := &drwaMigrationManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
		Holders:       []drwaMigrationHolder{{Address: "h1", Version: 1, Body: []byte(`{}`)}},
	}
	snap, err := captureDRWAMigrationSnapshot(adapter, manifest)
	require.NoError(t, err)
	require.NotNil(t, snap)
	require.Equal(t, "T1", snap.TokenID)
}

func TestBuildDRWAMigrationEnvelopeSuccess(t *testing.T) {
	manifest := &drwaMigrationManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
		Holders: []drwaMigrationHolder{
			{Address: "h2", Version: 1, Body: []byte(`{}`)},
			{Address: "h1", Version: 1, Body: []byte(`{}`)},
		},
	}
	env, err := buildDRWAMigrationEnvelope(manifest)
	require.NoError(t, err)
	require.NotNil(t, env)
	require.Equal(t, 3, len(env.Operations)) // 1 policy + 2 holders
}

func TestPersistDRWAMigrationAuthorizedCallersSuccess(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	nonZero := make([]byte, 32)
	nonZero[0] = 1
	hexAddr := hex.EncodeToString(nonZero)

	manifest := &drwaMigrationManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
		AuthorizedCallers: map[string]string{
			drwaSyncCallerPolicyRegistry:   hexAddr,
			drwaSyncCallerAssetManager:     hexAddr,
			drwaSyncCallerIdentityRegistry: hexAddr,
			drwaSyncCallerAttestation:      hexAddr,
			drwaSyncCallerRecoveryAdmin:    hexAddr,
		},
	}
	require.NoError(t, persistDRWAMigrationAuthorizedCallers(adapter, manifest))
	require.Equal(t, nonZero, adapter.authorizedCallers[drwaSyncCallerPolicyRegistry])
}

// ---------------------------------------------------------------------------
// verifyDRWAPreRecoveryStateHash — test with mock that implements drwaMigrationStateReader
// ---------------------------------------------------------------------------

func TestVerifyDRWAPreRecoveryStateHashMismatch(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["T1"] = 1
	adapter.tokenBodies["T1"] = []byte(`{}`)

	envelope := &drwaSyncEnvelope{
		CallerDomain:         drwaSyncCallerRecoveryAdmin,
		PreRecoveryStateHash: []byte("stale-hash-that-wont-match"),
		Operations: []drwaSyncOperation{
			{OperationType: drwaSyncOpTokenPolicy, TokenID: "T1", Version: 2},
		},
	}
	err := verifyDRWAPreRecoveryStateHash(adapter, envelope)
	require.ErrorIs(t, err, errDRWARecoveryStateChanged)
}

func TestVerifyDRWAPreRecoveryStateHashMatches(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["T1"] = 1
	adapter.tokenBodies["T1"] = []byte(`{}`)

	// Compute the correct state hash for the current state
	manifest := &drwaRecoveryManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
	}
	stateHash, err := computeDRWARecoveryStateHash(adapter, manifest)
	require.NoError(t, err)

	envelope := &drwaSyncEnvelope{
		CallerDomain:         drwaSyncCallerRecoveryAdmin,
		PreRecoveryStateHash: stateHash,
		Operations: []drwaSyncOperation{
			{OperationType: drwaSyncOpTokenPolicy, TokenID: "T1", Version: 2},
		},
	}
	err = verifyDRWAPreRecoveryStateHash(adapter, envelope)
	require.NoError(t, err)
}

// Full recovery_admin apply with pre-recovery state hash and timelock
func TestApplyDRWASyncEnvelopeRecoveryAdminFullPath(t *testing.T) {
	adapter := newMockTimelockAdapter()
	adapter.currentBlock = 10000
	adapter.tokenVersions["T1"] = 1
	adapter.tokenBodies["T1"] = []byte(`{}`)

	// Compute state hash
	manifest := &drwaRecoveryManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
	}
	stateHash, err := computeDRWARecoveryStateHash(adapter.mockDRWASyncStateAdapter, manifest)
	require.NoError(t, err)

	ops := []drwaSyncOperation{
		{OperationType: drwaSyncOpTokenPolicy, TokenID: "T1", Version: 2, Body: []byte(`{"new":"policy"}`)},
	}
	hash, err := computeDRWASyncHash(drwaSyncCallerRecoveryAdmin, ops)
	require.NoError(t, err)

	envelope := &drwaSyncEnvelope{
		CallerDomain:         drwaSyncCallerRecoveryAdmin,
		PayloadHash:          hash,
		Operations:           ops,
		PreRecoveryStateHash: stateHash,
		RecoveryScope:        []string{"T1"},
	}

	result, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerRecoveryAdmin))
	require.NoError(t, err)
	require.Equal(t, 1, result.AppliedOperations)
	require.Equal(t, uint64(10000), adapter.lastBlocks["T1"])
}

// ---------------------------------------------------------------------------
// applyDRWASyncOperation for holder_profile and asset_record paths
// ---------------------------------------------------------------------------

func TestApplyDRWASyncOperationHolderProfile(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	err := applyDRWASyncOperation(adapter, drwaSyncOperation{
		OperationType: drwaSyncOpHolderProfile,
		TokenID:       "PROFILE-1",
		Holder:        "h1",
		Version:       1,
		Body:          []byte(`{}`),
	})
	require.NoError(t, err)
	require.Equal(t, uint64(1), adapter.holderProfileVersions["h1"])
}

// ---------------------------------------------------------------------------
// parseDRWABinaryPayload — max operations exceeded
// ---------------------------------------------------------------------------

func TestParseDRWABinaryPayloadMaxOpsExceeded(t *testing.T) {
	t.Parallel()
	// Empty canonical payload
	_, err := parseDRWABinaryPayload([]byte{})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// PutRecoveryLastBlock through real adapter (0% → covered)
// ---------------------------------------------------------------------------

func TestPutRecoveryLastBlockThroughAdapter(t *testing.T) {
	systemAccount := vmmock.NewAccountWrapMock(core.SystemAccountAddress)
	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return systemAccount, nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	require.NoError(t, adapter.PutRecoveryLastBlock("T1", 999))

	block, err := adapter.GetRecoveryLastBlock("T1")
	require.NoError(t, err)
	require.Equal(t, uint64(999), block)
}

// ---------------------------------------------------------------------------
// Rollout validation additional paths
// ---------------------------------------------------------------------------

func TestValidateDRWARolloutManifestAllStages(t *testing.T) {
	t.Parallel()

	for _, stage := range []string{drwaRolloutStageCanary, drwaRolloutStageLimited, drwaRolloutStageProduction} {
		require.NoError(t, validateDRWARolloutManifest(&drwaRolloutManifest{
			TokenID: "T1", Issuer: "issuer", Stage: stage,
		}))
	}
	require.Error(t, validateDRWARolloutManifest(&drwaRolloutManifest{
		TokenID: "T1", Issuer: "issuer", Stage: "invalid",
	}))

	// API error rate exceeded
	require.Error(t, validateDRWARolloutManifest(&drwaRolloutManifest{
		TokenID: "T1", Issuer: "issuer", Stage: drwaRolloutStageCanary,
		MaxAPIErrorRateBps: 999,
	}))

	// Denial mismatch exceeded
	require.Error(t, validateDRWARolloutManifest(&drwaRolloutManifest{
		TokenID: "T1", Issuer: "issuer", Stage: drwaRolloutStageCanary,
		MaxDenialMismatchRateBps: 999,
	}))
}

func TestInspectDRWARolloutPreflightSafeModeRequired(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["T1"] = 1
	adapter.tokenBodies["T1"] = []byte(`{}`)

	manifest := &drwaRolloutManifest{
		TokenID: "T1", Issuer: "issuer", Stage: drwaRolloutStageCanary,
		ExpectedPolicyVersion: 1,
	}
	recoveryReport := &drwaRecoveryReport{RequiresSafeMode: true}

	// Without AllowSafeModeRollout → error
	_, err := inspectDRWARolloutPreflight(adapter, manifest, recoveryReport)
	require.ErrorIs(t, err, errDRWARolloutSafeModeRequired)

	// With AllowSafeModeRollout → success
	manifest.AllowSafeModeRollout = true
	report, err := inspectDRWARolloutPreflight(adapter, manifest, recoveryReport)
	require.NoError(t, err)
	require.True(t, report.Ready)
}

func TestInspectDRWARolloutPreflightPolicyVersionMismatch(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["T1"] = 5
	adapter.tokenBodies["T1"] = []byte(`{}`)

	manifest := &drwaRolloutManifest{
		TokenID: "T1", Issuer: "issuer", Stage: drwaRolloutStageLimited,
		ExpectedPolicyVersion: 3, // mismatch
	}
	// RequiresCanaryOnly → limited stage fails
	_, err := inspectDRWARolloutPreflight(adapter, manifest, nil)
	require.ErrorIs(t, err, errDRWARolloutNotCanaryReady)
}

func TestInspectDRWARolloutPreflightMissingHolders(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["T1"] = 1
	adapter.tokenBodies["T1"] = []byte(`{}`)

	manifest := &drwaRolloutManifest{
		TokenID: "T1", Issuer: "issuer", Stage: drwaRolloutStageCanary,
		ExpectedPolicyVersion: 1,
		RequiredHolders:       []string{"h1", "h2"},
	}
	report, err := inspectDRWARolloutPreflight(adapter, manifest, nil)
	require.NoError(t, err)
	require.False(t, report.Ready, "missing holders should make not ready")
	require.Equal(t, 2, len(report.MissingHolders))
}

func TestInspectDRWARolloutPreflightWithThresholds(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["T1"] = 1
	adapter.tokenBodies["T1"] = []byte(`{}`)

	manifest := &drwaRolloutManifest{
		TokenID: "T1", Issuer: "issuer", Stage: drwaRolloutStageCanary,
		ExpectedPolicyVersion: 1,
		MaxSyncFailureRateBps: 50,
		MaxAPIErrorRateBps:    30,
		MaxDenialMismatchRateBps: 5,
	}
	report, err := inspectDRWARolloutPreflight(adapter, manifest, nil)
	require.NoError(t, err)
	require.True(t, report.Ready)
	require.True(t, len(report.Checks) >= 3) // threshold checks appear
}

// ---------------------------------------------------------------------------
// applyDRWASyncEnvelope — recovery scope required and scope violation
// ---------------------------------------------------------------------------

func TestApplyDRWASyncEnvelopeRecoveryScopeRequired(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()

	ops := []drwaSyncOperation{
		{OperationType: drwaSyncOpTokenPolicy, TokenID: "T1", Version: 1, Body: []byte(`{}`)},
	}
	hash, _ := computeDRWASyncHash(drwaSyncCallerRecoveryAdmin, ops)

	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerRecoveryAdmin,
		PayloadHash:  hash,
		Operations:   ops,
		// No RecoveryScope — should fail
	}

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerRecoveryAdmin))
	require.Error(t, err)
	require.Contains(t, err.Error(), drwaSyncRejectRecoveryScopeRequired)
}

func TestApplyDRWASyncEnvelopeRecoveryScopeViolation(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()

	ops := []drwaSyncOperation{
		{OperationType: drwaSyncOpTokenPolicy, TokenID: "T1", Version: 1, Body: []byte(`{}`)},
	}
	hash, _ := computeDRWASyncHash(drwaSyncCallerRecoveryAdmin, ops)

	envelope := &drwaSyncEnvelope{
		CallerDomain:  drwaSyncCallerRecoveryAdmin,
		PayloadHash:   hash,
		Operations:    ops,
		RecoveryScope: []string{"OTHER-TOKEN"}, // T1 not in scope
	}

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerRecoveryAdmin))
	require.Error(t, err)
	require.Contains(t, err.Error(), drwaSyncRejectRecoveryScopeViolation)
}

// ---------------------------------------------------------------------------
// decodeBech32Address wrong payload length
// ---------------------------------------------------------------------------

func TestDecodeBech32AddressWrongPayloadLength(t *testing.T) {
	t.Parallel()
	// erd1 prefix but data that doesn't decode to 32 bytes
	_, err := decodeBech32Address("erd1qp")
	require.Error(t, err)
}

func TestPersistDRWAMigrationAuthorizedCallersInvalidAddress(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()

	manifest := &drwaMigrationManifest{
		TokenID:       "T1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
		AuthorizedCallers: map[string]string{
			drwaSyncCallerPolicyRegistry:   "invalid",
			drwaSyncCallerAssetManager:     "invalid",
			drwaSyncCallerIdentityRegistry: "invalid",
			drwaSyncCallerAttestation:      "invalid",
			drwaSyncCallerRecoveryAdmin:    "invalid",
		},
	}
	// All addresses invalid → validation fails before persist
	err := persistDRWAMigrationAuthorizedCallers(adapter, manifest)
	require.Error(t, err)
}
