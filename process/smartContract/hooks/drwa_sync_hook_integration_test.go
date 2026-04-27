package hooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/keccak"
	"github.com/stretchr/testify/require"
)

const (
	drwaIntTestTokenEstate = "ESTATE-a1b2c3"
	drwaIntTestTokenCarbon = "CARBON-1"
	drwaIntTestMsgDecode   = "decodeDRWASyncEnvelope: %v"
	drwaIntTestMsgApply    = "applyDRWASyncEnvelope: %v"
)

// buildBinaryEnvelope constructs the wire-format payload that the Rust
// managedDRWASyncMirror hook produces: [32-byte keccak256 hash] || [canonical binary payload].
func buildBinaryEnvelope(t *testing.T, callerDomain string, operations []drwaSyncOperation) []byte {
	t.Helper()

	canonical, err := serializeDRWASyncEnvelopePayload(callerDomain, operations)
	if err != nil {
		t.Fatalf("serializeDRWASyncEnvelopePayload: %v", err)
	}

	hash := keccak.NewKeccak().Compute(string(canonical))
	if len(hash) != drwaBinaryHashSize {
		t.Fatalf("expected %d-byte hash, got %d", drwaBinaryHashSize, len(hash))
	}

	var envelope bytes.Buffer
	envelope.Write(hash)
	envelope.Write(canonical)
	return envelope.Bytes()
}

// --- Integration: decode → apply pipeline (binary path) ---

func TestIntegrationBinaryPipelineTokenPolicyAndHolderMirror(t *testing.T) {
	tokenPolicyOp := drwaSyncOperation{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       drwaIntTestTokenEstate,
		Version:       1,
		Body:          []byte(`{"transferable":true,"max_supply":"1000000"}`),
	}
	holderMirrorOp := drwaSyncOperation{
		OperationType: drwaSyncOpHolderMirror,
		TokenID:       drwaIntTestTokenEstate,
		Holder:        "erd1qqqqqqqqqqqqqpgq0000000000000000000000000000000000000000001",
		Version:       1,
		Body:          []byte(`{"kyc_status":"verified","country":"SG"}`),
	}

	operations := []drwaSyncOperation{tokenPolicyOp, holderMirrorOp}
	payload := buildBinaryEnvelope(t, drwaSyncCallerRecoveryAdmin, operations)

	envelope, err := decodeDRWASyncEnvelope(payload)
	if err != nil {
		t.Fatalf(drwaIntTestMsgDecode, err)
	}
	if len(envelope.Operations) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(envelope.Operations))
	}

	// Recovery admin envelopes require an explicit recovery scope listing the
	// token IDs the operations target.
	envelope.RecoveryScope = []string{drwaIntTestTokenEstate}

	adapter := newMockDRWASyncStateAdapter()
	callerAddr := testDRWACallerAddress(drwaSyncCallerRecoveryAdmin)

	result, err := applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, callerAddr)
	if err != nil {
		t.Fatalf(drwaIntTestMsgApply, err)
	}
	if result.AppliedOperations != 2 {
		t.Fatalf("expected 2 applied operations, got %d", result.AppliedOperations)
	}
	if result.LastTokenID != drwaIntTestTokenEstate {
		t.Fatalf("expected last token ID %s, got %s", drwaIntTestTokenEstate, result.LastTokenID)
	}

	if adapter.tokenVersions[drwaIntTestTokenEstate] != 1 {
		t.Fatal("token policy version not set to 1")
	}
	if !bytes.Equal(adapter.tokenBodies[drwaIntTestTokenEstate], tokenPolicyOp.Body) {
		t.Fatal("token policy body mismatch")
	}

	holderKey := drwaIntTestTokenEstate + "|" + holderMirrorOp.Holder
	if adapter.holderVersions[holderKey] != 1 {
		t.Fatal("holder mirror version not set to 1")
	}
	if !bytes.Equal(adapter.holderBodies[holderKey], holderMirrorOp.Body) {
		t.Fatal("holder mirror body mismatch")
	}
}

func TestIntegrationBinaryPipelinePolicyRegistryTokenPolicy(t *testing.T) {
	op := drwaSyncOperation{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "BOND-ff0011",
		Version:       1,
		Body:          []byte(`{"freeze_enabled":true}`),
	}

	payload := buildBinaryEnvelope(t, drwaSyncCallerPolicyRegistry, []drwaSyncOperation{op})
	envelope, err := decodeDRWASyncEnvelope(payload)
	if err != nil {
		t.Fatalf(drwaIntTestMsgDecode, err)
	}

	adapter := newMockDRWASyncStateAdapter()
	result, err := applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err != nil {
		t.Fatalf(drwaIntTestMsgApply, err)
	}
	if result.AppliedOperations != 1 {
		t.Fatalf(drwaTestMsgOneApplied, result.AppliedOperations)
	}
	if adapter.tokenVersions["BOND-ff0011"] != 1 {
		t.Fatal("token policy version not written")
	}
}

func TestIntegrationBinaryPipelineAssetManagerHolderMirror(t *testing.T) {
	op := drwaSyncOperation{
		OperationType: drwaSyncOpHolderMirror,
		TokenID:       "FUND-001122",
		Holder:        "erd1holder",
		Version:       1,
		Body:          []byte(`{"accredited":true}`),
	}

	payload := buildBinaryEnvelope(t, drwaSyncCallerAssetManager, []drwaSyncOperation{op})
	envelope, err := decodeDRWASyncEnvelope(payload)
	if err != nil {
		t.Fatalf(drwaIntTestMsgDecode, err)
	}

	adapter := newMockDRWASyncStateAdapter()
	result, err := applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerAssetManager))
	if err != nil {
		t.Fatalf(drwaIntTestMsgApply, err)
	}
	if result.AppliedOperations != 1 {
		t.Fatalf(drwaTestMsgOneApplied, result.AppliedOperations)
	}
	if adapter.holderVersions["FUND-001122|erd1holder"] != 1 {
		t.Fatal("holder mirror version not written")
	}
}

func TestIntegrationBinaryPipelineMultipleTokenPolicies(t *testing.T) {
	ops := []drwaSyncOperation{
		{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "TOKEN-A",
			Version:       1,
			Body:          []byte(`{"a":1}`),
		},
		{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "TOKEN-B",
			Version:       1,
			Body:          []byte(`{"b":2}`),
		},
	}

	payload := buildBinaryEnvelope(t, drwaSyncCallerPolicyRegistry, ops)
	envelope, err := decodeDRWASyncEnvelope(payload)
	if err != nil {
		t.Fatalf(drwaIntTestMsgDecode, err)
	}

	adapter := newMockDRWASyncStateAdapter()
	result, err := applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err != nil {
		t.Fatalf(drwaIntTestMsgApply, err)
	}
	if result.AppliedOperations != 2 {
		t.Fatalf("expected 2 applied operations, got %d", result.AppliedOperations)
	}
	if adapter.tokenVersions["TOKEN-A"] != 1 || adapter.tokenVersions["TOKEN-B"] != 1 {
		t.Fatal("both token policies should be at version 1")
	}
}

func TestIntegrationBinaryPipelineAuthAdminAuthorizedCallerUpdate(t *testing.T) {
	op := drwaSyncOperation{
		OperationType: drwaSyncOpAuthorizedCallerUpdate,
		TokenID:       drwaSyncCallerPolicyRegistry,
		Version:       1,
		Body:          []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
	}

	payload := buildBinaryEnvelope(t, drwaSyncCallerAuthAdmin, []drwaSyncOperation{op})
	envelope, err := decodeDRWASyncEnvelope(payload)
	if err != nil {
		t.Fatalf(drwaIntTestMsgDecode, err)
	}

	adapter := newMockDRWASyncStateAdapter()
	result, err := applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerAuthAdmin))
	if err != nil {
		t.Fatalf(drwaIntTestMsgApply, err)
	}
	if result.AppliedOperations != 1 {
		t.Fatalf(drwaTestMsgOneApplied, result.AppliedOperations)
	}
	if adapter.authorizedCallerVersions[drwaSyncCallerPolicyRegistry] != 1 {
		t.Fatal("authorized caller version not written")
	}

	expected, err := NormalizeDRWAAuthorizedCallerAddress(string(op.Body))
	if err != nil {
		t.Fatalf("NormalizeDRWAAuthorizedCallerAddress: %v", err)
	}
	if !bytes.Equal(adapter.authorizedCallers[drwaSyncCallerPolicyRegistry], expected) {
		t.Fatal("authorized caller body mismatch")
	}
}

func TestIntegrationBinaryPipelineAuthAdminRejectsVersionGap(t *testing.T) {
	op := drwaSyncOperation{
		OperationType: drwaSyncOpAuthorizedCallerUpdate,
		TokenID:       drwaSyncCallerPolicyRegistry,
		Version:       3,
		Body:          []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
	}

	payload := buildBinaryEnvelope(t, drwaSyncCallerAuthAdmin, []drwaSyncOperation{op})
	envelope, err := decodeDRWASyncEnvelope(payload)
	if err != nil {
		t.Fatalf(drwaIntTestMsgDecode, err)
	}

	adapter := newMockDRWASyncStateAdapter()
	require.NoError(t, adapter.SetAuthorizedCallerAddressVersioned(drwaSyncCallerPolicyRegistry, testDRWACallerAddress(drwaSyncCallerPolicyRegistry), 1))

	_, err = applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerAuthAdmin))
	if err == nil || err.Error() != drwaSyncRejectVersionGap {
		t.Fatalf("expected version gap rejection for auth_admin update, got %v", err)
	}
}

func TestIntegrationBinaryPipelineAuthAdminRejectsEmptyDomain(t *testing.T) {
	op := drwaSyncOperation{
		OperationType: drwaSyncOpAuthorizedCallerUpdate,
		TokenID:       "",
		Version:       1,
		Body:          []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
	}

	payload := buildBinaryEnvelope(t, drwaSyncCallerAuthAdmin, []drwaSyncOperation{op})
	_, err := decodeDRWASyncEnvelope(payload)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid token_id")

	_ = newMockDRWASyncStateAdapter()
}

func TestIntegrationBinaryPipelineAuthAdminRejectsControlCharDomain(t *testing.T) {
	op := drwaSyncOperation{
		OperationType: drwaSyncOpAuthorizedCallerUpdate,
		TokenID:       "policy\x00registry",
		Version:       1,
		Body:          []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
	}

	payload := buildBinaryEnvelope(t, drwaSyncCallerAuthAdmin, []drwaSyncOperation{op})
	_, err := decodeDRWASyncEnvelope(payload)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid token_id")

	_ = newMockDRWASyncStateAdapter()
}

func TestIntegrationBinaryPipelineAuthAdminRejectsHashMismatch(t *testing.T) {
	op := drwaSyncOperation{
		OperationType: drwaSyncOpAuthorizedCallerUpdate,
		TokenID:       drwaSyncCallerPolicyRegistry,
		Version:       1,
		Body:          []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
	}

	canonical, err := serializeDRWASyncEnvelopePayload(drwaSyncCallerAuthAdmin, []drwaSyncOperation{op})
	if err != nil {
		t.Fatalf("serializeDRWASyncEnvelopePayload: %v", err)
	}
	badHash, err := computeDRWASyncHash(drwaSyncCallerPolicyRegistry, []drwaSyncOperation{op})
	if err != nil {
		t.Fatalf("computeDRWASyncHash: %v", err)
	}

	payload := append(badHash, canonical...)
	envelope, err := decodeDRWASyncEnvelope(payload)
	if err != nil {
		t.Fatalf(drwaIntTestMsgDecode, err)
	}

	adapter := newMockDRWASyncStateAdapter()
	_, err = applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerAuthAdmin))
	if err == nil || err.Error() != drwaSyncRejectHashMismatch {
		t.Fatalf("expected hash mismatch rejection, got %v", err)
	}
}

func TestIntegrationBinaryPipelineAuthAdminUnauthorizedCaller(t *testing.T) {
	op := drwaSyncOperation{
		OperationType: drwaSyncOpAuthorizedCallerUpdate,
		TokenID:       drwaSyncCallerPolicyRegistry,
		Version:       1,
		Body:          []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
	}

	payload := buildBinaryEnvelope(t, drwaSyncCallerAuthAdmin, []drwaSyncOperation{op})
	envelope, err := decodeDRWASyncEnvelope(payload)
	if err != nil {
		t.Fatalf(drwaIntTestMsgDecode, err)
	}

	adapter := newMockDRWASyncStateAdapter()
	_, err = applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, []byte("wrong_auth_admin"))
	if err == nil || err.Error() != drwaSyncRejectUnauthorizedCaller {
		t.Fatalf("expected unauthorized caller rejection, got %v", err)
	}
}

func TestIntegrationBinaryPipelineAuthAdminRejectsInvalidAddressBody(t *testing.T) {
	op := drwaSyncOperation{
		OperationType: drwaSyncOpAuthorizedCallerUpdate,
		TokenID:       drwaSyncCallerPolicyRegistry,
		Version:       1,
		Body:          []byte("not-hex-not-bech32"),
	}

	payload := buildBinaryEnvelope(t, drwaSyncCallerAuthAdmin, []drwaSyncOperation{op})
	envelope, err := decodeDRWASyncEnvelope(payload)
	if err != nil {
		t.Fatalf(drwaIntTestMsgDecode, err)
	}

	adapter := newMockDRWASyncStateAdapter()
	_, err = applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerAuthAdmin))
	if err == nil {
		t.Fatal("expected invalid authorized caller body rejection")
	}
	if !errors.Is(err, errDRWAInvalidAuthorizedCaller) {
		t.Fatalf("expected errDRWAInvalidAuthorizedCaller, got %v", err)
	}
}

func TestIntegrationBinaryPipelineAuthAdminRejectsDomainOperationMismatch(t *testing.T) {
	op := drwaSyncOperation{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       drwaIntTestTokenCarbon,
		Version:       1,
		Body:          []byte(`{}`),
	}

	payload := buildBinaryEnvelope(t, drwaSyncCallerAuthAdmin, []drwaSyncOperation{op})
	envelope, err := decodeDRWASyncEnvelope(payload)
	if err != nil {
		t.Fatalf(drwaIntTestMsgDecode, err)
	}

	adapter := newMockDRWASyncStateAdapter()
	_, err = applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerAuthAdmin))
	if err == nil || err.Error() != drwaSyncRejectUnauthorizedCaller {
		t.Fatalf("expected unauthorized caller rejection for auth_admin domain/op mismatch, got %v", err)
	}
}

// --- Error cases ---

func TestIntegrationBinaryPipelineMalformedPayloadTooShort(t *testing.T) {
	payload := make([]byte, drwaBinaryHashSize)
	_, err := decodeDRWASyncEnvelope(payload)
	if err == nil {
		t.Fatal("expected error for too-short binary payload")
	}
}

func TestIntegrationBinaryPipelineMalformedPayloadInvalidCallerTag(t *testing.T) {
	var payload bytes.Buffer
	payload.Write(make([]byte, drwaBinaryHashSize))
	payload.WriteByte(0xFF)
	_, err := decodeDRWASyncEnvelope(payload.Bytes())
	if err == nil {
		t.Fatal("expected error for invalid caller domain tag")
	}
}

func TestIntegrationBinaryPipelineMalformedPayloadTruncatedOperation(t *testing.T) {
	var payload bytes.Buffer
	payload.Write(make([]byte, drwaBinaryHashSize))
	payload.WriteByte(0) // policy_registry caller tag
	payload.WriteByte(0) // token_policy op tag
	_, err := decodeDRWASyncEnvelope(payload.Bytes())
	if err == nil {
		t.Fatal("expected error for truncated operation")
	}
}

func TestIntegrationBinaryPipelineHashMismatch(t *testing.T) {
	op := drwaSyncOperation{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       drwaIntTestTokenCarbon,
		Version:       1,
		Body:          []byte(`{}`),
	}

	payload := buildBinaryEnvelope(t, drwaSyncCallerPolicyRegistry, []drwaSyncOperation{op})
	payload[0] ^= 0xFF

	envelope, err := decodeDRWASyncEnvelope(payload)
	if err != nil {
		t.Fatalf("decode should succeed even with wrong hash: %v", err)
	}

	adapter := newMockDRWASyncStateAdapter()
	_, err = applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err == nil || err.Error() != drwaSyncRejectHashMismatch {
		t.Fatalf("expected hash mismatch rejection, got %v", err)
	}
}

func TestIntegrationBinaryPipelineUnauthorizedCaller(t *testing.T) {
	op := drwaSyncOperation{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       drwaIntTestTokenCarbon,
		Version:       1,
		Body:          []byte(`{}`),
	}

	payload := buildBinaryEnvelope(t, drwaSyncCallerPolicyRegistry, []drwaSyncOperation{op})
	envelope, err := decodeDRWASyncEnvelope(payload)
	if err != nil {
		t.Fatalf(drwaIntTestMsgDecode, err)
	}

	adapter := newMockDRWASyncStateAdapter()
	_, err = applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, []byte("wrong_address"))
	if err == nil || err.Error() != drwaSyncRejectUnauthorizedCaller {
		t.Fatalf("expected unauthorized caller rejection, got %v", err)
	}
}

func TestIntegrationBinaryPipelineUnauthorizedCallerEmptyAddress(t *testing.T) {
	op := drwaSyncOperation{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       drwaIntTestTokenCarbon,
		Version:       1,
		Body:          []byte(`{}`),
	}

	payload := buildBinaryEnvelope(t, drwaSyncCallerPolicyRegistry, []drwaSyncOperation{op})
	envelope, err := decodeDRWASyncEnvelope(payload)
	if err != nil {
		t.Fatalf(drwaIntTestMsgDecode, err)
	}

	adapter := newMockDRWASyncStateAdapter()
	_, err = applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, nil)
	if err == nil || err.Error() != drwaSyncRejectUnauthorizedCaller {
		t.Fatalf("expected unauthorized caller rejection for nil address, got %v", err)
	}
}

func TestIntegrationBinaryPipelineCallerDomainOperationMismatch(t *testing.T) {
	op := drwaSyncOperation{
		OperationType: drwaSyncOpHolderMirror,
		TokenID:       drwaIntTestTokenCarbon,
		Holder:        "erd1holder",
		Version:       1,
		Body:          []byte(`{}`),
	}

	payload := buildBinaryEnvelope(t, drwaSyncCallerPolicyRegistry, []drwaSyncOperation{op})
	envelope, err := decodeDRWASyncEnvelope(payload)
	if err != nil {
		t.Fatalf(drwaIntTestMsgDecode, err)
	}

	adapter := newMockDRWASyncStateAdapter()
	_, err = applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err == nil || err.Error() != drwaSyncRejectUnauthorizedCaller {
		t.Fatalf("expected unauthorized caller rejection for domain/op mismatch, got %v", err)
	}
}

func TestIntegrationBinaryPipelineVersionGapRejection(t *testing.T) {
	op := drwaSyncOperation{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "GAP-TOKEN",
		Version:       2,
		Body:          []byte(`{}`),
	}

	payload := buildBinaryEnvelope(t, drwaSyncCallerPolicyRegistry, []drwaSyncOperation{op})
	envelope, err := decodeDRWASyncEnvelope(payload)
	if err != nil {
		t.Fatalf(drwaIntTestMsgDecode, err)
	}

	adapter := newMockDRWASyncStateAdapter()
	_, err = applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err == nil || err.Error() != drwaSyncRejectVersionGap {
		t.Fatalf("expected version gap rejection, got %v", err)
	}
}

func TestIntegrationBinaryPipelineAtomicRollbackOnPartialFailure(t *testing.T) {
	ops := []drwaSyncOperation{
		{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "TOKEN-OK",
			Version:       1,
			Body:          []byte(`{"ok":true}`),
		},
		{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "TOKEN-FAIL",
			Version:       5, // gap
			Body:          []byte(`{"fail":true}`),
		},
	}

	payload := buildBinaryEnvelope(t, drwaSyncCallerPolicyRegistry, ops)
	envelope, err := decodeDRWASyncEnvelope(payload)
	if err != nil {
		t.Fatalf(drwaIntTestMsgDecode, err)
	}

	adapter := newMockDRWASyncStateAdapter()
	_, err = applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err == nil {
		t.Fatal("expected version gap error on second operation")
	}
	if !adapter.rolledBack {
		t.Fatal("expected adapter rollback after partial failure")
	}
}

func TestIntegrationBinaryPipelineNilPayload(t *testing.T) {
	_, err := decodeDRWASyncEnvelope(nil)
	if err == nil {
		t.Fatal("expected error for nil payload")
	}
}

func TestIntegrationBinaryPipelineEmptyPayload(t *testing.T) {
	_, err := decodeDRWASyncEnvelope([]byte{})
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
}

// --- JSON path integration ---

func TestIntegrationJSONPipelineTokenPolicyEndToEnd(t *testing.T) {
	op := drwaSyncOperation{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       drwaIntTestTokenCarbon,
		Version:       1,
		Body:          []byte(`{"transferable":false}`),
	}
	hash, err := computeDRWASyncHash(drwaSyncCallerPolicyRegistry, []drwaSyncOperation{op})
	if err != nil {
		t.Fatalf("computeDRWASyncHash: %v", err)
	}

	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		PayloadHash:  hash,
		Operations:   []drwaSyncOperation{op},
	}

	jsonPayload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal envelope: %v", err)
	}

	decodedEnvelope, err := decodeDRWASyncEnvelope(jsonPayload)
	if err != nil {
		t.Fatalf(drwaIntTestMsgDecode, err)
	}

	adapter := newMockDRWASyncStateAdapter()
	result, err := applyDRWASyncEnvelope(adapter, decodedEnvelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err != nil {
		t.Fatalf(drwaIntTestMsgApply, err)
	}
	if result.AppliedOperations != 1 {
		t.Fatalf(drwaTestMsgOneApplied, result.AppliedOperations)
	}
	if adapter.tokenVersions[drwaIntTestTokenCarbon] != 1 {
		t.Fatal("token policy version not written via JSON pipeline")
	}
	if !bytes.Equal(adapter.tokenBodies[drwaIntTestTokenCarbon], op.Body) {
		t.Fatal("token policy body mismatch via JSON pipeline")
	}
}

func TestIntegrationJSONPipelineHashMismatch(t *testing.T) {
	op := drwaSyncOperation{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       drwaIntTestTokenCarbon,
		Version:       1,
		Body:          []byte(`{}`),
	}
	hash, err := computeDRWASyncHash(drwaSyncCallerPolicyRegistry, []drwaSyncOperation{op})
	if err != nil {
		t.Fatalf("computeDRWASyncHash: %v", err)
	}

	corruptHash := make([]byte, len(hash))
	copy(corruptHash, hash)
	corruptHash[0] ^= 0xFF

	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		PayloadHash:  corruptHash,
		Operations:   []drwaSyncOperation{op},
	}

	jsonPayload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	decodedEnvelope, err := decodeDRWASyncEnvelope(jsonPayload)
	if err != nil {
		t.Fatalf(drwaIntTestMsgDecode, err)
	}

	adapter := newMockDRWASyncStateAdapter()
	_, err = applyDRWASyncEnvelope(adapter, decodedEnvelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err == nil || err.Error() != drwaSyncRejectHashMismatch {
		t.Fatalf("expected hash mismatch rejection via JSON pipeline, got %v", err)
	}
}

func TestIntegrationJSONPipelineMalformedJSON(t *testing.T) {
	payload := []byte(`{"caller_domain":"policy_registry","operations":[{`)
	_, err := decodeDRWASyncEnvelope(payload)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}
