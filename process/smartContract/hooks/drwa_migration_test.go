package hooks

import (
	"bytes"
	"encoding/hex"
	"math"
	"strings"
	"testing"
)

func TestValidateDRWAMigrationManifestRejectsDuplicateHolder(t *testing.T) {
	t.Parallel()

	err := validateDRWAMigrationManifest(&drwaMigrationManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{"drwa_enabled":true}`),
		Holders: []drwaMigrationHolder{
			{Address: "erd1holder", Version: 1, Body: []byte(`{}`)},
			{Address: "erd1holder", Version: 2, Body: []byte(`{}`)},
		},
	})

	if err == nil {
		t.Fatalf("expected duplicate holder rejection")
	}
}

func TestBuildDRWAMigrationEnvelopeOrdersPolicyThenSortedHolders(t *testing.T) {
	t.Parallel()

	envelope, err := buildDRWAMigrationEnvelope(&drwaMigrationManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 7,
		PolicyBody:    []byte(`{"drwa_enabled":true}`),
		Holders: []drwaMigrationHolder{
			{Address: "erd1z", Version: 3, Body: []byte(`{"kyc":"approved"}`)},
			{Address: "erd1a", Version: 2, Body: []byte(`{"kyc":"approved"}`)},
		},
	})
	if err != nil {
		t.Fatalf("build envelope: %v", err)
	}

	if envelope.CallerDomain != drwaSyncCallerRecoveryAdmin {
		t.Fatalf("unexpected caller domain: %s", envelope.CallerDomain)
	}
	if len(envelope.Operations) != 3 {
		t.Fatalf("unexpected operations len: %d", len(envelope.Operations))
	}
	if envelope.Operations[0].OperationType != drwaSyncOpTokenPolicy {
		t.Fatalf("expected token policy first")
	}
	if envelope.Operations[1].Holder != "erd1a" || envelope.Operations[2].Holder != "erd1z" {
		t.Fatalf("holders not sorted: %+v", envelope.Operations)
	}
	if len(envelope.PayloadHash) == 0 {
		t.Fatalf("expected payload hash")
	}
}

func TestCaptureDRWAMigrationSnapshotAndBuildRollbackEnvelope(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["CARBON-1"] = 5
	adapter.tokenBodies["CARBON-1"] = []byte(`{"drwa_enabled":false}`)
	adapter.holderVersions["CARBON-1|erd1a"] = 4
	adapter.holderBodies["CARBON-1|erd1a"] = []byte(`{"kyc":"approved"}`)

	manifest := &drwaMigrationManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 6,
		PolicyBody:    []byte(`{"drwa_enabled":true}`),
		Holders: []drwaMigrationHolder{
			{Address: "erd1a", Version: 5, Body: []byte(`{"kyc":"approved"}`)},
			{Address: "erd1b", Version: 1, Body: []byte(`{"kyc":"approved"}`)},
		},
	}

	snapshot, err := captureDRWAMigrationSnapshot(adapter, manifest)
	if err != nil {
		t.Fatalf("capture snapshot: %v", err)
	}

	if snapshot.TokenPolicy == nil || snapshot.TokenPolicy.Version != 5 {
		t.Fatalf("unexpected token policy snapshot: %+v", snapshot.TokenPolicy)
	}
	if snapshot.Holders["erd1a"] == nil || snapshot.Holders["erd1a"].Version != 4 {
		t.Fatalf("unexpected holder snapshot: %+v", snapshot.Holders["erd1a"])
	}
	if snapshot.Holders["erd1b"] != nil {
		t.Fatalf("expected nil snapshot for new holder")
	}

	rollbackEnvelope, err := buildDRWARollbackEnvelope(snapshot)
	if err != nil {
		t.Fatalf("build rollback envelope: %v", err)
	}

	if len(rollbackEnvelope.Operations) != 3 {
		t.Fatalf("unexpected rollback operations: %d", len(rollbackEnvelope.Operations))
	}
	// SM-2: Rollback now uses stored.Version + 1 (post-migration version).
	// Snapshot captured version 5, so rollback uses 6.
	if rollbackEnvelope.Operations[0].Version != 6 {
		t.Fatalf("unexpected rollback token version: %d", rollbackEnvelope.Operations[0].Version)
	}
	if rollbackEnvelope.Operations[1].Holder != "erd1a" {
		t.Fatalf("unexpected rollback holder: %s", rollbackEnvelope.Operations[1].Holder)
	}
	if !bytes.Equal(rollbackEnvelope.Operations[1].Body, []byte(`{"kyc":"approved"}`)) {
		t.Fatalf("unexpected rollback body: %s", string(rollbackEnvelope.Operations[1].Body))
	}
	if rollbackEnvelope.Operations[2].OperationType != drwaSyncOpHolderMirrorDelete {
		t.Fatalf("expected delete operation for new holder, got %+v", rollbackEnvelope.Operations[2])
	}
	if rollbackEnvelope.Operations[2].Holder != "erd1b" {
		t.Fatalf("unexpected rollback delete holder: %s", rollbackEnvelope.Operations[2].Holder)
	}
	if rollbackEnvelope.Operations[2].Version != 2 {
		t.Fatalf("unexpected rollback delete version: %d", rollbackEnvelope.Operations[2].Version)
	}
}

func TestBuildDRWARollbackEnvelopeRejectsDeleteVersionOverflow(t *testing.T) {
	t.Parallel()

	snapshot := &drwaMigrationSnapshot{
		TokenID: "CARBON-1",
		Holders: map[string]*drwaSyncStoredValue{
			"erd1holder": nil,
		},
		RequestedHolderState: map[string]drwaMigrationHolder{
			"erd1holder": {
				Address: "erd1holder",
				Version: math.MaxUint64,
			},
		},
	}

	_, err := buildDRWARollbackEnvelope(snapshot)
	if err == nil || !strings.Contains(err.Error(), "rollback delete version overflow") {
		t.Fatalf("expected overflow rejection, got %v", err)
	}
}

func TestApplyDRWAMigrationEnvelopeRollsBackAfterPartialProgress(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["CARBON-1"] = 5
	adapter.tokenBodies["CARBON-1"] = []byte(`{"drwa_enabled":false}`)
	adapter.holderVersions["CARBON-1|erd1a"] = 4
	adapter.holderBodies["CARBON-1|erd1a"] = []byte(`{"kyc":"approved"}`)
	adapter.ensureHolderIndexed("CARBON-1", "erd1a")

	manifest := &drwaMigrationManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 6,
		PolicyBody:    []byte(`{"drwa_enabled":true}`),
		Holders: []drwaMigrationHolder{
			{Address: "erd1a", Version: 5, Body: []byte(`{"kyc":"revalidated"}`)},
			{Address: "erd1b", Version: 1, Body: []byte(`{"kyc":"approved"}`)},
		},
	}

	envelope, err := buildDRWAMigrationEnvelope(manifest)
	if err != nil {
		t.Fatalf("build migration envelope: %v", err)
	}
	envelope.RecoveryScope = []string{manifest.TokenID}

	callCount := 0
	adapter.putHolderHook = func(tokenID, holder string, version uint64, body []byte) error {
		callCount++
		if callCount == 2 {
			return errDRWATestFailPut
		}
		key := tokenID + "|" + holder
		adapter.holderVersions[key] = version
		adapter.holderBodies[key] = body
		adapter.ensureHolderIndexed(tokenID, holder)
		return nil
	}

	_, err = applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerRecoveryAdmin))
	if err == nil {
		t.Fatalf("expected migration apply failure")
	}
	if !adapter.rolledBack {
		t.Fatalf("expected rollback after partial migration progress")
	}

	if adapter.tokenVersions["CARBON-1"] != 5 || !bytes.Equal(adapter.tokenBodies["CARBON-1"], []byte(`{"drwa_enabled":false}`)) {
		t.Fatalf("expected token policy restored after rollback")
	}
	if adapter.holderVersions["CARBON-1|erd1a"] != 4 || !bytes.Equal(adapter.holderBodies["CARBON-1|erd1a"], []byte(`{"kyc":"approved"}`)) {
		t.Fatalf("expected original holder mirror restored after rollback")
	}
	if _, exists := adapter.holderVersions["CARBON-1|erd1b"]; exists {
		t.Fatalf("expected new holder mirror to be absent after rollback")
	}
}

func TestPersistDRWAMigrationAuthorizedCallers(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()
	// SM-1: All addresses must be 64-char hex (decodes to 32 bytes).
	// Raw 32-byte binary is no longer accepted.
	policyHex := strings.Repeat("a1", 32)   // 64 hex chars → 32 bytes
	assetHex := strings.Repeat("b2", 32)
	identityHex := strings.Repeat("c3", 32)
	attestationHex := strings.Repeat("d4", 32)
	recoveryHex := strings.Repeat("e5", 32)
	manifest := &drwaMigrationManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{"drwa_enabled":true}`),
		AuthorizedCallers: map[string]string{
			drwaSyncCallerPolicyRegistry:   policyHex,
			drwaSyncCallerAssetManager:     assetHex,
			drwaSyncCallerIdentityRegistry: identityHex,
			drwaSyncCallerAttestation:      attestationHex,
			drwaSyncCallerRecoveryAdmin:    recoveryHex,
		},
	}

	err := persistDRWAMigrationAuthorizedCallers(adapter, manifest)
	if err != nil {
		t.Fatalf("persist authorized callers: %v", err)
	}

	policyDecoded, _ := hex.DecodeString(policyHex)
	assetDecoded, _ := hex.DecodeString(assetHex)
	identityDecoded, _ := hex.DecodeString(identityHex)
	attestationDecoded, _ := hex.DecodeString(attestationHex)
	recoveryDecoded, _ := hex.DecodeString(recoveryHex)

	if !bytes.Equal(adapter.authorizedCallers[drwaSyncCallerPolicyRegistry], policyDecoded) {
		t.Fatalf("unexpected policy caller")
	}
	if !bytes.Equal(adapter.authorizedCallers[drwaSyncCallerAssetManager], assetDecoded) {
		t.Fatalf("unexpected asset caller")
	}
	if !bytes.Equal(adapter.authorizedCallers[drwaSyncCallerIdentityRegistry], identityDecoded) {
		t.Fatalf("unexpected identity caller")
	}
	if !bytes.Equal(adapter.authorizedCallers[drwaSyncCallerAttestation], attestationDecoded) {
		t.Fatalf("unexpected attestation caller")
	}
	if !bytes.Equal(adapter.authorizedCallers[drwaSyncCallerRecoveryAdmin], recoveryDecoded) {
		t.Fatalf("unexpected recovery caller")
	}
}

func TestValidateDRWAMigrationManifestRejectsInvalidAuthorizedCallerFormat(t *testing.T) {
	t.Parallel()

	err := validateDRWAMigrationManifest(&drwaMigrationManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{"drwa_enabled":true}`),
		AuthorizedCallers: map[string]string{
			drwaSyncCallerPolicyRegistry: "erd1policy",
			drwaSyncCallerAssetManager:   strings.Repeat("a", 32),
			drwaSyncCallerIdentityRegistry: strings.Repeat("i", 32),
			drwaSyncCallerAttestation:  strings.Repeat("t", 32),
			drwaSyncCallerRecoveryAdmin:  strings.Repeat("r", 32),
		},
	})

	if err == nil {
		t.Fatalf("expected invalid authorized caller format rejection")
	}
}

func TestBuildDRWAAuthorizedCallerKeyUsesDedicatedAuthPrefix(t *testing.T) {
	t.Parallel()

	if got := string(buildDRWAAuthorizedCallerKey(drwaSyncCallerPolicyRegistry)); got != "drwa:auth:"+drwaSyncCallerPolicyRegistry {
		t.Fatalf("unexpected authorized caller key: %s", got)
	}
}

// ---------------------------------------------------------------------------
// bech32 function tests (0% → covered)
// ---------------------------------------------------------------------------

func TestBech32VerifyChecksum_ValidAddress(t *testing.T) {
	t.Parallel()

	// The all-zeros 32-byte address encodes to this known-valid bech32 erd1 address.
	address := "erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu"
	_, data, err := bech32Decode(address)
	if err != nil {
		t.Fatalf("bech32Decode failed for valid address: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty data from bech32Decode")
	}
}

func TestBech32VerifyChecksum_InvalidChecksum(t *testing.T) {
	t.Parallel()

	// Corrupt last character of a valid address.
	address := "erd1qqqqqqqqqqqqqqqpgqhe8t5jewej70zupmh44jurgn29psua5l2jps3ntjj4"
	_, _, err := bech32Decode(address)
	if err == nil {
		t.Fatal("expected checksum rejection for corrupted address")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("expected checksum error, got: %v", err)
	}
}

func TestBech32HrpExpand(t *testing.T) {
	t.Parallel()

	expanded := bech32HrpExpand("erd")
	// "erd" → high bits: [3, 3, 3], separator: [0], low bits: [5, 18, 4]
	expected := []byte{3, 3, 3, 0, 5, 18, 4}
	if !bytes.Equal(expanded, expected) {
		t.Fatalf("unexpected bech32HrpExpand result: got %v, want %v", expanded, expected)
	}
}

func TestBech32Polymod_EmptyInput(t *testing.T) {
	t.Parallel()

	result := bech32Polymod(nil)
	if result != 1 {
		t.Fatalf("expected polymod(nil) == 1, got %d", result)
	}
}

func TestBech32ConvertBits_5to8(t *testing.T) {
	t.Parallel()

	// Convert known 5-bit groups back to 8-bit.
	fiveBit := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	result, err := bech32ConvertBits(fiveBit, 5, 8, false)
	if err != nil {
		t.Fatalf("bech32ConvertBits failed: %v", err)
	}
	for _, b := range result {
		if b != 0 {
			t.Fatalf("expected all zero bytes, got %v", result)
		}
	}
}

func TestBech32ConvertBits_InvalidData(t *testing.T) {
	t.Parallel()

	// Value 32 is out of range for 5-bit groups (max 31).
	_, err := bech32ConvertBits([]byte{32}, 5, 8, false)
	if err == nil {
		t.Fatal("expected error for out-of-range data")
	}
}

func TestDecodeBech32Address_FullPath(t *testing.T) {
	t.Parallel()

	// Use a real MultiversX system SC address (all zeros → erd1qqq...):
	// The system smart contract address is 32 zero bytes, bech32-encoded as:
	address := "erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu"
	decoded, err := decodeBech32Address(address)
	if err != nil {
		t.Fatalf("decodeBech32Address failed: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(decoded))
	}
	// All-zero address
	for i, b := range decoded {
		if b != 0 {
			t.Fatalf("expected byte %d to be 0, got %d", i, b)
		}
	}
}

func TestDecodeBech32Address_WrongHRP(t *testing.T) {
	t.Parallel()

	// A valid bech32 string but with wrong HRP.
	_, err := decodeBech32Address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
	if err == nil || !strings.Contains(err.Error(), "HRP") {
		t.Fatalf("expected HRP rejection, got %v", err)
	}
}

func TestDecodeBech32Address_InvalidLength(t *testing.T) {
	t.Parallel()

	_, err := decodeBech32Address("erd1x")
	if err == nil {
		t.Fatal("expected error for short address")
	}
}
