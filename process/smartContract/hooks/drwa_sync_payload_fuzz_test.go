package hooks

// drwa_sync_payload_fuzz_test.go — G9 Sync Payload Negative Coverage
//
// This file contains two test suites for the binary sync payload decoder:
//
//  1. FuzzDRWASyncEnvelopeDecode — Go fuzzer that feeds arbitrary byte slices
//     into decodeDRWASyncEnvelope and asserts it never panics.
//
//  2. TestDRWASyncPayloadNegative — table-driven negative tests for the
//     structured rejection paths: empty payload, oversized payload, hash
//     mismatch, version replay, and unauthorized caller.
//
// No new dependencies are introduced; all helpers are from drwa_sync_test.go
// and drwa_sync.go.

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzDRWASyncEnvelopeDecode fuzzes the full binary payload decoder.
// The fuzz target calls decodeDRWASyncEnvelope with arbitrary data and verifies
// that the function never panics — it may return an error for any input.
func FuzzDRWASyncEnvelopeDecode(f *testing.F) {
	// Seed: empty payload — must return an error, not panic.
	f.Add([]byte{})

	// Seed: single byte — too short for any valid payload.
	f.Add([]byte{0x00})

	// Seed: 32 bytes of zeros (hash prefix only, no body).
	f.Add(bytes.Repeat([]byte{0x00}, 32))

	// Seed: valid minimal binary payload (policy_registry, one token-policy op).
	validOps := []drwaSyncOperation{{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "T-1",
		Version:       1,
		Body:          []byte(`{}`),
	}}
	canonical, err := serializeDRWASyncEnvelopePayload(drwaSyncCallerPolicyRegistry, validOps)
	if err == nil {
		hash, hashErr := computeDRWASyncHash(drwaSyncCallerPolicyRegistry, validOps)
		if hashErr == nil {
			f.Add(append(hash, canonical...))
		}
	}

	// Seed: valid hash prefix followed by corrupted body.
	if err == nil {
		hash, hashErr := computeDRWASyncHash(drwaSyncCallerPolicyRegistry, validOps)
		if hashErr == nil {
			corrupted := append(hash, []byte{0xFF, 0xFE, 0xFD}...)
			f.Add(corrupted)
		}
	}

	// Seed: valid binary payload for auth_admin authorized_caller_update.
	validAuthOps := []drwaSyncOperation{{
		OperationType: drwaSyncOpAuthorizedCallerUpdate,
		TokenID:       drwaSyncCallerPolicyRegistry,
		Version:       1,
		Body:          []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
	}}
	authCanonical, authErr := serializeDRWASyncEnvelopePayload(drwaSyncCallerAuthAdmin, validAuthOps)
	if authErr == nil {
		authHash, hashErr := computeDRWASyncHash(drwaSyncCallerAuthAdmin, validAuthOps)
		if hashErr == nil {
			f.Add(append(authHash, authCanonical...))
		}
	}

	// Seed: payload larger than drwaSyncMaxPayloadBytes — one byte over limit.
	oversized := make([]byte, drwaSyncMaxPayloadBytes+1)
	f.Add(oversized)

	// Seed: JSON-format envelope (starts with '{').
	f.Add([]byte(`{"caller_domain":"policy_registry","operations":[]}`))

	// Seed: JSON envelope with truncated JSON.
	f.Add([]byte(`{"caller_domain":"asset_manager","operations":[`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic; error is acceptable for any input.
		_, _ = decodeDRWASyncEnvelope(data)
	})
}

// TestDRWASyncPayloadNegative is a table-driven test for structured rejection paths.
func TestDRWASyncPayloadNegative(t *testing.T) {
	// Build a valid envelope/binary payload once for use in several sub-cases.
	validOps := []drwaSyncOperation{{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "BOND-1",
		Version:       1,
		Body:          []byte(`{"drwa_enabled":true}`),
	}}
	validCanonical, err := serializeDRWASyncEnvelopePayload(drwaSyncCallerPolicyRegistry, validOps)
	if err != nil {
		t.Fatalf("setup: serialize: %v", err)
	}
	validHash, err := computeDRWASyncHash(drwaSyncCallerPolicyRegistry, validOps)
	if err != nil {
		t.Fatalf("setup: hash: %v", err)
	}
	validBinaryPayload := append(validHash, validCanonical...)

	type tableCase struct {
		name       string
		payload    func() []byte
		wantErrSub string // substring that must appear in the error message
		wantNilErr bool   // if true, expect no error (smoke-check a valid payload)
	}

	cases := []tableCase{
		{
			name:       "empty_payload",
			payload:    func() []byte { return []byte{} },
			wantErrSub: "nil DRWA sync payload",
		},
		{
			name:       "payload_too_large",
			payload:    func() []byte { return make([]byte, drwaSyncMaxPayloadBytes+1) },
			wantErrSub: drwaSyncRejectPayloadTooLarge,
		},
		{
			name: "hash_mismatch_corrupted_body",
			payload: func() []byte {
				// Keep valid hash but corrupt the canonical body after it.
				corrupted := make([]byte, len(validBinaryPayload))
				copy(corrupted, validBinaryPayload)
				if len(corrupted) > drwaBinaryHashSize+2 {
					corrupted[drwaBinaryHashSize+1] ^= 0xFF
				}
				return corrupted
			},
			// A corrupted body will fail during binary parsing, not hash-check
			// (the hash check happens at applyDRWASyncEnvelope, not decode).
			// decodeDRWASyncEnvelope may return a parse error; we just check
			// that it returns a non-nil error.
			wantErrSub: "",
		},
		{
			name:       "valid_binary_payload_decoded_ok",
			payload:    func() []byte { return validBinaryPayload },
			wantNilErr: true,
		},
		{
			name: "version_replay_stale_via_apply",
			// decodeDRWASyncEnvelope does not check versions; stale-version
			// rejection occurs in applyDRWASyncEnvelope.  This sub-case
			// verifies the rejection string from the apply layer.
			payload: nil, // handled separately below
		},
		{
			name: "unauthorized_caller_via_apply",
			// Same: unauthorized-caller rejection occurs in applyDRWASyncEnvelope.
			payload: nil, // handled separately below
		},
	}

	for _, tc := range cases {
		if tc.payload == nil {
			continue // apply-layer cases handled below
		}

		t.Run(tc.name, func(t *testing.T) {
			_, decodeErr := decodeDRWASyncEnvelope(tc.payload())
			if tc.wantNilErr {
				if decodeErr != nil {
					t.Fatalf("expected no error, got %v", decodeErr)
				}
				return
			}
			if decodeErr == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErrSub)
			}
			if tc.wantErrSub != "" && !containsString(decodeErr.Error(), tc.wantErrSub) {
				t.Fatalf("expected error %q, got %q", tc.wantErrSub, decodeErr.Error())
			}
		})
	}

	// --- apply-layer rejection cases ---

	t.Run("version_replay_stale", func(t *testing.T) {
		adapter := newMockDRWASyncStateAdapter()
		adapter.tokenVersions["BOND-1"] = 7 // current version in mirror

		envelope := &drwaSyncEnvelope{
			CallerDomain: drwaSyncCallerPolicyRegistry,
			Operations: []drwaSyncOperation{{
				OperationType: drwaSyncOpTokenPolicy,
				TokenID:       "BOND-1",
				Version:       6, // less than current — stale
				Body:          []byte(`{}`),
			}},
		}
		hash, hashErr := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
		if hashErr != nil {
			t.Fatalf("hash: %v", hashErr)
		}
		envelope.PayloadHash = hash

		_, applyErr := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
		if applyErr == nil || applyErr.Error() != drwaSyncRejectReplayStale {
			t.Fatalf("expected %s, got %v", drwaSyncRejectReplayStale, applyErr)
		}
	})

	t.Run("unauthorized_caller", func(t *testing.T) {
		adapter := newMockDRWASyncStateAdapter()
		envelope := &drwaSyncEnvelope{
			CallerDomain: "unknown_domain",
			Operations: []drwaSyncOperation{{
				OperationType: drwaSyncOpTokenPolicy,
				TokenID:       "BOND-1",
				Version:       1,
				Body:          []byte(`{}`),
			}},
		}

		// computeDRWASyncHash requires a known caller domain tag;
		// build the envelope hash manually using a known domain so we can
		// proceed to the authorization check.
		hashOps := []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "BOND-1",
			Version:       1,
			Body:          []byte(`{}`),
		}}
		hash, hashErr := computeDRWASyncHash(drwaSyncCallerPolicyRegistry, hashOps)
		if hashErr != nil {
			t.Fatalf("hash: %v", hashErr)
		}
		envelope.PayloadHash = hash

		_, applyErr := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
		if applyErr == nil || applyErr.Error() != drwaSyncRejectUnauthorizedCaller {
			t.Fatalf("expected %s, got %v", drwaSyncRejectUnauthorizedCaller, applyErr)
		}
	})

	t.Run("version_not_monotonically_increasing_skip", func(t *testing.T) {
		adapter := newMockDRWASyncStateAdapter()
		adapter.tokenVersions["BOND-1"] = 1 // current version

		envelope := &drwaSyncEnvelope{
			CallerDomain: drwaSyncCallerPolicyRegistry,
			Operations: []drwaSyncOperation{{
				OperationType: drwaSyncOpTokenPolicy,
				TokenID:       "BOND-1",
				Version:       3, // skips 2 — not exactly currentVersion+1
				Body:          []byte(`{}`),
			}},
		}
		hash, hashErr := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
		if hashErr != nil {
			t.Fatalf("hash: %v", hashErr)
		}
		envelope.PayloadHash = hash

		_, applyErr := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
		if applyErr == nil || applyErr.Error() != drwaSyncRejectVersionGap {
			t.Fatalf("expected %s for version skip, got %v", drwaSyncRejectVersionGap, applyErr)
		}
	})
}

// buildDRWABinaryPayloadForTokenPolicy is a test-local helper that constructs
// the [hash || canonical] binary hook payload for a single token-policy operation.
// It mirrors the production build_sync_hook_payload path in Rust.
func buildDRWABinaryPayloadForTokenPolicy(t *testing.T, tokenID string, version uint64, body []byte) []byte {
	t.Helper()

	ops := []drwaSyncOperation{{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       tokenID,
		Version:       version,
		Body:          body,
	}}
	canonical, err := serializeDRWASyncEnvelopePayload(drwaSyncCallerPolicyRegistry, ops)
	if err != nil {
		t.Fatalf("buildDRWABinaryPayloadForTokenPolicy serialize: %v", err)
	}
	hash, err := computeDRWASyncHash(drwaSyncCallerPolicyRegistry, ops)
	if err != nil {
		t.Fatalf("buildDRWABinaryPayloadForTokenPolicy hash: %v", err)
	}
	return append(hash, canonical...)
}

// TestDRWASyncPayloadBinaryRoundTrip proves that a binary payload constructed by
// buildDRWABinaryPayloadForTokenPolicy round-trips through decodeDRWASyncEnvelope
// without loss and that the resulting envelope can be applied to a fresh adapter.
func TestDRWASyncPayloadBinaryRoundTrip(t *testing.T) {
	tokenID := "ROUNDTRIP-1"
	body := []byte(`{"drwa_enabled":true,"global_pause":false}`)
	payload := buildDRWABinaryPayloadForTokenPolicy(t, tokenID, 1, body)

	envelope, err := decodeDRWASyncEnvelope(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if envelope.CallerDomain != drwaSyncCallerPolicyRegistry {
		t.Fatalf("wrong caller domain: %q", envelope.CallerDomain)
	}
	if len(envelope.Operations) != 1 {
		t.Fatalf("expected 1 operation, got %d", len(envelope.Operations))
	}
	op := envelope.Operations[0]
	if op.TokenID != tokenID {
		t.Fatalf("wrong token ID: %q", op.TokenID)
	}
	if op.Version != 1 {
		t.Fatalf("wrong version: %d", op.Version)
	}
	if !bytes.Equal(op.Body, body) {
		t.Fatalf("body mismatch: %q", op.Body)
	}

	adapter := newMockDRWASyncStateAdapter()
	result, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if result.AppliedOperations != 1 {
		t.Fatalf("expected 1 applied operation, got %d", result.AppliedOperations)
	}
	if adapter.tokenVersions[tokenID] != 1 {
		t.Fatalf("expected mirror version 1, got %d", adapter.tokenVersions[tokenID])
	}
}

// TestDRWASyncPayloadVersionFieldEncoding proves that the version field is encoded
// as big-endian uint64 in the binary payload (per the sync specification).
func TestDRWASyncPayloadVersionFieldEncoding(t *testing.T) {
	const wantVersion = uint64(0x0102030405060708)

	payload, err := serializeDRWASyncEnvelopePayload(drwaSyncCallerPolicyRegistry, []drwaSyncOperation{{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "V-1",
		Version:       wantVersion,
		Body:          []byte{},
	}})
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	// Layout before the version field:
	// [2 schema version] [1 caller tag] [1 op tag] [4 token-id length] [token-id bytes] [4 holder length] [32 holder zeros]
	tokenIDLen := 3 // "V-1"
	holderLen := 32 // zero placeholder for token_policy
	versionOffset := 2 + 1 + 1 + 4 + tokenIDLen + 4 + holderLen
	if len(payload) < versionOffset+8 {
		t.Fatalf("payload too short: %d bytes", len(payload))
	}

	gotVersion := binary.BigEndian.Uint64(payload[versionOffset : versionOffset+8])
	if gotVersion != wantVersion {
		t.Fatalf("expected version 0x%016X, got 0x%016X", wantVersion, gotVersion)
	}
}

func TestDRWASyncPayloadV2RecoveryGovernanceDecode(t *testing.T) {
	proposalID := bytes.Repeat([]byte{0xAB}, 32)
	ops := []drwaSyncOperation{{
		OperationType: drwaSyncOpGovernanceApprove,
		Version:       1,
		Body:          proposalID,
	}}
	hash, err := computeDRWASyncHash(drwaSyncCallerRecoveryAdmin, ops)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	canonical := make([]byte, 0)
	canonical = binary.BigEndian.AppendUint16(canonical, drwaSyncEnvelopeSchemaVersionWithRecovery)
	canonical = append(canonical, 4) // recovery_admin
	canonical = appendDRWATestLenPrefixed(canonical, bytes.Repeat([]byte{0xCD}, 32))
	canonical = binary.BigEndian.AppendUint16(canonical, 1)
	canonical = appendDRWATestLenPrefixed(canonical, []byte("CARBON-ab12cd"))
	canonical = binary.BigEndian.AppendUint16(canonical, 1)
	canonical = append(canonical, 7) // governance approve
	canonical = appendDRWATestLenPrefixed(canonical, nil)
	canonical = appendDRWATestLenPrefixed(canonical, nil)
	canonical = binary.BigEndian.AppendUint64(canonical, 1)
	canonical = appendDRWATestLenPrefixed(canonical, proposalID)

	envelope, err := decodeDRWASyncEnvelope(append(hash, canonical...))
	if err != nil {
		t.Fatalf("decode v2 recovery governance payload: %v", err)
	}
	if envelope.SchemaVersion != drwaSyncEnvelopeSchemaVersionWithRecovery {
		t.Fatalf("expected schema v2, got %d", envelope.SchemaVersion)
	}
	if envelope.CallerDomain != drwaSyncCallerRecoveryAdmin {
		t.Fatalf("expected recovery_admin caller, got %q", envelope.CallerDomain)
	}
	if len(envelope.PreRecoveryStateHash) != 32 {
		t.Fatalf("expected 32-byte pre-recovery hash, got %d", len(envelope.PreRecoveryStateHash))
	}
	if len(envelope.RecoveryScope) != 1 || envelope.RecoveryScope[0] != "CARBON-ab12cd" {
		t.Fatalf("unexpected recovery scope: %#v", envelope.RecoveryScope)
	}
	if len(envelope.Operations) != 1 || envelope.Operations[0].OperationType != drwaSyncOpGovernanceApprove {
		t.Fatalf("unexpected operations: %#v", envelope.Operations)
	}
	if !bytes.Equal(envelope.Operations[0].Body, proposalID) {
		t.Fatalf("proposal body mismatch")
	}
}

func TestDRWASyncPayloadRejectsUnsupportedSchemaVersion(t *testing.T) {
	payload, err := serializeDRWASyncEnvelopePayload(drwaSyncCallerPolicyRegistry, []drwaSyncOperation{{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "V-1",
		Version:       1,
		Body:          []byte{},
	}})
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	hash, err := computeDRWASyncHash(drwaSyncCallerPolicyRegistry, []drwaSyncOperation{{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "V-1",
		Version:       1,
		Body:          []byte{},
	}})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	payload[1] = 99
	_, err = decodeDRWASyncEnvelope(append(hash, payload...))
	if err == nil || !containsString(err.Error(), "unsupported DRWA binary sync schema version: 99") {
		t.Fatalf("expected unsupported schema version rejection, got %v", err)
	}
}

func appendDRWATestLenPrefixed(dest []byte, value []byte) []byte {
	dest = binary.BigEndian.AppendUint32(dest, uint32(len(value)))
	return append(dest, value...)
}

// containsString reports whether s contains substr.  Avoids importing strings.
func containsString(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
