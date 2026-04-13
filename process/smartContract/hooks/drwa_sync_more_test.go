package hooks

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyDRWASyncEnvelopeEdgeCases(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()

	_, err := applyDRWASyncEnvelope(nil, &drwaSyncEnvelope{}, 1, []byte("caller"))
	require.Error(t, err)

	_, err = applyDRWASyncEnvelope(adapter, nil, 1, []byte("caller"))
	require.Error(t, err)

	// noop envelope with nil PayloadHash must be rejected (hash required).
	_, err = applyDRWASyncEnvelope(adapter, &drwaSyncEnvelope{}, 1, []byte("caller"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "DRWA_NOOP_ENVELOPE_HASH_REQUIRED")

	tooMany := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		Operations: []drwaSyncOperation{
			{OperationType: drwaSyncOpTokenPolicy, TokenID: "A", Version: 1, Body: []byte(`{}`)},
			{OperationType: drwaSyncOpTokenPolicy, TokenID: "B", Version: 1, Body: []byte(`{}`)},
		},
	}
	_, err = applyDRWASyncEnvelope(adapter, tooMany, 1, []byte("policy_registry"))
	require.Error(t, err)

	hashMismatch := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		Operations: []drwaSyncOperation{
			{OperationType: drwaSyncOpTokenPolicy, TokenID: "CARBON-1", Version: 1, Body: []byte(`{}`)},
		},
		PayloadHash: bytes.Repeat([]byte{1}, drwaBinaryHashSize),
	}
	_, err = applyDRWASyncEnvelope(adapter, hashMismatch, 4, []byte("policy_registry"))
	require.Error(t, err)
}

func TestApplyDRWASyncOperationUnknownType(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	err := applyDRWASyncOperation(adapter, drwaSyncOperation{
		OperationType: "unknown",
		TokenID:       "CARBON-1",
		Version:       1,
	})
	require.Error(t, err)
}

func TestBinaryTagDecodersRejectUnknownTags(t *testing.T) {
	_, err := drwaCallerDomainFromTag(9)
	require.Error(t, err)

	_, err = drwaOperationTypeFromTag(9)
	require.Error(t, err)
}

func TestBinaryReadersRejectShortPayloads(t *testing.T) {
	_, err := readDRWABinaryLenPrefixed(bytes.NewReader([]byte{0, 0, 0}))
	require.Error(t, err)

	_, err = readDRWABinaryLenPrefixed(bytes.NewReader([]byte{0, 0, 0, 5, 1}))
	require.Error(t, err)

	_, err = readDRWABinaryOperation(bytes.NewReader([]byte{0, 0, 0}))
	require.Error(t, err)
}

func TestIsDRWASyncCallerAuthorizedRejectsInvalidInputs(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()

	require.False(t, isDRWASyncCallerAuthorized(adapter, drwaSyncCallerPolicyRegistry, []drwaSyncOperation{
		{OperationType: drwaSyncOpTokenPolicy},
	}, nil))

	require.False(t, isDRWASyncCallerAuthorized(adapter, "unknown", []drwaSyncOperation{
		{OperationType: drwaSyncOpTokenPolicy},
	}, []byte("policy_registry")))

	require.False(t, isDRWASyncCallerAuthorized(adapter, drwaSyncCallerIdentityRegistry, []drwaSyncOperation{
		{OperationType: drwaSyncOpTokenPolicy},
	}, []byte("identity_registry")))

	require.False(t, isDRWASyncCallerAuthorized(adapter, drwaSyncCallerAttestation, []drwaSyncOperation{
		{OperationType: drwaSyncOpHolderMirror},
	}, []byte("attestation")))
}

func TestSerializeDRWASyncEnvelopePayloadRejectsUnknownDomainAndOperation(t *testing.T) {
	_, err := serializeDRWASyncEnvelopePayload("unknown", nil)
	require.Error(t, err)

	_, err = serializeDRWASyncEnvelopePayload(drwaSyncCallerPolicyRegistry, []drwaSyncOperation{{
		OperationType: "unknown",
	}})
	require.Error(t, err)
}
