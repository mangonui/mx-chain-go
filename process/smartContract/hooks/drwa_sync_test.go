package hooks

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/process"
	teststate "github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type mockDRWASyncStateAdapterSnapshot struct {
	tokenVersions             map[string]uint64
	assetVersions             map[string]uint64
	holderVersions            map[string]uint64
	holderProfileVersions     map[string]uint64
	holderAuditorAuthVersions map[string]uint64
	activeTokens              map[string]bool
	tokenBodies               map[string][]byte
	assetBodies               map[string][]byte
	holderBodies              map[string][]byte
	holderProfileBodies       map[string][]byte
	holderAuditorAuthBodies   map[string][]byte
	holderIndex               map[string][]string
}

type mockDRWASyncStateAdapter struct {
	tokenVersions             map[string]uint64
	assetVersions             map[string]uint64
	holderVersions            map[string]uint64
	holderProfileVersions     map[string]uint64
	holderAuditorAuthVersions map[string]uint64
	activeTokens              map[string]bool
	tokenBodies               map[string][]byte
	assetBodies               map[string][]byte
	holderBodies              map[string][]byte
	holderProfileBodies       map[string][]byte
	holderAuditorAuthBodies   map[string][]byte
	authorizedCallers         map[string][]byte
	authorizedCallerVersions  map[string]uint64
	recoveryEvidence          map[string][]byte
	rolloutEvidence           map[string][]byte
	rolloutVerification       map[string][]byte
	holderIndex               map[string][]string
	savedSnapshots            []mockDRWASyncStateAdapterSnapshot
	failPut                   bool
	rolledBack                bool
	putHolderHook             func(tokenID, holder string, version uint64, body []byte) error
}

func newMockDRWASyncStateAdapter() *mockDRWASyncStateAdapter {
	return &mockDRWASyncStateAdapter{
		tokenVersions:             make(map[string]uint64),
		assetVersions:             make(map[string]uint64),
		holderVersions:            make(map[string]uint64),
		holderProfileVersions:     make(map[string]uint64),
		holderAuditorAuthVersions: make(map[string]uint64),
		activeTokens:              make(map[string]bool),
		tokenBodies:               make(map[string][]byte),
		assetBodies:               make(map[string][]byte),
		holderBodies:              make(map[string][]byte),
		holderProfileBodies:       make(map[string][]byte),
		holderAuditorAuthBodies:   make(map[string][]byte),
		authorizedCallers: map[string][]byte{
			drwaSyncCallerPolicyRegistry:   testDRWACallerAddress(drwaSyncCallerPolicyRegistry),
			drwaSyncCallerAssetManager:     testDRWACallerAddress(drwaSyncCallerAssetManager),
			drwaSyncCallerIdentityRegistry: testDRWACallerAddress(drwaSyncCallerIdentityRegistry),
			drwaSyncCallerAttestation:      testDRWACallerAddress(drwaSyncCallerAttestation),
			drwaSyncCallerRecoveryAdmin:    testDRWACallerAddress(drwaSyncCallerRecoveryAdmin),
			drwaSyncCallerAuthAdmin:        testDRWACallerAddress(drwaSyncCallerAuthAdmin),
		},
		authorizedCallerVersions: make(map[string]uint64),
		recoveryEvidence:         make(map[string][]byte),
		rolloutEvidence:          make(map[string][]byte),
		rolloutVerification:      make(map[string][]byte),
		holderIndex:              make(map[string][]string),
	}
}

func testDRWACallerAddress(domain string) []byte {
	addr := make([]byte, drwaAuthorizedCallerAddressLen)
	copy(addr, []byte("test:"+domain))
	return addr
}

func (m *mockDRWASyncStateAdapter) GetTokenPolicyVersion(tokenID string) (uint64, error) {
	return m.tokenVersions[tokenID], nil
}

func (m *mockDRWASyncStateAdapter) GetAssetRecordVersion(tokenID string) (uint64, error) {
	return m.assetVersions[tokenID], nil
}

func (m *mockDRWASyncStateAdapter) GetHolderMirrorVersion(tokenID, holder string) (uint64, error) {
	return m.holderVersions[tokenID+"|"+holder], nil
}

func (m *mockDRWASyncStateAdapter) GetHolderProfileVersion(holder string) (uint64, error) {
	return m.holderProfileVersions[holder], nil
}

func (m *mockDRWASyncStateAdapter) GetHolderAuditorAuthorizationVersion(tokenID, holder string) (uint64, error) {
	return m.holderAuditorAuthVersions[tokenID+"|"+holder], nil
}

func (m *mockDRWASyncStateAdapter) GetAuthorizedCallerAddress(domain string) ([]byte, error) {
	return append([]byte(nil), m.authorizedCallers[domain]...), nil
}

func (m *mockDRWASyncStateAdapter) PutAuthorizedCallerAddress(domain string, address []byte) error {
	m.authorizedCallers[domain] = append([]byte(nil), address...)
	return nil
}

func (m *mockDRWASyncStateAdapter) GetAuthorizedCallerAddressVersioned(domain string) ([]byte, uint64, error) {
	return append([]byte(nil), m.authorizedCallers[domain]...), m.authorizedCallerVersions[domain], nil
}

func (m *mockDRWASyncStateAdapter) SetAuthorizedCallerAddressVersioned(domain string, address []byte, version uint64) error {
	m.authorizedCallers[domain] = append([]byte(nil), address...)
	m.authorizedCallerVersions[domain] = version
	return nil
}

func (m *mockDRWASyncStateAdapter) SetDRWAActive(tokenID string) error {
	if m.failPut {
		return errDRWATestFailPut
	}
	m.activeTokens[tokenID] = true
	return nil
}

func (m *mockDRWASyncStateAdapter) GetTokenPolicyStored(tokenID string) (*drwaSyncStoredValue, error) {
	version, ok := m.tokenVersions[tokenID]
	if !ok {
		return nil, nil
	}
	return &drwaSyncStoredValue{
		Version: version,
		Body:    m.tokenBodies[tokenID],
	}, nil
}

func (m *mockDRWASyncStateAdapter) GetHolderMirrorStored(tokenID, holder string) (*drwaSyncStoredValue, error) {
	key := tokenID + "|" + holder
	version, ok := m.holderVersions[key]
	if !ok {
		return nil, nil
	}
	return &drwaSyncStoredValue{
		Version: version,
		Body:    m.holderBodies[key],
	}, nil
}

func (m *mockDRWASyncStateAdapter) PutTokenPolicyBody(tokenID string, version uint64, body []byte) error {
	if m.failPut {
		return errDRWATestFailPut
	}
	m.tokenVersions[tokenID] = version
	m.tokenBodies[tokenID] = body
	return nil
}

func (m *mockDRWASyncStateAdapter) PutAssetRecordBody(tokenID string, version uint64, body []byte) error {
	if m.failPut {
		return errDRWATestFailPut
	}
	m.assetVersions[tokenID] = version
	m.assetBodies[tokenID] = body
	return nil
}

func (m *mockDRWASyncStateAdapter) PutHolderMirrorBody(tokenID, holder string, version uint64, body []byte) error {
	if m.putHolderHook != nil {
		return m.putHolderHook(tokenID, holder, version, body)
	}
	if m.failPut {
		return errDRWATestFailPut
	}
	key := tokenID + "|" + holder
	m.holderVersions[key] = version
	m.holderBodies[key] = body
	m.ensureHolderIndexed(tokenID, holder)
	return nil
}

func (m *mockDRWASyncStateAdapter) PutHolderProfileBody(holder string, version uint64, body []byte) error {
	if m.failPut {
		return errDRWATestFailPut
	}
	m.holderProfileVersions[holder] = version
	m.holderProfileBodies[holder] = body
	return nil
}

func (m *mockDRWASyncStateAdapter) PutHolderAuditorAuthorizationBody(tokenID, holder string, version uint64, body []byte) error {
	if m.failPut {
		return errDRWATestFailPut
	}
	key := tokenID + "|" + holder
	m.holderAuditorAuthVersions[key] = version
	m.holderAuditorAuthBodies[key] = body
	return nil
}

func (m *mockDRWASyncStateAdapter) DeleteHolderMirror(tokenID, holder string, version uint64) error {
	if m.failPut {
		return errDRWATestFailPut
	}
	key := tokenID + "|" + holder
	delete(m.holderVersions, key)
	delete(m.holderBodies, key)
	m.removeHolderIndexed(tokenID, holder)
	return nil
}

func (m *mockDRWASyncStateAdapter) PersistRecoveryEvidence(tokenID string, payload []byte) error {
	if m.failPut {
		return errDRWATestFailPut
	}
	m.recoveryEvidence[tokenID] = append([]byte(nil), payload...)
	return nil
}

func (m *mockDRWASyncStateAdapter) PersistRolloutEvidence(tokenID string, payload []byte) error {
	if m.failPut {
		return errDRWATestFailPut
	}
	m.rolloutEvidence[tokenID] = append([]byte(nil), payload...)
	return nil
}

func (m *mockDRWASyncStateAdapter) PersistRolloutVerification(tokenID string, payload []byte) error {
	if m.failPut {
		return errDRWATestFailPut
	}
	m.rolloutVerification[tokenID] = append([]byte(nil), payload...)
	return nil
}

func (m *mockDRWASyncStateAdapter) ListHolderMirrorAddresses(tokenID string) ([]string, error) {
	addresses := append([]string(nil), m.holderIndex[tokenID]...)
	return addresses, nil
}

func (m *mockDRWASyncStateAdapter) Snapshot() int {
	snap := mockDRWASyncStateAdapterSnapshot{
		tokenVersions:             copyMapUint64(m.tokenVersions),
		assetVersions:             copyMapUint64(m.assetVersions),
		holderVersions:            copyMapUint64(m.holderVersions),
		holderProfileVersions:     copyMapUint64(m.holderProfileVersions),
		holderAuditorAuthVersions: copyMapUint64(m.holderAuditorAuthVersions),
		activeTokens:              copyMapBool(m.activeTokens),
		tokenBodies:               copyMapBytes(m.tokenBodies),
		assetBodies:               copyMapBytes(m.assetBodies),
		holderBodies:              copyMapBytes(m.holderBodies),
		holderProfileBodies:       copyMapBytes(m.holderProfileBodies),
		holderAuditorAuthBodies:   copyMapBytes(m.holderAuditorAuthBodies),
		holderIndex:               copyMapStringSlice(m.holderIndex),
	}
	m.savedSnapshots = append(m.savedSnapshots, snap)
	return len(m.savedSnapshots) - 1
}

func (m *mockDRWASyncStateAdapter) Rollback(snapshot int) error {
	if snapshot >= 0 && snapshot < len(m.savedSnapshots) {
		snap := m.savedSnapshots[snapshot]
		m.tokenVersions = snap.tokenVersions
		m.assetVersions = snap.assetVersions
		m.holderVersions = snap.holderVersions
		m.holderProfileVersions = snap.holderProfileVersions
		m.holderAuditorAuthVersions = snap.holderAuditorAuthVersions
		m.activeTokens = snap.activeTokens
		m.tokenBodies = snap.tokenBodies
		m.assetBodies = snap.assetBodies
		m.holderBodies = snap.holderBodies
		m.holderProfileBodies = snap.holderProfileBodies
		m.holderAuditorAuthBodies = snap.holderAuditorAuthBodies
		m.holderIndex = snap.holderIndex
		m.savedSnapshots = m.savedSnapshots[:snapshot]
	}
	m.rolledBack = true
	return nil
}

func copyMapUint64(src map[string]uint64) map[string]uint64 {
	dst := make(map[string]uint64, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func copyMapBool(src map[string]bool) map[string]bool {
	dst := make(map[string]bool, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func copyMapBytes(src map[string][]byte) map[string][]byte {
	dst := make(map[string][]byte, len(src))
	for k, v := range src {
		dst[k] = append([]byte(nil), v...)
	}
	return dst
}

func copyMapStringSlice(src map[string][]string) map[string][]string {
	dst := make(map[string][]string, len(src))
	for k, v := range src {
		dst[k] = append([]string(nil), v...)
	}
	return dst
}

func (m *mockDRWASyncStateAdapter) IsInterfaceNil() bool {
	return m == nil
}

func (m *mockDRWASyncStateAdapter) ensureHolderIndexed(tokenID, holder string) {
	addresses := m.holderIndex[tokenID]
	for _, existing := range addresses {
		if existing == holder {
			return
		}
	}
	m.holderIndex[tokenID] = append(addresses, holder)
}

func (m *mockDRWASyncStateAdapter) removeHolderIndexed(tokenID, holder string) {
	addresses := m.holderIndex[tokenID]
	filtered := addresses[:0]
	for _, existing := range addresses {
		if existing != holder {
			filtered = append(filtered, existing)
		}
	}
	m.holderIndex[tokenID] = append([]string(nil), filtered...)
}

const drwaTestMsgOneApplied = "expected 1 applied operation, got %d"

var errDRWATestFailPut = &drwaTestError{"fail put"}

type drwaTestError struct {
	msg string
}

func (e *drwaTestError) Error() string { return e.msg }

func TestDecodeDRWASyncEnvelopeRejectsOversizedPayload(t *testing.T) {
	payload := make([]byte, drwaSyncMaxPayloadBytes+1)

	_, err := decodeDRWASyncEnvelope(payload)
	if err == nil || err.Error() != drwaSyncRejectPayloadTooLarge {
		t.Fatalf("expected oversized payload rejection, got %v", err)
	}
}

func TestDecodeDRWASyncEnvelopeRejectsMalformedPayload(t *testing.T) {
	payload := []byte(`{"caller_domain":"asset_manager","operations":[`)

	_, err := decodeDRWASyncEnvelope(payload)
	if err == nil {
		t.Fatalf("expected malformed payload rejection")
	}
}

func TestApplyDRWASyncEnvelopeRejectsUnauthorizedCaller(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	envelope := &drwaSyncEnvelope{
		CallerDomain: "random_caller",
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "CARBON-1",
			Version:       1,
			Body:          []byte(`{}`),
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, []byte("random_caller"))
	if err == nil || err.Error() != drwaSyncRejectUnauthorizedCaller {
		t.Fatalf("expected unauthorized caller rejection, got %v", err)
	}
}

func TestApplyDRWASyncOperationMarksTokenActiveOnFirstPolicySync(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()
	err := applyDRWASyncOperation(adapter, drwaSyncOperation{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "BOND-1",
		Version:       1,
		Body:          []byte(`{"drwa_enabled":true}`),
	})
	require.NoError(t, err)
	require.True(t, adapter.activeTokens["BOND-1"])
	require.Equal(t, uint64(1), adapter.tokenVersions["BOND-1"])
}

func TestSerializeDRWASyncEnvelopePayloadTokenPolicyUsesZeroAddressHolder(t *testing.T) {
	operations := []drwaSyncOperation{{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "CARBON-1",
		Version:       7,
		Body:          []byte{0xAA, 0xBB},
	}}

	payload, err := serializeDRWASyncEnvelopePayload(drwaSyncCallerPolicyRegistry, operations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := bytes.NewBuffer(nil)
	schemaVersionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(schemaVersionBytes, drwaSyncEnvelopeSchemaVersion)
	expected.Write(schemaVersionBytes)
	expected.WriteByte(0)
	expected.WriteByte(0)
	writeLengthPrefixedTest(expected, []byte("CARBON-1"))
	writeLengthPrefixedTest(expected, make([]byte, 32))
	versionBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(versionBytes, 7)
	expected.Write(versionBytes)
	writeLengthPrefixedTest(expected, []byte{0xAA, 0xBB})

	if !bytes.Equal(expected.Bytes(), payload) {
		t.Fatalf("unexpected payload bytes: %x", payload)
	}
}

func TestSerializeDRWASyncEnvelopePayloadHolderMirrorUsesHolderBytes(t *testing.T) {
	operations := []drwaSyncOperation{{
		OperationType: drwaSyncOpHolderMirror,
		TokenID:       "CARBON-1",
		Holder:        "holder-address",
		Version:       2,
		Body:          []byte{0x01},
	}}

	payload, err := serializeDRWASyncEnvelopePayload(drwaSyncCallerAssetManager, operations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// callerDomain=AssetManager → tag 1, opType=HolderMirror → tag 2
	expected := bytes.NewBuffer(nil)
	schemaVersionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(schemaVersionBytes, drwaSyncEnvelopeSchemaVersion)
	expected.Write(schemaVersionBytes)
	expected.WriteByte(1) // callerDomain: AssetManager
	expected.WriteByte(2) // opType: HolderMirror
	writeLengthPrefixedTest(expected, []byte("CARBON-1"))
	writeLengthPrefixedTest(expected, []byte("holder-address"))
	versionBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(versionBytes, 2)
	expected.Write(versionBytes)
	writeLengthPrefixedTest(expected, []byte{0x01})

	if !bytes.Equal(expected.Bytes(), payload) {
		t.Fatalf("unexpected payload bytes: %x", payload)
	}
}

func TestSerializeDRWASyncEnvelopePayloadHolderProfileUsesIdentityRegistryTags(t *testing.T) {
	operations := []drwaSyncOperation{{
		OperationType: drwaSyncOpHolderProfile,
		TokenID:       "",
		Holder:        "holder-address",
		Version:       2,
		Body:          []byte{0x02},
	}}

	payload, err := serializeDRWASyncEnvelopePayload(drwaSyncCallerIdentityRegistry, operations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// callerDomain=IdentityRegistry → tag 2, opType=HolderProfile → tag 3
	expected := bytes.NewBuffer(nil)
	schemaVersionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(schemaVersionBytes, drwaSyncEnvelopeSchemaVersion)
	expected.Write(schemaVersionBytes)
	expected.WriteByte(2) // callerDomain: IdentityRegistry
	expected.WriteByte(3) // opType: HolderProfile
	writeLengthPrefixedTest(expected, []byte(""))
	writeLengthPrefixedTest(expected, []byte("holder-address"))
	versionBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(versionBytes, 2)
	expected.Write(versionBytes)
	writeLengthPrefixedTest(expected, []byte{0x02})

	if !bytes.Equal(expected.Bytes(), payload) {
		t.Fatalf("unexpected payload bytes: %x", payload)
	}
}

func TestSerializeDRWASyncEnvelopePayloadHolderAuditorAuthorizationUsesAttestationTags(t *testing.T) {
	operations := []drwaSyncOperation{{
		OperationType: drwaSyncOpHolderAuditorAuth,
		TokenID:       "CARBON-1",
		Holder:        "holder-address",
		Version:       4,
		Body:          []byte{0x01},
	}}

	payload, err := serializeDRWASyncEnvelopePayload(drwaSyncCallerAttestation, operations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// callerDomain=Attestation → tag 3, opType=HolderAuditorAuth → tag 4
	expected := bytes.NewBuffer(nil)
	schemaVersionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(schemaVersionBytes, drwaSyncEnvelopeSchemaVersion)
	expected.Write(schemaVersionBytes)
	expected.WriteByte(3) // callerDomain: Attestation
	expected.WriteByte(4) // opType: HolderAuditorAuth
	writeLengthPrefixedTest(expected, []byte("CARBON-1"))
	writeLengthPrefixedTest(expected, []byte("holder-address"))
	versionBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(versionBytes, 4)
	expected.Write(versionBytes)
	writeLengthPrefixedTest(expected, []byte{0x01})

	if !bytes.Equal(expected.Bytes(), payload) {
		t.Fatalf("unexpected payload bytes: %x", payload)
	}
}

func TestApplyDRWASyncEnvelopeRejectsHashMismatch(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		PayloadHash:  []byte("wrong-hash"),
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "CARBON-1",
			Version:       1,
			Body:          []byte(`{}`),
		}},
	}

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err == nil || err.Error() != drwaSyncRejectHashMismatch {
		t.Fatalf("expected hash mismatch rejection, got %v", err)
	}
}

func writeLengthPrefixedTest(buffer *bytes.Buffer, value []byte) {
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, uint32(len(value)))
	buffer.Write(lengthBytes)
	buffer.Write(value)
}

func TestApplyDRWASyncEnvelopeRejectsCallerAddressMismatch(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "CARBON-1",
			Version:       1,
			Body:          []byte(`{}`),
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerAssetManager))
	if err == nil || err.Error() != drwaSyncRejectUnauthorizedCaller {
		t.Fatalf("expected caller-address mismatch rejection, got %v", err)
	}
}

func TestComputeDRWASyncHashBindsCallerDomain(t *testing.T) {
	operations := []drwaSyncOperation{{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "CARBON-1",
		Version:       1,
		Body:          []byte(`{}`),
	}}

	left, err := computeDRWASyncHash(drwaSyncCallerPolicyRegistry, operations)
	if err != nil {
		t.Fatalf("policy hash: %v", err)
	}
	right, err := computeDRWASyncHash(drwaSyncCallerAssetManager, operations)
	if err != nil {
		t.Fatalf("asset hash: %v", err)
	}
	if string(left) == string(right) {
		t.Fatalf("expected caller domain to affect sync hash")
	}
}

func TestApplyDRWASyncEnvelopeRejectsStaleReplay(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["CARBON-1"] = 7
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "CARBON-1",
			Version:       6,
			Body:          []byte(`{}`),
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err == nil || err.Error() != drwaSyncRejectReplayStale {
		t.Fatalf("expected stale replay rejection, got %v", err)
	}
}

func TestApplyDRWASyncEnvelopeRejectsEqualVersionConflict(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["CARBON-1"] = 7
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "CARBON-1",
			Version:       7,
			Body:          []byte(`{}`),
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err == nil || err.Error() != drwaSyncRejectReplayDuplicate {
		t.Fatalf("expected duplicate rejection, got %v", err)
	}
}

func TestApplyDRWASyncEnvelopeRejectsVersionSkip(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["CARBON-1"] = 1
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "CARBON-1",
			Version:       3,
			Body:          []byte(`{}`),
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err == nil || err.Error() != drwaSyncRejectVersionGap {
		t.Fatalf("expected version-gap rejection, got %v", err)
	}
}

func TestApplyDRWASyncEnvelopeRollsBackAtomically(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.failPut = true
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerAssetManager,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpHolderMirror,
			TokenID:       "CARBON-1",
			Holder:        "erd1holder",
			Version:       1,
			Body:          []byte(`{}`),
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerAssetManager))
	if err == nil {
		t.Fatalf("expected batch failure")
	}
	if !adapter.rolledBack {
		t.Fatalf("expected rollback on failed batch")
	}
}

func TestApplyDRWASyncEnvelopeRejectsOversizedPayload(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerAssetManager,
		Operations: []drwaSyncOperation{
			{OperationType: drwaSyncOpHolderMirror, TokenID: "A", Holder: "h1", Version: 1, Body: []byte(`{}`)},
			{OperationType: drwaSyncOpHolderMirror, TokenID: "B", Holder: "h2", Version: 1, Body: []byte(`{}`)},
		},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	_, err := applyDRWASyncEnvelope(adapter, envelope, 1, testDRWACallerAddress(drwaSyncCallerAssetManager))
	if err == nil || err.Error() != drwaSyncRejectPayloadTooLarge {
		t.Fatalf("expected oversized payload rejection, got %v", err)
	}
}

func TestApplyDRWASyncEnvelopeRejectsPolicyRegistryOnMixedBatch(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		Operations: []drwaSyncOperation{
			{OperationType: drwaSyncOpTokenPolicy, TokenID: "CARBON-1", Version: 1, Body: []byte(`{}`)},
			{OperationType: drwaSyncOpHolderMirror, TokenID: "CARBON-1", Holder: "erd1holder", Version: 1, Body: []byte(`{}`)},
		},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err == nil || err.Error() != drwaSyncRejectUnauthorizedCaller {
		t.Fatalf("expected mixed-batch caller rejection, got %v", err)
	}
}

func TestApplyDRWASyncEnvelopeAppliesHolderProfile(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerIdentityRegistry,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpHolderProfile,
			TokenID:       "",
			Holder:        "erd1holder",
			Version:       1,
			Body:          []byte(`{"kyc_status":"approved"}`),
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	result, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerIdentityRegistry))
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if result.AppliedOperations != 1 {
		t.Fatalf(drwaTestMsgOneApplied, result.AppliedOperations)
	}
	if adapter.holderProfileVersions["erd1holder"] != 1 {
		t.Fatalf("expected holder profile version 1, got %d", adapter.holderProfileVersions["erd1holder"])
	}
}

func TestApplyDRWASyncEnvelopeRejectsEmptyTokenIDForNonHolderProfile(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "",
			Version:       1,
			Body:          []byte(`{}`),
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err == nil || err.Error() != "invalid TokenID in operation: empty field" {
		t.Fatalf("expected empty token id rejection for non-holder-profile op, got %v", err)
	}
}

func TestApplyDRWASyncEnvelopeAppliesHolderProfileWithRawAddressBytes(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	holderBytes := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xff, 0xff,
	}
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerIdentityRegistry,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpHolderProfile,
			TokenID:       "",
			Holder:        string(holderBytes),
			Version:       1,
			Body:          []byte(`{"kyc_status":"approved"}`),
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	result, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerIdentityRegistry))
	if err != nil {
		t.Fatalf("expected success with raw binary holder address, got %v", err)
	}
	if result.AppliedOperations != 1 {
		t.Fatalf(drwaTestMsgOneApplied, result.AppliedOperations)
	}
	if adapter.holderProfileVersions[string(holderBytes)] != 1 {
		t.Fatalf("expected holder profile version 1, got %d", adapter.holderProfileVersions[string(holderBytes)])
	}
}

func TestApplyDRWASyncEnvelopeAppliesHolderAuditorAuthorization(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerAttestation,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpHolderAuditorAuth,
			TokenID:       "CARBON-1",
			Holder:        "erd1holder",
			Version:       1,
			Body:          []byte(`{"auditor_authorized":true}`),
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	result, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerAttestation))
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if result.AppliedOperations != 1 {
		t.Fatalf(drwaTestMsgOneApplied, result.AppliedOperations)
	}
	if adapter.holderAuditorAuthVersions["CARBON-1|erd1holder"] != 1 {
		t.Fatalf("expected holder auditor auth version 1, got %d", adapter.holderAuditorAuthVersions["CARBON-1|erd1holder"])
	}
}

func TestApplyDRWASyncEnvelopeRejectsIdentityRegistryWrongOperation(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerIdentityRegistry,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpHolderMirror,
			TokenID:       "CARBON-1",
			Holder:        "erd1holder",
			Version:       1,
			Body:          []byte(`{}`),
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerIdentityRegistry))
	if err == nil || err.Error() != drwaSyncRejectUnauthorizedCaller {
		t.Fatalf("expected unauthorized caller rejection, got %v", err)
	}
}

func TestApplyDRWASyncEnvelopeRejectsAttestationWrongOperation(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerAttestation,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpHolderProfile,
			Holder:        "erd1holder",
			Version:       1,
			Body:          []byte(`{}`),
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerAttestation))
	if err == nil || err.Error() != drwaSyncRejectUnauthorizedCaller {
		t.Fatalf("expected unauthorized caller rejection, got %v", err)
	}
}

func TestApplyDRWASyncEnvelopeRollsBackAfterPartialProgress(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	callCount := 0
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerAssetManager,
		Operations: []drwaSyncOperation{
			{OperationType: drwaSyncOpHolderMirror, TokenID: "CARBON-1", Holder: "erd1holder", Version: 1, Body: []byte(`{"kyc":"approved"}`)},
			{OperationType: drwaSyncOpHolderMirror, TokenID: "CARBON-2", Holder: "erd1holder", Version: 1, Body: []byte(`{"kyc":"approved"}`)},
		},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	adapter.putHolderHook = func(tokenID, holder string, version uint64, body []byte) error {
		callCount++
		if callCount == 2 {
			return errDRWATestFailPut
		}
		key := tokenID + "|" + holder
		adapter.holderVersions[key] = version
		adapter.holderBodies[key] = body
		return nil
	}

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerAssetManager))
	if err == nil {
		t.Fatalf("expected rollback-triggering failure")
	}
	if !adapter.rolledBack {
		t.Fatalf("expected rollback after partial progress")
	}
}

func TestApplyDRWASyncEnvelopeAppliesHigherVersion(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.holderVersions["CARBON-1|erd1holder"] = 1
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerAssetManager,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpHolderMirror,
			TokenID:       "CARBON-1",
			Holder:        "erd1holder",
			Version:       2,
			Body:          []byte(`{"kyc":"approved"}`),
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	result, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerAssetManager))
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if result.AppliedOperations != 1 {
		t.Fatalf(drwaTestMsgOneApplied, result.AppliedOperations)
	}
}

func TestApplyDRWASyncEnvelopeDeletesUnexpectedHolderMirror(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.holderVersions["CARBON-1|erd1ghost"] = 5
	adapter.holderBodies["CARBON-1|erd1ghost"] = []byte(`{"kyc":"approved"}`)
	adapter.ensureHolderIndexed("CARBON-1", "erd1ghost")
	envelope := &drwaSyncEnvelope{
		CallerDomain:  drwaSyncCallerRecoveryAdmin,
		RecoveryScope: []string{"CARBON-1"},
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpHolderMirrorDelete,
			TokenID:       "CARBON-1",
			Holder:        "erd1ghost",
			Version:       6,
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	result, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerRecoveryAdmin))
	if err != nil {
		t.Fatalf("expected delete success, got %v", err)
	}
	if result.AppliedOperations != 1 {
		t.Fatalf(drwaTestMsgOneApplied, result.AppliedOperations)
	}
	if _, exists := adapter.holderVersions["CARBON-1|erd1ghost"]; exists {
		t.Fatalf("expected holder mirror deletion")
	}
}

func TestValidateDRWASyncVersionRejectsUint64OverflowBoundary(t *testing.T) {
	err := validateDRWASyncVersion(math.MaxUint64, 0)
	require.EqualError(t, err, drwaSyncRejectVersionOverflow)
}

// TestAuthorizedCallerMalformedMetricFiresOnLengthMismatch locks in the
// M-08 (AUD-014) observability guarantee: when the stored expected
// address or the live caller address is not a production-shape 32-byte
// address, the `sync_authorized_caller_malformed` metric fires so
// operators can distinguish a corrupt provisioning record from an
// ordinary caller rejection.
func TestAuthorizedCallerMalformedMetricFiresOnLengthMismatch(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	shortAddress := []byte("asset_manager")

	resetDRWAMetrics()
	authorized := isDRWASyncCallerAuthorized(
		adapter,
		drwaSyncCallerAssetManager,
		[]drwaSyncOperation{{
			OperationType: drwaSyncOpHolderMirror,
			TokenID:       "CARBON-1",
			Holder:        "erd1holder",
			Version:       1,
			Body:          []byte(`{"kyc":"approved"}`),
		}},
		shortAddress,
	)
	require.False(t, authorized, "short malformed caller address must not authorize")
	require.Equal(
		t,
		uint64(1),
		snapshotDRWAMetrics()[drwaMetricAuthorizedCallerMalformed],
		"short-address caller must increment the malformed-caller metric",
	)

	// Production-shape 32-byte addresses must NOT trigger the metric.
	resetDRWAMetrics()
	thirtyTwoBytes := testDRWACallerAddress(drwaSyncCallerAssetManager)
	authorized = isDRWASyncCallerAuthorized(
		adapter,
		drwaSyncCallerAssetManager,
		[]drwaSyncOperation{{
			OperationType: drwaSyncOpHolderMirror,
			TokenID:       "CARBON-1",
			Holder:        "erd1holder",
			Version:       1,
			Body:          []byte(`{"kyc":"approved"}`),
		}},
		thirtyTwoBytes,
	)
	require.True(t, authorized, "matching 32-byte addresses must authorize")
	require.Equal(
		t,
		uint64(0),
		snapshotDRWAMetrics()[drwaMetricAuthorizedCallerMalformed],
		"32-byte address pair must not increment the malformed-caller metric",
	)
}

func TestRecoveryAdminRejectsUnsupportedOperationTypes(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	authorized := isDRWASyncCallerAuthorized(
		adapter,
		drwaSyncCallerRecoveryAdmin,
		[]drwaSyncOperation{{
			OperationType: drwaSyncOpHolderProfile,
			Holder:        "erd1holder",
			Version:       1,
			Body:          []byte(`{}`),
		}},
		testDRWACallerAddress(drwaSyncCallerRecoveryAdmin),
	)

	require.False(t, authorized)
}

func TestApplyDRWASyncEnvelopeRejectsAssetManagerDeleteOperation(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerAssetManager,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpHolderMirrorDelete,
			TokenID:       "CARBON-1",
			Holder:        "erd1ghost",
			Version:       2,
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerAssetManager))
	if err == nil || err.Error() != drwaSyncRejectUnauthorizedCaller {
		t.Fatalf("expected unauthorized delete rejection, got %v", err)
	}
}

func TestDRWAHookStateAdapterWritesPolicyAndHolder(t *testing.T) {
	systemAccount := teststate.NewAccountWrapMock(core.SystemAccountAddress)
	holderAddress := []byte("erd1holder")
	holderAccount := teststate.NewAccountWrapMock(holderAddress)

	accountsStub := &teststate.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			switch string(address) {
			case string(core.SystemAccountAddress):
				return systemAccount, nil
			case string(holderAddress):
				return holderAccount, nil
			default:
				return nil, nil
			}
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error {
			return nil
		},
		JournalLenCalled: func() int {
			return 1
		},
		RevertToSnapshotCalled: func(snapshot int) error {
			return nil
		},
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)
	err = adapter.PutTokenPolicyBody("CARBON-1", 2, []byte(`{"regulated":true}`))
	if err != nil {
		t.Fatalf("PutTokenPolicyBody failed: %v", err)
	}

	err = adapter.PutHolderMirrorBody("CARBON-1", string(holderAddress), 3, []byte(`{"kyc":"approved"}`))
	if err != nil {
		t.Fatalf("PutHolderMirrorBody failed: %v", err)
	}

	policyVersion, err := adapter.GetTokenPolicyVersion("CARBON-1")
	if err != nil {
		t.Fatalf("GetTokenPolicyVersion failed: %v", err)
	}
	if policyVersion != 2 {
		t.Fatalf("expected policy version 2, got %d", policyVersion)
	}

	holderVersion, err := adapter.GetHolderMirrorVersion("CARBON-1", string(holderAddress))
	if err != nil {
		t.Fatalf("GetHolderMirrorVersion failed: %v", err)
	}
	if holderVersion != 3 {
		t.Fatalf("expected holder version 3, got %d", holderVersion)
	}
}

func TestDRWAHookStateAdapterWritesProfileAndAuditorAuthorization(t *testing.T) {
	systemAccount := teststate.NewAccountWrapMock(core.SystemAccountAddress)
	holderAddress := []byte("erd1holder")
	holderAccount := teststate.NewAccountWrapMock(holderAddress)

	accountsStub := &teststate.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			switch string(address) {
			case string(core.SystemAccountAddress):
				return systemAccount, nil
			case string(holderAddress):
				return holderAccount, nil
			default:
				return nil, nil
			}
		},
		SaveAccountCalled:      func(account vmcommon.AccountHandler) error { return nil },
		JournalLenCalled:       func() int { return 1 },
		RevertToSnapshotCalled: func(snapshot int) error { return nil },
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	err = adapter.PutHolderProfileBody(string(holderAddress), 2, []byte(`{"kyc_status":"approved"}`))
	require.NoError(t, err)
	err = adapter.PutHolderAuditorAuthorizationBody("CARBON-1", string(holderAddress), 4, []byte(`{"auditor_authorized":true}`))
	require.NoError(t, err)

	profileVersion, err := adapter.GetHolderProfileVersion(string(holderAddress))
	require.NoError(t, err)
	require.Equal(t, uint64(2), profileVersion)

	auditorVersion, err := adapter.GetHolderAuditorAuthorizationVersion("CARBON-1", string(holderAddress))
	require.NoError(t, err)
	require.Equal(t, uint64(4), auditorVersion)
}

// TestDecodeDRWASyncEnvelopeBinaryPathAndApply proves that a binary hook payload
// produced by the Rust managedDRWASyncMirror call (format: [32-byte keccak256] ||
// [canonical binary payload]) is correctly decoded and atomically applied to the
// native mirror.  The invoke_drwa_sync_hook
// wrapper is a no-op in unit builds, so this test exercises the full Go-side path
// that runs on every real block.
func TestDecodeDRWASyncEnvelopeBinaryPathAndApply(t *testing.T) {
	policyBody := []byte(`{"drwa_enabled":true,"global_pause":false,"strict_auditor_mode":false,"metadata_protection_enabled":false}`)
	operations := []drwaSyncOperation{{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "BOND-1",
		Version:       1,
		Body:          policyBody,
	}}

	// Build the canonical binary payload (mirrors Rust serialize_sync_envelope_payload).
	canonical, err := serializeDRWASyncEnvelopePayload(drwaSyncCallerPolicyRegistry, operations)
	if err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	// Compute keccak256 hash of canonical payload (mirrors Rust crypto().keccak256()).
	hash, err := computeDRWASyncHash(drwaSyncCallerPolicyRegistry, operations)
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}
	if len(hash) != drwaBinaryHashSize {
		t.Fatalf("expected %d-byte hash, got %d", drwaBinaryHashSize, len(hash))
	}

	// Assemble the full binary hook payload: [32-byte hash] || [canonical].
	// This is exactly what build_sync_hook_payload in Rust produces.
	binaryPayload := append(hash, canonical...)

	// The first byte of a binary payload is never '{' (it is the hash prefix), so
	// decodeDRWASyncEnvelope must route to the binary path.
	if binaryPayload[0] == '{' {
		t.Fatalf("test invariant broken: binary payload starts with '{'")
	}

	envelope, err := decodeDRWASyncEnvelope(binaryPayload)
	if err != nil {
		t.Fatalf("binary decode failed: %v", err)
	}
	if envelope.CallerDomain != drwaSyncCallerPolicyRegistry {
		t.Fatalf("wrong caller domain: %q", envelope.CallerDomain)
	}
	if len(envelope.Operations) != 1 {
		t.Fatalf("expected 1 operation, got %d", len(envelope.Operations))
	}
	op := envelope.Operations[0]
	if op.TokenID != "BOND-1" || op.Version != 1 {
		t.Fatalf("wrong operation fields: %+v", op)
	}
	if !bytes.Equal(op.Body, policyBody) {
		t.Fatalf("body mismatch: %q", op.Body)
	}

	// Apply to state adapter — proves the mirror is atomically updated.
	adapter := newMockDRWASyncStateAdapter()
	result, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if result.AppliedOperations != 1 {
		t.Fatalf(drwaTestMsgOneApplied, result.AppliedOperations)
	}
	if adapter.tokenVersions["BOND-1"] != 1 {
		t.Fatalf("expected mirror version 1, got %d", adapter.tokenVersions["BOND-1"])
	}
	if !bytes.Equal(adapter.tokenBodies["BOND-1"], policyBody) {
		t.Fatalf("mirror body mismatch")
	}
}

func TestDecodeDRWASyncEnvelopeBinaryHolderProfileAllowsEmptyTokenID(t *testing.T) {
	holderBytes := append([]byte{0x01}, bytes.Repeat([]byte{0x00}, 31)...)
	holder := string(holderBytes)
	operations := []drwaSyncOperation{{
		OperationType: drwaSyncOpHolderProfile,
		TokenID:       "",
		Holder:        holder,
		Version:       2,
		Body:          []byte(`{"kyc_status":"approved"}`),
	}}

	canonical, err := serializeDRWASyncEnvelopePayload(drwaSyncCallerIdentityRegistry, operations)
	require.NoError(t, err)

	hash, err := computeDRWASyncHash(drwaSyncCallerIdentityRegistry, operations)
	require.NoError(t, err)

	binaryPayload := append(hash, canonical...)
	envelope, err := decodeDRWASyncEnvelope(binaryPayload)
	require.NoError(t, err)

	require.Equal(t, drwaSyncCallerIdentityRegistry, envelope.CallerDomain)
	require.Len(t, envelope.Operations, 1)
	require.Equal(t, drwaSyncOpHolderProfile, envelope.Operations[0].OperationType)
	require.Equal(t, "", envelope.Operations[0].TokenID)
	require.Equal(t, holder, envelope.Operations[0].Holder)
	require.Equal(t, uint64(2), envelope.Operations[0].Version)
	require.Equal(t, []byte(`{"kyc_status":"approved"}`), envelope.Operations[0].Body)
}

func TestDRWAHookStateAdapterRejectsWrongTypeAssertion(t *testing.T) {
	accountsStub := &teststate.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return &teststate.StateUserAccountHandlerStub{}, nil
		},
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)
	_, err = adapter.GetTokenPolicyVersion("CARBON-1")
	if err != process.ErrWrongTypeAssertion {
		t.Fatalf("expected wrong type assertion, got %v", err)
	}
}

func TestNoopEnvelopeWithNilHashRejected(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()

	// Case 1: noop envelope with nil PayloadHash must be rejected.
	envelopeNilHash := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		PayloadHash:  nil,
		Operations:   []drwaSyncOperation{},
	}
	_, err := applyDRWASyncEnvelope(adapter, envelopeNilHash, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	require.Error(t, err)
	require.Contains(t, err.Error(), "DRWA_NOOP_ENVELOPE_HASH_REQUIRED")

	// Case 2: noop envelope with empty []byte{} PayloadHash must be rejected.
	envelopeEmptyHash := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		PayloadHash:  []byte{},
		Operations:   []drwaSyncOperation{},
	}
	_, err = applyDRWASyncEnvelope(adapter, envelopeEmptyHash, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	require.Error(t, err)
	require.Contains(t, err.Error(), "DRWA_NOOP_ENVELOPE_HASH_REQUIRED")

	// Case 3: noop envelope with valid PayloadHash must be accepted.
	validHash, err := computeDRWASyncHash(drwaSyncCallerPolicyRegistry, nil)
	require.NoError(t, err)
	envelopeValidHash := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		PayloadHash:  validHash,
		Operations:   []drwaSyncOperation{},
	}
	result, err := applyDRWASyncEnvelope(adapter, envelopeValidHash, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	require.NoError(t, err)
	require.True(t, result.Noop)
}

// ---------------------------------------------------------------------------
// F1 (closes N3 + N7): single-token recovery envelope enforcement
// ---------------------------------------------------------------------------

const (
	drwaF1TokenA       = "TOKEN-A"
	drwaF1TokenB       = "TOKEN-B"
	drwaF1PolicyBodyOn = `{"drwa_enabled":true}`
)

// TestApplyDRWASyncEnvelopeRejectsMultiTokenRecoveryScope verifies that a
// recovery_admin envelope carrying more than one token in RecoveryScope is
// rejected with the dedicated multi-token error. This is the regression guard
// for N3 (governance routing decided on first token while apply mutated all)
// and N7 (pre-recovery state hash bound only the first token's state).
func TestApplyDRWASyncEnvelopeRejectsMultiTokenRecoveryScope(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions[drwaF1TokenA] = 0
	adapter.tokenVersions[drwaF1TokenB] = 0

	envelope := &drwaSyncEnvelope{
		CallerDomain:  drwaSyncCallerRecoveryAdmin,
		RecoveryScope: []string{drwaF1TokenA, drwaF1TokenB},
		Operations: []drwaSyncOperation{
			{
				OperationType: drwaSyncOpTokenPolicy,
				TokenID:       drwaF1TokenA,
				Version:       1,
				Body:          []byte(drwaF1PolicyBodyOn),
			},
			{
				OperationType: drwaSyncOpTokenPolicy,
				TokenID:       drwaF1TokenB,
				Version:       1,
				Body:          []byte(drwaF1PolicyBodyOn),
			},
		},
	}
	hash, err := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	require.NoError(t, err)
	envelope.PayloadHash = hash

	_, err = applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerRecoveryAdmin))
	require.Error(t, err)
	require.Contains(t, err.Error(), drwaSyncRejectRecoveryScopeMultiToken)

	// Confirm that no operations were applied (atomicity preserved on rejection).
	require.Equal(t, uint64(0), adapter.tokenVersions[drwaF1TokenA])
	require.Equal(t, uint64(0), adapter.tokenVersions[drwaF1TokenB])
}

// TestApplyDRWASyncEnvelopeAcceptsSingleTokenRecoveryScope is the regression
// guard that ensures the F1 fix did not over-restrict legitimate single-token
// recovery flow. Every existing builder produces single-token envelopes; this
// test asserts they continue to work.
func TestApplyDRWASyncEnvelopeAcceptsSingleTokenRecoveryScope(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()

	envelope := &drwaSyncEnvelope{
		CallerDomain:  drwaSyncCallerRecoveryAdmin,
		RecoveryScope: []string{drwaF1TokenA},
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       drwaF1TokenA,
			Version:       1,
			Body:          []byte(drwaF1PolicyBodyOn),
		}},
	}
	hash, err := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	require.NoError(t, err)
	envelope.PayloadHash = hash

	result, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerRecoveryAdmin))
	require.NoError(t, err)
	require.Equal(t, 1, result.AppliedOperations)
	require.Equal(t, uint64(1), adapter.tokenVersions[drwaF1TokenA])
}

// TestApplyDRWASyncEnvelopeMultiTokenAllowedForNonRecoveryDomains asserts that
// the multi-token restriction is scoped only to recovery_admin. Non-recovery
// caller domains (policy_registry, asset_manager, etc.) have no recovery scope
// concept and must continue to accept multi-operation envelopes that span
// different tokens. This is a scope-creep guard for the F1 fix.
func TestApplyDRWASyncEnvelopeMultiTokenAllowedForNonRecoveryDomains(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()

	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		Operations: []drwaSyncOperation{
			{
				OperationType: drwaSyncOpTokenPolicy,
				TokenID:       drwaF1TokenA,
				Version:       1,
				Body:          []byte(drwaF1PolicyBodyOn),
			},
			{
				OperationType: drwaSyncOpTokenPolicy,
				TokenID:       drwaF1TokenB,
				Version:       1,
				Body:          []byte(drwaF1PolicyBodyOn),
			},
		},
	}
	hash, err := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	require.NoError(t, err)
	envelope.PayloadHash = hash

	result, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	require.NoError(t, err)
	require.Equal(t, 2, result.AppliedOperations)
	require.Equal(t, uint64(1), adapter.tokenVersions[drwaF1TokenA])
	require.Equal(t, uint64(1), adapter.tokenVersions[drwaF1TokenB])
}
