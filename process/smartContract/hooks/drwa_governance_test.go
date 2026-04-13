package hooks

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// --- In-memory governance store for testing ---

type mockGovernanceStore struct {
	configs   map[string]*DRWAGovernanceConfig
	proposals map[[32]byte]*DRWAGovernanceProposal
}

func newMockGovernanceStore() *mockGovernanceStore {
	return &mockGovernanceStore{
		configs:   make(map[string]*DRWAGovernanceConfig),
		proposals: make(map[[32]byte]*DRWAGovernanceProposal),
	}
}

func (s *mockGovernanceStore) GetGovernanceConfig(tokenID string) (*DRWAGovernanceConfig, error) {
	cfg, ok := s.configs[tokenID]
	if !ok {
		return nil, nil
	}
	return cfg, nil
}

func (s *mockGovernanceStore) SaveGovernanceConfig(tokenID string, cfg *DRWAGovernanceConfig) error {
	s.configs[tokenID] = cfg
	return nil
}

func (s *mockGovernanceStore) GetProposal(proposalID [32]byte) (*DRWAGovernanceProposal, error) {
	p, ok := s.proposals[proposalID]
	if !ok {
		return nil, nil
	}
	return p, nil
}

func (s *mockGovernanceStore) SaveProposal(proposal *DRWAGovernanceProposal) error {
	s.proposals[proposal.ProposalID] = proposal
	return nil
}

func (s *mockGovernanceStore) DeleteProposal(proposalID [32]byte) error {
	delete(s.proposals, proposalID)
	return nil
}

// --- Test helpers ---

func makeSigners(count int) [][]byte {
	signers := make([][]byte, count)
	for i := range signers {
		s := make([]byte, 32)
		s[0] = byte(i + 1)
		signers[i] = s
	}
	return signers
}

func make3of5Config() *DRWAGovernanceConfig {
	return &DRWAGovernanceConfig{
		Threshold:   3,
		Signers:     makeSigners(5),
		ProposalTTL: 2400,
		MaxSigners:  10,
	}
}

func makeTestRecoveryEnvelope(tokenID string) drwaSyncEnvelope {
	ops := []drwaSyncOperation{
		{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       tokenID,
			Version:       1,
			Body:          []byte(`{"transferable":true}`),
		},
	}
	hash, _ := computeDRWASyncHash(drwaSyncCallerRecoveryAdmin, ops)
	return drwaSyncEnvelope{
		CallerDomain:  drwaSyncCallerRecoveryAdmin,
		PayloadHash:   hash,
		Operations:    ops,
		RecoveryScope: []string{tokenID},
	}
}

// --- Config Validation Tests ---

func TestValidateGovernanceConfigThresholdBelow2(t *testing.T) {
	cfg := &DRWAGovernanceConfig{
		Threshold:   1,
		Signers:     makeSigners(3),
		ProposalTTL: 2400,
		MaxSigners:  10,
	}
	err := ValidateGovernanceConfig(cfg)
	require.ErrorIs(t, err, errDRWAGovernanceInvalidThreshold)
}

func TestValidateGovernanceConfigThresholdExceedsSigners(t *testing.T) {
	cfg := &DRWAGovernanceConfig{
		Threshold:   4,
		Signers:     makeSigners(3),
		ProposalTTL: 2400,
		MaxSigners:  10,
	}
	err := ValidateGovernanceConfig(cfg)
	require.ErrorIs(t, err, errDRWAGovernanceThresholdExceedsLen)
}

func TestValidateGovernanceConfigDuplicateSigners(t *testing.T) {
	signers := makeSigners(3)
	signers[2] = append([]byte(nil), signers[0]...) // duplicate signer 0
	cfg := &DRWAGovernanceConfig{
		Threshold:   2,
		Signers:     signers,
		ProposalTTL: 2400,
		MaxSigners:  10,
	}
	err := ValidateGovernanceConfig(cfg)
	require.ErrorIs(t, err, errDRWAGovernanceDuplicateSigner)
}

func TestValidateGovernanceConfigNoSigners(t *testing.T) {
	cfg := &DRWAGovernanceConfig{
		Threshold:   2,
		Signers:     nil,
		ProposalTTL: 2400,
		MaxSigners:  10,
	}
	err := ValidateGovernanceConfig(cfg)
	require.ErrorIs(t, err, errDRWAGovernanceNoSigners)
}

func TestValidateGovernanceConfigTooManySigners(t *testing.T) {
	cfg := &DRWAGovernanceConfig{
		Threshold:   2,
		Signers:     makeSigners(5),
		ProposalTTL: 2400,
		MaxSigners:  3,
	}
	err := ValidateGovernanceConfig(cfg)
	require.ErrorIs(t, err, errDRWAGovernanceTooManySigners)
}

func TestValidateGovernanceConfigMaxSignersExceedsAbsolute(t *testing.T) {
	cfg := &DRWAGovernanceConfig{
		Threshold:   2,
		Signers:     makeSigners(3),
		ProposalTTL: 2400,
		MaxSigners:  100,
	}
	err := ValidateGovernanceConfig(cfg)
	require.ErrorIs(t, err, errDRWAGovernanceInvalidMaxSigners)
}

func TestValidateGovernanceConfigZeroTTL(t *testing.T) {
	cfg := &DRWAGovernanceConfig{
		Threshold:   2,
		Signers:     makeSigners(3),
		ProposalTTL: 0,
		MaxSigners:  10,
	}
	err := ValidateGovernanceConfig(cfg)
	require.ErrorIs(t, err, errDRWAGovernanceInvalidProposalTTL)
}

func TestValidateGovernanceConfigValid3of5(t *testing.T) {
	cfg := make3of5Config()
	require.NoError(t, ValidateGovernanceConfig(cfg))
}

func TestValidateGovernanceConfigNil(t *testing.T) {
	require.Error(t, ValidateGovernanceConfig(nil))
}

func TestValidateGovernanceConfigMaxSignersBelowThreshold(t *testing.T) {
	cfg := &DRWAGovernanceConfig{
		Threshold:   3,
		Signers:     makeSigners(3),
		ProposalTTL: 2400,
		MaxSigners:  2,
	}
	err := ValidateGovernanceConfig(cfg)
	require.ErrorIs(t, err, errDRWAGovernanceInvalidMaxSigners)
}

// --- Happy Path: Propose -> Approve -> Execute (3-of-5) ---

func TestGovernanceHappyPath3of5(t *testing.T) {
	resetDRWAMetrics()
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)

	tokenID := "TOKEN-abc123"
	cfg := make3of5Config()
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := cfg.Signers

	// Signer 0 proposes (counts as first approval).
	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, proposalID)

	// Verify proposal was created with 1 approval.
	proposal, err := store.GetProposal(proposalID)
	require.NoError(t, err)
	require.NotNil(t, proposal)
	require.Len(t, proposal.Approvals, 1)
	require.True(t, bytes.Equal(signers[0], proposal.Approvals[0]))
	require.False(t, proposal.Executed)

	// Signer 1 approves.
	require.NoError(t, engine.ApproveRecoveryOperation(signers[1], proposalID))
	proposal, _ = store.GetProposal(proposalID)
	require.Len(t, proposal.Approvals, 2)

	// Signer 2 approves — threshold (3) now met.
	require.NoError(t, engine.ApproveRecoveryOperation(signers[2], proposalID))
	proposal, _ = store.GetProposal(proposalID)
	require.Len(t, proposal.Approvals, 3)

	// Signer 3 executes (any authorized signer can execute once threshold is met).
	resolvedEnvelope, err := engine.ExecuteRecoveryOperation(signers[3], proposalID, 1010)
	require.NoError(t, err)
	require.NotNil(t, resolvedEnvelope)
	require.Equal(t, drwaSyncCallerRecoveryAdmin, resolvedEnvelope.CallerDomain)
	require.Len(t, resolvedEnvelope.Operations, 1)
	require.Equal(t, tokenID, resolvedEnvelope.Operations[0].TokenID)

	// Verify proposal is marked as executed.
	proposal, _ = store.GetProposal(proposalID)
	require.True(t, proposal.Executed)

	// Verify metrics.
	metrics := snapshotDRWAMetrics()
	require.Equal(t, uint64(1), metrics[drwaMetricGovernanceProposalCreated])
	require.Equal(t, uint64(2), metrics[drwaMetricGovernanceApprovalAdded])
	require.Equal(t, uint64(1), metrics[drwaMetricGovernanceProposalExecuted])
}

// --- Duplicate Approval Rejection ---

func TestGovernanceDuplicateApprovalRejected(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-dup"
	require.NoError(t, store.SaveGovernanceConfig(tokenID, make3of5Config()))

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := make3of5Config().Signers

	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)

	// Signer 0 tries to approve again — already approved as proposer.
	err = engine.ApproveRecoveryOperation(signers[0], proposalID)
	require.ErrorIs(t, err, errDRWAGovernanceDuplicateApproval)
}

// --- Expired Proposal Rejection ---

func TestGovernanceExpiredProposalRejected(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-exp"
	cfg := make3of5Config()
	cfg.ProposalTTL = 100
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := cfg.Signers

	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)

	require.NoError(t, engine.ApproveRecoveryOperation(signers[1], proposalID))
	require.NoError(t, engine.ApproveRecoveryOperation(signers[2], proposalID))

	// Execute at block 1101 — TTL of 100 expired (created at 1000, deadline = 1100).
	_, err = engine.ExecuteRecoveryOperation(signers[3], proposalID, 1101)
	require.ErrorIs(t, err, errDRWAGovernanceProposalExpired)
}

// --- Insufficient Approvals Rejection ---

func TestGovernanceInsufficientApprovalsRejected(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-insuf"
	require.NoError(t, store.SaveGovernanceConfig(tokenID, make3of5Config()))

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := make3of5Config().Signers

	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)

	// Only 1 approval (proposer), need 3.
	_, err = engine.ExecuteRecoveryOperation(signers[1], proposalID, 1010)
	require.ErrorIs(t, err, errDRWAGovernanceThresholdNotMet)
}

// --- Non-Signer Rejection ---

func TestGovernanceNonSignerProposalRejected(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-nonsig"
	require.NoError(t, store.SaveGovernanceConfig(tokenID, make3of5Config()))

	envelope := makeTestRecoveryEnvelope(tokenID)
	outsider := make([]byte, 32)
	outsider[0] = 0xFF

	_, err := engine.ProposeRecoveryOperation(outsider, envelope, 1000)
	require.ErrorIs(t, err, errDRWAGovernanceSignerNotAuthorized)
}

func TestGovernanceNonSignerApprovalRejected(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-nonsig2"
	require.NoError(t, store.SaveGovernanceConfig(tokenID, make3of5Config()))

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := make3of5Config().Signers

	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)

	outsider := make([]byte, 32)
	outsider[0] = 0xFF
	err = engine.ApproveRecoveryOperation(outsider, proposalID)
	require.ErrorIs(t, err, errDRWAGovernanceSignerNotAuthorized)
}

func TestGovernanceNonSignerExecuteRejected(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-nonsig3"
	cfg := make3of5Config()
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := cfg.Signers

	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)
	require.NoError(t, engine.ApproveRecoveryOperation(signers[1], proposalID))
	require.NoError(t, engine.ApproveRecoveryOperation(signers[2], proposalID))

	outsider := make([]byte, 32)
	outsider[0] = 0xFF
	_, err = engine.ExecuteRecoveryOperation(outsider, proposalID, 1010)
	require.ErrorIs(t, err, errDRWAGovernanceSignerNotAuthorized)
}

// --- Double Execution Prevention ---

func TestGovernanceDoubleExecutionPrevented(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-dblexec"
	require.NoError(t, store.SaveGovernanceConfig(tokenID, make3of5Config()))

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := make3of5Config().Signers

	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)
	require.NoError(t, engine.ApproveRecoveryOperation(signers[1], proposalID))
	require.NoError(t, engine.ApproveRecoveryOperation(signers[2], proposalID))

	// First execution succeeds.
	_, err = engine.ExecuteRecoveryOperation(signers[3], proposalID, 1010)
	require.NoError(t, err)

	// Second execution fails.
	_, err = engine.ExecuteRecoveryOperation(signers[3], proposalID, 1020)
	require.ErrorIs(t, err, errDRWAGovernanceProposalExecuted)
}

// --- Execute Before Threshold Met ---

func TestGovernanceExecuteBeforeThreshold(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-early"
	require.NoError(t, store.SaveGovernanceConfig(tokenID, make3of5Config()))

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := make3of5Config().Signers

	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)

	// Only 1 approval — try to execute with 2 approvals (proposer + 1).
	require.NoError(t, engine.ApproveRecoveryOperation(signers[1], proposalID))

	_, err = engine.ExecuteRecoveryOperation(signers[2], proposalID, 1005)
	require.ErrorIs(t, err, errDRWAGovernanceThresholdNotMet)
}

// --- Proposal Not Found ---

func TestGovernanceProposalNotFound(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)

	var fakeID [32]byte
	fakeID[0] = 0xDE

	err := engine.ApproveRecoveryOperation([]byte("signer"), fakeID)
	require.ErrorIs(t, err, errDRWAGovernanceProposalNotFound)

	_, err = engine.ExecuteRecoveryOperation([]byte("signer"), fakeID, 100)
	require.ErrorIs(t, err, errDRWAGovernanceProposalNotFound)
}

// --- Governance Not Enabled for Token ---

func TestGovernanceNotEnabledForToken(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)

	envelope := makeTestRecoveryEnvelope("UNGOVERN-TOKEN")
	signer := make([]byte, 32)
	signer[0] = 1

	_, err := engine.ProposeRecoveryOperation(signer, envelope, 1000)
	require.ErrorIs(t, err, errDRWAGovernanceNotEnabled)
}

// --- IsSignerAuthorized ---

func TestIsSignerAuthorized(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-auth"
	cfg := make3of5Config()
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	require.True(t, engine.IsSignerAuthorized(cfg.Signers[0], tokenID))
	require.True(t, engine.IsSignerAuthorized(cfg.Signers[4], tokenID))

	outsider := make([]byte, 32)
	outsider[0] = 0xFF
	require.False(t, engine.IsSignerAuthorized(outsider, tokenID))
	require.False(t, engine.IsSignerAuthorized(nil, tokenID))
	require.False(t, engine.IsSignerAuthorized(cfg.Signers[0], "UNKNOWN-TOKEN"))
}

// --- Backward Compatibility: No Governance Config -> Single-Key Works ---

func TestBackwardCompatibilityNoGovernanceConfig(t *testing.T) {
	// When no governance config exists for a token, recovery_admin should
	// work exactly as before via the standard applyDRWASyncEnvelope path.
	adapter := newMockDRWASyncStateAdapter()

	tokenID := "TOKEN-legacy"
	ops := []drwaSyncOperation{
		{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       tokenID,
			Version:       1,
			Body:          []byte(`{"transferable":true}`),
		},
	}
	hash, err := computeDRWASyncHash(drwaSyncCallerRecoveryAdmin, ops)
	require.NoError(t, err)

	envelope := &drwaSyncEnvelope{
		CallerDomain:  drwaSyncCallerRecoveryAdmin,
		PayloadHash:   hash,
		Operations:    ops,
		RecoveryScope: []string{tokenID},
	}

	// The mock adapter does NOT implement drwaSyncGovernanceProvider,
	// so maybeRouteToGovernance returns (nil, false, nil) — falls through
	// to single-key recovery path.
	result, err := applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, []byte("recovery_admin"))
	require.NoError(t, err)
	require.Equal(t, 1, result.AppliedOperations)
	require.False(t, result.GovernancePending)
	require.Equal(t, [32]byte{}, result.GovernanceProposalID)

	// Verify the operation was actually applied.
	require.Equal(t, uint64(1), adapter.tokenVersions[tokenID])
}

// --- IsGovernanceEnabled ---

func TestIsGovernanceEnabled(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)

	require.False(t, engine.IsGovernanceEnabled("TOKEN-no"))

	require.NoError(t, store.SaveGovernanceConfig("TOKEN-yes", make3of5Config()))
	require.True(t, engine.IsGovernanceEnabled("TOKEN-yes"))
}

// --- Nil Store Edge Cases ---

func TestGovernanceEngineNilStore(t *testing.T) {
	engine := NewDRWAGovernanceEngine(nil)

	require.False(t, engine.IsGovernanceEnabled("TOKEN"))
	require.False(t, engine.IsSignerAuthorized([]byte("x"), "TOKEN"))

	envelope := makeTestRecoveryEnvelope("TOKEN")
	_, err := engine.ProposeRecoveryOperation([]byte("x"), envelope, 100)
	require.ErrorIs(t, err, errDRWAGovernanceNilStore)

	err = engine.ApproveRecoveryOperation([]byte("x"), [32]byte{})
	require.ErrorIs(t, err, errDRWAGovernanceNilStore)

	_, err = engine.ExecuteRecoveryOperation([]byte("x"), [32]byte{}, 100)
	require.ErrorIs(t, err, errDRWAGovernanceNilStore)
}

// --- Nil/Empty Caller ---

func TestGovernanceNilCaller(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-nilcall"
	require.NoError(t, store.SaveGovernanceConfig(tokenID, make3of5Config()))

	envelope := makeTestRecoveryEnvelope(tokenID)

	_, err := engine.ProposeRecoveryOperation(nil, envelope, 1000)
	require.ErrorIs(t, err, errDRWAGovernanceNilCaller)

	_, err = engine.ProposeRecoveryOperation([]byte{}, envelope, 1000)
	require.ErrorIs(t, err, errDRWAGovernanceNilCaller)

	err = engine.ApproveRecoveryOperation(nil, [32]byte{})
	require.ErrorIs(t, err, errDRWAGovernanceNilCaller)

	_, err = engine.ExecuteRecoveryOperation(nil, [32]byte{}, 100)
	require.ErrorIs(t, err, errDRWAGovernanceNilCaller)
}

// --- Approve on Already-Executed Proposal ---

func TestGovernanceApproveOnExecutedProposal(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-appexec"
	cfg := make3of5Config()
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := cfg.Signers

	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)
	require.NoError(t, engine.ApproveRecoveryOperation(signers[1], proposalID))
	require.NoError(t, engine.ApproveRecoveryOperation(signers[2], proposalID))

	_, err = engine.ExecuteRecoveryOperation(signers[3], proposalID, 1010)
	require.NoError(t, err)

	// Now try to approve the executed proposal.
	err = engine.ApproveRecoveryOperation(signers[4], proposalID)
	require.ErrorIs(t, err, errDRWAGovernanceProposalExecuted)
}

// --- Envelope Serialization Round-Trip ---

func TestGovernanceEnvelopeSerializationRoundTrip(t *testing.T) {
	envelope := makeTestRecoveryEnvelope("TOKEN-serde")

	data, err := serializeGovernanceEnvelope(&envelope)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	restored, err := deserializeGovernanceEnvelope(data)
	require.NoError(t, err)
	require.Equal(t, envelope.CallerDomain, restored.CallerDomain)
	require.Len(t, restored.Operations, len(envelope.Operations))
	require.Equal(t, envelope.Operations[0].TokenID, restored.Operations[0].TokenID)
	require.Equal(t, envelope.RecoveryScope, restored.RecoveryScope)
}

// --- Edge: Execute exactly at TTL boundary ---

func TestGovernanceExecuteAtExactTTLBoundary(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-ttlbound"
	cfg := make3of5Config()
	cfg.ProposalTTL = 100
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := cfg.Signers

	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)
	require.NoError(t, engine.ApproveRecoveryOperation(signers[1], proposalID))
	require.NoError(t, engine.ApproveRecoveryOperation(signers[2], proposalID))

	// Execute at block 1100 — exactly at deadline (1000 + 100). Should succeed.
	resolved, err := engine.ExecuteRecoveryOperation(signers[3], proposalID, 1100)
	require.NoError(t, err)
	require.NotNil(t, resolved)
}

// --- Edge: Execute one block past TTL boundary ---

func TestGovernanceExecuteOneBlockPastTTL(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-ttlpast"
	cfg := make3of5Config()
	cfg.ProposalTTL = 100
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := cfg.Signers

	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)
	require.NoError(t, engine.ApproveRecoveryOperation(signers[1], proposalID))
	require.NoError(t, engine.ApproveRecoveryOperation(signers[2], proposalID))

	// Execute at block 1101 — one past deadline. Should fail.
	_, err = engine.ExecuteRecoveryOperation(signers[3], proposalID, 1101)
	require.ErrorIs(t, err, errDRWAGovernanceProposalExpired)
}

// --- computeProposalID determinism ---

func TestComputeProposalIDDeterministic(t *testing.T) {
	var hash [32]byte
	hash[0] = 0xAB
	id1 := computeProposalID(hash, 42)
	id2 := computeProposalID(hash, 42)
	require.Equal(t, id1, id2)

	// Different nonce = different ID.
	id3 := computeProposalID(hash, 43)
	require.NotEqual(t, id1, id3)

	// Different hash = different ID.
	var hash2 [32]byte
	hash2[0] = 0xCD
	id4 := computeProposalID(hash2, 42)
	require.NotEqual(t, id1, id4)
}

// --- Integration: maybeRouteToGovernance with non-governance adapter ---

func TestMaybeRouteToGovernanceNonGovernanceAdapter(t *testing.T) {
	// A plain mockDRWASyncStateAdapter does not implement drwaSyncGovernanceProvider.
	adapter := newMockDRWASyncStateAdapter()
	envelope := makeTestRecoveryEnvelope("TOKEN-plain")

	result, handled, err := maybeRouteToGovernance(adapter, &envelope, []byte("caller"))
	require.NoError(t, err)
	require.False(t, handled)
	require.Nil(t, result)
}

// --- Integration: governance-capable adapter routes through governance ---

type mockGovernanceCapableAdapter struct {
	*mockDRWASyncStateAdapter
	engine       *DRWAGovernanceEngine
	currentBlock uint64
}

func (m *mockGovernanceCapableAdapter) GetGovernanceEngine() *DRWAGovernanceEngine {
	return m.engine
}

func (m *mockGovernanceCapableAdapter) GetCurrentBlockNonceForGovernance() (uint64, error) {
	return m.currentBlock, nil
}

func TestMaybeRouteToGovernanceWithGovernanceAdapter(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-gcap"
	cfg := make3of5Config()
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	adapter := &mockGovernanceCapableAdapter{
		mockDRWASyncStateAdapter: newMockDRWASyncStateAdapter(),
		engine:                   engine,
		currentBlock:             2000,
	}

	envelope := makeTestRecoveryEnvelope(tokenID)
	signer := cfg.Signers[0]

	result, handled, err := maybeRouteToGovernance(adapter, &envelope, signer)
	require.NoError(t, err)
	require.True(t, handled)
	require.NotNil(t, result)
	require.True(t, result.GovernancePending)
	require.NotEqual(t, [32]byte{}, result.GovernanceProposalID)

	// Token policy should NOT have been applied yet.
	require.Equal(t, uint64(0), adapter.tokenVersions[tokenID])
}

// --- Integration: handleDRWAGovernanceOperation for approve/execute ---

func TestHandleDRWAGovernanceOperationApproveAndExecute(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-govop"
	cfg := make3of5Config()
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	adapter := &mockGovernanceCapableAdapter{
		mockDRWASyncStateAdapter: newMockDRWASyncStateAdapter(),
		engine:                   engine,
		currentBlock:             3000,
	}

	// First, create a proposal via the engine directly.
	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := cfg.Signers
	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 3000)
	require.NoError(t, err)

	// Approve via handleDRWAGovernanceOperation.
	approveEnvelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerRecoveryAdmin,
		Operations: []drwaSyncOperation{
			{
				OperationType: drwaSyncOpGovernanceApprove,
				TokenID:       tokenID,
				Body:          proposalID[:],
			},
		},
	}

	// Approve with signer 1.
	result, err := handleDRWAGovernanceOperation(adapter, approveEnvelope, signers[1])
	require.NoError(t, err)
	require.True(t, result.GovernancePending)

	// Approve with signer 2 — threshold now met.
	result, err = handleDRWAGovernanceOperation(adapter, approveEnvelope, signers[2])
	require.NoError(t, err)

	// Execute via handleDRWAGovernanceOperation.
	executeEnvelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerRecoveryAdmin,
		Operations: []drwaSyncOperation{
			{
				OperationType: drwaSyncOpGovernanceExecute,
				TokenID:       tokenID,
				Body:          proposalID[:],
			},
		},
	}

	// Use recovery_admin authorized caller for the execution path.
	result, err = handleDRWAGovernanceOperation(adapter, executeEnvelope, signers[3])
	require.NoError(t, err)
	require.Equal(t, proposalID, result.GovernanceProposalID)
	require.Equal(t, 1, result.AppliedOperations)

	// Verify the token policy was actually applied.
	require.Equal(t, uint64(1), adapter.tokenVersions[tokenID])
}
