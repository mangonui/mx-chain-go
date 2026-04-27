package hooks

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmmock "github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

// --- In-memory governance store for testing ---

type mockGovernanceStore struct {
	configs      map[string]*DRWAGovernanceConfig
	proposals    map[[32]byte]*DRWAGovernanceProposal
	auditRecords map[[32]byte]*DRWAGovernanceAuditRecord
}

func newMockGovernanceStore() *mockGovernanceStore {
	return &mockGovernanceStore{
		configs:      make(map[string]*DRWAGovernanceConfig),
		proposals:    make(map[[32]byte]*DRWAGovernanceProposal),
		auditRecords: make(map[[32]byte]*DRWAGovernanceAuditRecord),
	}
}

func (s *mockGovernanceStore) GetGovernanceConfig(tokenID string) (*DRWAGovernanceConfig, error) {
	cfg, ok := s.configs[tokenID]
	if !ok {
		return nil, nil
	}
	return cloneDRWAGovernanceConfig(cfg), nil
}

func (s *mockGovernanceStore) SaveGovernanceConfig(tokenID string, cfg *DRWAGovernanceConfig, expectedVersion ...uint64) error {
	if cfg == nil {
		return errDRWAGovernanceNilStore
	}

	currentVersion := uint64(0)
	if existing, ok := s.configs[tokenID]; ok && existing != nil {
		currentVersion = existing.Version
	}

	matchVersion := cfg.Version
	if len(expectedVersion) > 0 {
		matchVersion = expectedVersion[0]
	}
	if matchVersion != currentVersion {
		return errDRWAGovernanceConfigVersionMismatch
	}

	cloned := cloneDRWAGovernanceConfig(cfg)
	cloned.Version = currentVersion + 1
	s.configs[tokenID] = cloned
	cfg.Version = cloned.Version
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

// M-14: mock implementations for the audit-record methods.
func (s *mockGovernanceStore) SaveAuditRecord(record *DRWAGovernanceAuditRecord) error {
	if record == nil {
		return errDRWAGovernanceProposalNotFound
	}
	s.auditRecords[record.ProposalID] = record
	return nil
}

func (s *mockGovernanceStore) GetAuditRecord(proposalID [32]byte) (*DRWAGovernanceAuditRecord, error) {
	rec, ok := s.auditRecords[proposalID]
	if !ok {
		return nil, nil
	}
	return rec, nil
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

func TestGovernanceTrieStoreConfigRoundTrip(t *testing.T) {
	systemAccount := vmmock.NewAccountWrapMock(core.SystemAccountAddress)
	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			if string(address) == string(core.SystemAccountAddress) {
				return systemAccount, nil
			}
			return vmmock.NewAccountWrapMock(address), nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
	}

	store, err := newDRWAGovernanceTrieStore(accountsStub)
	require.NoError(t, err)

	cfg := make3of5Config()
	require.NoError(t, store.SaveGovernanceConfig("TOKEN-store", cfg))

	got, err := store.GetGovernanceConfig("TOKEN-store")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, uint64(1), got.Version)
	require.Equal(t, cfg.Threshold, got.Threshold)
	require.Equal(t, cfg.ProposalTTL, got.ProposalTTL)
	require.Equal(t, cfg.MaxSigners, got.MaxSigners)
	require.Equal(t, len(cfg.Signers), len(got.Signers))
}

func TestBlockChainHookQueryDRWANativeGovernanceConfig(t *testing.T) {
	systemAccount := vmmock.NewAccountWrapMock(core.SystemAccountAddress)
	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			if string(address) == string(core.SystemAccountAddress) {
				return systemAccount, nil
			}
			return vmmock.NewAccountWrapMock(address), nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
	}

	store, err := newDRWAGovernanceTrieStore(accountsStub)
	require.NoError(t, err)
	require.NoError(t, store.SaveGovernanceConfig("TOKEN-query", make3of5Config()))

	hook := &BlockChainHookImpl{accounts: accountsStub}
	encoded, err := hook.QueryDRWANativeGovernance(drwaNativeGovernanceQueryConfig, []byte("TOKEN-query"))
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"threshold":3`)
	require.Contains(t, string(encoded), `"proposal_ttl":2400`)
}

func TestGovernanceTrieStoreConfigRejectsVersionMismatch(t *testing.T) {
	systemAccount := vmmock.NewAccountWrapMock(core.SystemAccountAddress)
	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			if string(address) == string(core.SystemAccountAddress) {
				return systemAccount, nil
			}
			return vmmock.NewAccountWrapMock(address), nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
	}

	store, err := newDRWAGovernanceTrieStore(accountsStub)
	require.NoError(t, err)

	cfg := make3of5Config()
	require.NoError(t, store.SaveGovernanceConfig("TOKEN-store", cfg))

	stale := make3of5Config()
	err = store.SaveGovernanceConfig("TOKEN-store", stale)
	require.ErrorIs(t, err, errDRWAGovernanceConfigVersionMismatch)
}

func TestGovernanceTrieStoreProposalRoundTripAndDelete(t *testing.T) {
	systemAccount := vmmock.NewAccountWrapMock(core.SystemAccountAddress)
	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			if string(address) == string(core.SystemAccountAddress) {
				return systemAccount, nil
			}
			return vmmock.NewAccountWrapMock(address), nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
	}

	store, err := newDRWAGovernanceTrieStore(accountsStub)
	require.NoError(t, err)

	proposalID := [32]byte{1, 2, 3}
	proposal := &DRWAGovernanceProposal{
		ProposalID:      proposalID,
		EnvelopeHash:    [32]byte{9, 9, 9},
		Proposer:        []byte("signer"),
		Approvals:       [][]byte{[]byte("signer")},
		CreatedAtBlock:  100,
		Executed:        false,
		EnvelopePayload: []byte(`{"caller_domain":"recovery_admin"}`),
	}

	require.NoError(t, store.SaveProposal(proposal))

	got, err := store.GetProposal(proposalID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, proposal.ProposalID, got.ProposalID)
	require.Equal(t, proposal.CreatedAtBlock, got.CreatedAtBlock)
	require.Equal(t, proposal.Approvals, got.Approvals)
	require.Equal(t, proposal.EnvelopePayload, got.EnvelopePayload)

	require.NoError(t, store.DeleteProposal(proposalID))

	got, err = store.GetProposal(proposalID)
	require.NoError(t, err)
	require.Nil(t, got)
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

func TestGovernanceProposalIDCollisionRejected(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-collision"
	cfg := make3of5Config()
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := cfg.Signers

	firstProposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)

	expectedHash, err := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	require.NoError(t, err)
	var expectedEnvHash [32]byte
	copy(expectedEnvHash[:], expectedHash)
	require.Equal(t, firstProposalID, computeProposalID(expectedEnvHash, 1000))

	secondProposalID, err := engine.ProposeRecoveryOperation(signers[1], envelope, 1000)
	require.ErrorIs(t, err, errDRWAGovernanceProposalIDCollision)
	require.Equal(t, [32]byte{}, secondProposalID)

	stored, err := store.GetProposal(firstProposalID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.True(t, bytes.Equal(signers[0], stored.Proposer))
	require.Len(t, stored.Approvals, 1)
	require.True(t, bytes.Equal(signers[0], stored.Approvals[0]))
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

func TestGovernanceExpiredProposalRejectsLateApproval(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-exp-approve"
	cfg := make3of5Config()
	cfg.ProposalTTL = 100
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := cfg.Signers

	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)

	err = engine.ApproveRecoveryOperation(signers[1], proposalID, 1101)
	require.ErrorIs(t, err, errDRWAGovernanceProposalExpired)

	stored, err := store.GetProposal(proposalID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.Len(t, stored.Approvals, 1)
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

// --- No Governance Config -> Fail Closed ---

func TestRecoveryAdminNoGovernanceConfigFailsClosed(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	adapter := &mockGovernanceCapableAdapter{
		mockDRWASyncStateAdapter: newMockDRWASyncStateAdapter(),
		engine:                   engine,
		currentBlock:             100,
	}

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

	result, err := applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerRecoveryAdmin))
	require.ErrorIs(t, err, errDRWARecoveryGovernanceRequired)
	require.Nil(t, result)

	// Verify nothing was applied.
	require.Equal(t, uint64(0), adapter.tokenVersions[tokenID])
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

// ── B-10 (R-01-F-02) stale-approval-after-rotation regression tests ──

// TestB10StaleApprovalAfterSignerRotationIsDropped is the canonical
// regression test for R-01-F-02. Three signers (A, B, C) approve a
// proposal, quorum is met, then the signer config is rotated to remove
// A and B (e.g. key compromise). At execute time, A's and B's stored
// approvals MUST be dropped; only C's approval remains valid; with
// threshold=3 and only 1 valid approval the execute call rejects with
// `errDRWAGovernanceThresholdNotMet`. The stale-drop metric must fire
// twice (once per dropped approval).
func TestB10StaleApprovalAfterSignerRotationIsDropped(t *testing.T) {
	resetDRWAMetrics()
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)

	tokenID := "TOKEN-b10-rotation"
	cfg := make3of5Config()
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	envelope := makeTestRecoveryEnvelope(tokenID)
	originalSigners := cfg.Signers

	// Three signers approve.
	proposalID, err := engine.ProposeRecoveryOperation(originalSigners[0], envelope, 1000)
	require.NoError(t, err)
	require.NoError(t, engine.ApproveRecoveryOperation(originalSigners[1], proposalID))
	require.NoError(t, engine.ApproveRecoveryOperation(originalSigners[2], proposalID))

	// Rotate the signer set: drop signers 0 and 1 (simulating rotation
	// of two compromised keys). Keep signer 2 plus add two new signers
	// to preserve the 5-signer / 3-threshold floor promised by the
	// key-rotation procedure.
	rotatedSigners := [][]byte{
		append([]byte(nil), originalSigners[2]...),
		append([]byte(nil), originalSigners[3]...),
		append([]byte(nil), originalSigners[4]...),
		makeSigners(10)[6],
		makeSigners(10)[7],
	}
	rotatedCfg := &DRWAGovernanceConfig{
		Version:     cfg.Version,
		Threshold:   3,
		Signers:     rotatedSigners,
		ProposalTTL: cfg.ProposalTTL,
		MaxSigners:  cfg.MaxSigners,
	}
	require.NoError(t, ValidateGovernanceConfig(rotatedCfg))
	require.NoError(t, store.SaveGovernanceConfig(tokenID, rotatedCfg))

	// A current signer attempts execute. Only the still-valid approver
	// (signer 2) remains; threshold 3 is no longer met.
	_, err = engine.ExecuteRecoveryOperation(rotatedSigners[0], proposalID, 1010)
	require.ErrorIs(t, err, errDRWAGovernanceThresholdNotMet)

	// Verify the stale-drop metric fired exactly twice (signers 0 and 1).
	metrics := snapshotDRWAMetrics()
	require.Equal(
		t,
		uint64(2),
		metrics[drwaMetricGovernanceApprovalStaleAfterRotation],
		"two stale approvals must be reported",
	)

	// Verify the proposal is NOT marked executed (rejection happened
	// before the persist-and-execute step).
	stored, err := store.GetProposal(proposalID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.False(t, stored.Executed)
}

// TestB10PartialRotationPreservesValidApprovals covers the case where
// enough approvals survive the rotation to still meet threshold. Three
// signers approve with threshold=3, then only signer A is rotated out,
// but a new signer is added so the 5-signer floor holds. Even though
// one approval is dropped, 2 approvals remain — still below threshold
// so the execute must reject. We also assert that the stored proposal
// has its Approvals list compacted to only the surviving entries so
// later reads reflect post-rotation truth.
func TestB10PartialRotationCompactsStoredApprovals(t *testing.T) {
	resetDRWAMetrics()
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)

	tokenID := "TOKEN-b10-partial"
	cfg := make3of5Config()
	// Lower threshold to 2 so the post-rotation survivor count (2 valid
	// approvals) still meets threshold and the happy path executes.
	cfg.Threshold = 2
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	envelope := makeTestRecoveryEnvelope(tokenID)
	original := cfg.Signers

	// Three approvals: 0 (proposer), 1, 2.
	proposalID, err := engine.ProposeRecoveryOperation(original[0], envelope, 1000)
	require.NoError(t, err)
	require.NoError(t, engine.ApproveRecoveryOperation(original[1], proposalID))
	require.NoError(t, engine.ApproveRecoveryOperation(original[2], proposalID))

	// Rotate out signer 0 only; keep 1..4 and add a new signer to
	// replace 0.
	extra := makeSigners(10)[7]
	rotatedSigners := [][]byte{
		append([]byte(nil), original[1]...),
		append([]byte(nil), original[2]...),
		append([]byte(nil), original[3]...),
		append([]byte(nil), original[4]...),
		extra,
	}
	rotatedCfg := &DRWAGovernanceConfig{
		Version:     cfg.Version,
		Threshold:   2,
		Signers:     rotatedSigners,
		ProposalTTL: cfg.ProposalTTL,
		MaxSigners:  cfg.MaxSigners,
	}
	require.NoError(t, ValidateGovernanceConfig(rotatedCfg))
	require.NoError(t, store.SaveGovernanceConfig(tokenID, rotatedCfg))

	// Execute with a current signer. 2 surviving approvals >= threshold=2
	// → must succeed.
	_, err = engine.ExecuteRecoveryOperation(rotatedSigners[0], proposalID, 1010)
	require.NoError(t, err)

	// Metric must fire exactly once (signer 0 dropped).
	metrics := snapshotDRWAMetrics()
	require.Equal(
		t,
		uint64(1),
		metrics[drwaMetricGovernanceApprovalStaleAfterRotation],
		"exactly one stale approval must be reported",
	)

	// The stored proposal's Approvals slice must be compacted to
	// only the surviving approvers (signers 1 and 2). No rotated-out
	// signer may remain in the recorded approvals list.
	stored, err := store.GetProposal(proposalID)
	require.NoError(t, err)
	require.True(t, stored.Executed)
	require.Len(t, stored.Approvals, 2)
	for _, approval := range stored.Approvals {
		require.True(
			t,
			isGovernanceSigner(approval, rotatedSigners),
			"persisted approvals must be a subset of the current signer set",
		)
	}
}

// TestB10NoRotationDoesNotTriggerStaleDrops guards against a false-
// positive: the stale-drop metric must NOT fire when the signer set is
// unchanged between propose and execute. This is the happy path every
// real deployment takes on the overwhelming majority of recovery
// operations and it must be regression-safe.
func TestB10NoRotationDoesNotTriggerStaleDrops(t *testing.T) {
	resetDRWAMetrics()
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)

	tokenID := "TOKEN-b10-no-rotation"
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

	metrics := snapshotDRWAMetrics()
	require.Equal(
		t,
		uint64(0),
		metrics[drwaMetricGovernanceApprovalStaleAfterRotation],
		"no rotation → no stale-drop metric",
	)
}

// ── M-13 (R-01-F-04) envelope-hash re-verification tests ────────────

// TestM13RejectsTamperedEnvelopePayload is the canonical regression
// test for R-01-F-04. Quorum is reached normally, but between
// propose and execute the store's `EnvelopePayload` is mutated to
// carry a different operation list. Execute MUST detect the
// hash-mismatch and reject with `errDRWAGovernanceEnvelopeHashMismatch`.
// The dedicated mismatch metric must fire exactly once. The proposal
// must NOT flip to `Executed = true` because the reject happens before
// the persist step.
func TestM13RejectsTamperedEnvelopePayload(t *testing.T) {
	resetDRWAMetrics()
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)

	tokenID := "TOKEN-m13-tamper"
	cfg := make3of5Config()
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := cfg.Signers

	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)
	require.NoError(t, engine.ApproveRecoveryOperation(signers[1], proposalID))
	require.NoError(t, engine.ApproveRecoveryOperation(signers[2], proposalID))

	// Simulate an attacker (or buggy migration) swapping the stored
	// payload with a semantically different envelope — same token,
	// but a distinct operation list. The EnvelopeHash field on the
	// proposal still reflects the ORIGINAL, propose-time operations.
	tampered := makeTestRecoveryEnvelope(tokenID)
	tampered.Operations[0].Body = []byte(`{"transferable":false}`)
	tamperedPayload, err := serializeGovernanceEnvelope(&tampered)
	require.NoError(t, err)
	stored, err := store.GetProposal(proposalID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	stored.EnvelopePayload = tamperedPayload
	require.NoError(t, store.SaveProposal(stored))

	// Execute must reject with the dedicated hash-mismatch error.
	_, err = engine.ExecuteRecoveryOperation(signers[3], proposalID, 1010)
	require.ErrorIs(t, err, errDRWAGovernanceEnvelopeHashMismatch)

	// Metric fired exactly once.
	metrics := snapshotDRWAMetrics()
	require.Equal(
		t,
		uint64(1),
		metrics[drwaMetricGovernanceEnvelopeHashMismatch],
		"one envelope-hash mismatch must be reported",
	)

	// Proposal not executed.
	persisted, err := store.GetProposal(proposalID)
	require.NoError(t, err)
	require.False(t, persisted.Executed)
}

// TestM13AcceptsUnalteredEnvelope guards against false positives: the
// normal execute path whose payload is byte-identical to propose time
// MUST succeed without firing the mismatch metric.
func TestM13AcceptsUnalteredEnvelope(t *testing.T) {
	resetDRWAMetrics()
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)

	tokenID := "TOKEN-m13-untouched"
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

	metrics := snapshotDRWAMetrics()
	require.Equal(
		t,
		uint64(0),
		metrics[drwaMetricGovernanceEnvelopeHashMismatch],
		"untouched payload must not trigger the mismatch metric",
	)
}

// edge-cases (empty inputs, all-stale, all-valid) are locked in even if
// the calling code changes.
// TestB10FilterHelperEdgeCases exercises the filter helper directly so
// edge cases (empty inputs, all-stale, all-valid, mixed) are locked
// in even if the calling code in `ExecuteRecoveryOperation` later
// changes shape.
func TestB10FilterHelperEdgeCases(t *testing.T) {
	signers := makeSigners(3)
	outsider := []byte{0xFF, 0xFE}

	// All valid.
	valid, dropped := filterCurrentSignerApprovals(signers, signers)
	require.Len(t, valid, 3)
	require.Equal(t, uint32(0), dropped)

	// All stale.
	valid, dropped = filterCurrentSignerApprovals([][]byte{outsider, outsider}, signers)
	require.Len(t, valid, 0)
	require.Equal(t, uint32(2), dropped)

	// Mixed.
	mixed := [][]byte{signers[0], outsider, signers[1]}
	valid, dropped = filterCurrentSignerApprovals(mixed, signers)
	require.Len(t, valid, 2)
	require.Equal(t, uint32(1), dropped)
	require.True(t, bytes.Equal(valid[0], signers[0]))
	require.True(t, bytes.Equal(valid[1], signers[1]))

	// Empty approvals.
	valid, dropped = filterCurrentSignerApprovals(nil, signers)
	require.Len(t, valid, 0)
	require.Equal(t, uint32(0), dropped)

	// Empty signer set — all stale.
	valid, dropped = filterCurrentSignerApprovals(signers, nil)
	require.Len(t, valid, 0)
	require.Equal(t, uint32(3), dropped)
}

// ── M-14 (R-01-F-05) prune-after-retention tests ────────────────────

// TestM14ExecutedProposalEligibleAfterRetention verifies the happy
// path: an executed proposal becomes eligible for pruning exactly
// when `currentBlock >= ExecutedAtBlock + drwaGovernancePruneRetentionBlocks`.
// Pruning removes the full proposal payload but preserves the compact
// audit record.
func TestM14ExecutedProposalEligibleAfterRetention(t *testing.T) {
	resetDRWAMetrics()
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)

	tokenID := "TOKEN-m14-exec"
	cfg := make3of5Config()
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := cfg.Signers

	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)
	require.NoError(t, engine.ApproveRecoveryOperation(signers[1], proposalID))
	require.NoError(t, engine.ApproveRecoveryOperation(signers[2], proposalID))

	executedAt := uint64(1010)
	_, err = engine.ExecuteRecoveryOperation(signers[3], proposalID, executedAt)
	require.NoError(t, err)

	// Audit record was written at execute time.
	audit, err := store.GetAuditRecord(proposalID)
	require.NoError(t, err)
	require.NotNil(t, audit)
	require.Equal(t, executedAt, audit.ExecutedAtBlock)
	require.Equal(t, uint32(3), audit.ApprovalCount)
	require.Equal(t, "executed", audit.Outcome)

	// One block shy of retention window → NOT eligible.
	err = engine.PruneProposal(proposalID, executedAt+drwaGovernancePruneRetentionBlocks-1)
	require.ErrorIs(t, err, errDRWAGovernancePruneNotEligible)

	// Exactly at retention window → eligible.
	err = engine.PruneProposal(proposalID, executedAt+drwaGovernancePruneRetentionBlocks)
	require.NoError(t, err)

	// Proposal payload is gone; audit record survives.
	stored, err := store.GetProposal(proposalID)
	require.NoError(t, err)
	require.Nil(t, stored, "proposal payload must be deleted after prune")

	surviving, err := store.GetAuditRecord(proposalID)
	require.NoError(t, err)
	require.NotNil(t, surviving, "audit record must survive prune for forensic trail")
	require.Equal(t, proposalID, surviving.ProposalID)
	require.Equal(t, uint32(3), surviving.ApprovalCount)

	// Metric fired exactly once.
	metrics := snapshotDRWAMetrics()
	require.Equal(
		t,
		uint64(1),
		metrics[drwaMetricGovernanceProposalPruned],
		"prune metric must fire exactly once",
	)
}

// TestM14ExpiredProposalEligibleAfterRetention verifies the expired-
// but-never-executed path: a proposal that reached its TTL expiry
// still carries storage cost until the retention window elapses past
// expiry, after which it can be pruned.
func TestM14ExpiredProposalEligibleAfterRetention(t *testing.T) {
	resetDRWAMetrics()
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)

	tokenID := "TOKEN-m14-expired"
	cfg := make3of5Config()
	cfg.ProposalTTL = 100
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := cfg.Signers

	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)
	// Do NOT reach quorum. Proposal will expire.

	// TTL expires at block 1100. Retention window begins there.
	// Before retention: not eligible.
	err = engine.PruneProposal(proposalID, 1100+drwaGovernancePruneRetentionBlocks-1)
	require.ErrorIs(t, err, errDRWAGovernancePruneNotEligible)

	// At retention boundary: eligible.
	err = engine.PruneProposal(proposalID, 1100+drwaGovernancePruneRetentionBlocks)
	require.NoError(t, err)

	stored, err := store.GetProposal(proposalID)
	require.NoError(t, err)
	require.Nil(t, stored)
}

// TestM14PendingProposalNotEligible verifies that a proposal that is
// neither executed nor expired cannot be pruned — active governance
// items must never be silently deleted.
func TestM14PendingProposalNotEligible(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)

	tokenID := "TOKEN-m14-pending"
	cfg := make3of5Config()
	cfg.ProposalTTL = 100
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := cfg.Signers

	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)

	// Still within TTL and not executed.
	err = engine.PruneProposal(proposalID, 1050)
	require.ErrorIs(t, err, errDRWAGovernancePruneNotEligible)
}

// TestM14PruneMissingProposal verifies that attempting to prune an
// unknown proposal returns a clear `errDRWAGovernanceProposalNotFound`
// rather than silently succeeding.
func TestM14PruneMissingProposal(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)

	var fakeID [32]byte
	fakeID[0] = 0xAA

	err := engine.PruneProposal(fakeID, 1_000_000)
	require.ErrorIs(t, err, errDRWAGovernanceProposalNotFound)
}

// TestM14PruneNilStore guards the defensive early-return in
// PruneProposal — an engine constructed with a nil store must return
// `errDRWAGovernanceNilStore` rather than nil-deref panic.
func TestM14PruneNilStore(t *testing.T) {
	engine := NewDRWAGovernanceEngine(nil)
	var id [32]byte
	err := engine.PruneProposal(id, 1_000_000)
	require.ErrorIs(t, err, errDRWAGovernanceNilStore)
}

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

func TestHandleDRWAGovernanceOperationRejectsExpiredApprove(t *testing.T) {
	store := newMockGovernanceStore()
	engine := NewDRWAGovernanceEngine(store)
	tokenID := "TOKEN-handle-expired-approve"
	cfg := make3of5Config()
	cfg.ProposalTTL = 100
	require.NoError(t, store.SaveGovernanceConfig(tokenID, cfg))

	adapter := &mockGovernanceCapableAdapter{
		mockDRWASyncStateAdapter: newMockDRWASyncStateAdapter(),
		engine:                   engine,
		currentBlock:             1101,
	}

	envelope := makeTestRecoveryEnvelope(tokenID)
	signers := cfg.Signers
	proposalID, err := engine.ProposeRecoveryOperation(signers[0], envelope, 1000)
	require.NoError(t, err)

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

	result, err := handleDRWAGovernanceOperation(adapter, approveEnvelope, signers[1])
	require.Nil(t, result)
	require.ErrorIs(t, err, errDRWAGovernanceProposalExpired)

	stored, err := store.GetProposal(proposalID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.Len(t, stored.Approvals, 1)
}
