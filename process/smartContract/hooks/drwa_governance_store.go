package hooks

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-go/state"
)

const (
	// drwaGovernanceConfigPrefix is the storage key prefix for governance config.
	// Full key: DRWA_GOV_<hex(tokenID)>
	drwaGovernanceConfigPrefix = "DRWA_GOV_"

	// drwaGovernanceProposalPrefix is the storage key prefix for proposals.
	// Full key: DRWA_PROPOSAL_<hex(proposalID)>
	drwaGovernanceProposalPrefix = "DRWA_PROPOSAL_"

	// drwaGovernanceAuditPrefix is the storage key prefix for the M-14
	// compact audit records written on successful proposal execution
	// and preserved across `PruneProposal`.
	// Full key: DRWA_GOV_AUDIT_<hex(proposalID)>
	drwaGovernanceAuditPrefix = "DRWA_GOV_AUDIT_"
)

// drwaGovernanceTrieStore implements DRWAGovernanceStore using the same
// trie/account storage pattern as the existing DRWA sync adapter. All
// governance state is persisted on the system account.
type drwaGovernanceTrieStore struct {
	accounts state.AccountsAdapter
}

// newDRWAGovernanceTrieStore creates a governance store backed by the
// provided AccountsAdapter. Returns an error if accounts is nil.
func newDRWAGovernanceTrieStore(accounts state.AccountsAdapter) (*drwaGovernanceTrieStore, error) {
	if accounts == nil || accounts.IsInterfaceNil() {
		return nil, ErrNilDRWAAccountsAdapter
	}
	return &drwaGovernanceTrieStore{accounts: accounts}, nil
}

func buildDRWAGovernanceConfigKey(tokenID string) []byte {
	return []byte(drwaGovernanceConfigPrefix + hex.EncodeToString([]byte(tokenID)))
}

func buildDRWAGovernanceProposalKey(proposalID [32]byte) []byte {
	return []byte(drwaGovernanceProposalPrefix + hex.EncodeToString(proposalID[:]))
}

func buildDRWAGovernanceAuditKey(proposalID [32]byte) []byte {
	return []byte(drwaGovernanceAuditPrefix + hex.EncodeToString(proposalID[:]))
}

func cloneDRWAGovernanceConfig(cfg *DRWAGovernanceConfig) *DRWAGovernanceConfig {
	if cfg == nil {
		return nil
	}

	cloned := &DRWAGovernanceConfig{
		Version:     cfg.Version,
		Threshold:   cfg.Threshold,
		ProposalTTL: cfg.ProposalTTL,
		MaxSigners:  cfg.MaxSigners,
	}
	if len(cfg.Signers) > 0 {
		cloned.Signers = make([][]byte, len(cfg.Signers))
		for i, signer := range cfg.Signers {
			cloned.Signers[i] = append([]byte(nil), signer...)
		}
	}
	if cfg.RolloutThresholds != nil {
		rollout := *cfg.RolloutThresholds
		cloned.RolloutThresholds = &rollout
	}

	return cloned
}

func (s *drwaGovernanceTrieStore) GetGovernanceConfig(tokenID string) (*DRWAGovernanceConfig, error) {
	systemAccount, err := s.getSystemAccount()
	if err != nil {
		return nil, err
	}

	key := buildDRWAGovernanceConfigKey(tokenID)
	value, _, err := systemAccount.AccountDataHandler().RetrieveValue(key)
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		return nil, nil
	}

	cfg := &DRWAGovernanceConfig{}
	if err = json.Unmarshal(value, cfg); err != nil {
		return nil, fmt.Errorf("corrupt governance config for token %s: %w", tokenID, err)
	}

	return cfg, nil
}

func (s *drwaGovernanceTrieStore) SaveGovernanceConfig(tokenID string, cfg *DRWAGovernanceConfig, expectedVersion ...uint64) error {
	if cfg == nil {
		return errDRWAGovernanceNilStore
	}

	systemAccount, err := s.getSystemAccount()
	if err != nil {
		return err
	}

	key := buildDRWAGovernanceConfigKey(tokenID)
	currentVersion := uint64(0)
	value, _, err := systemAccount.AccountDataHandler().RetrieveValue(key)
	if err != nil {
		return err
	}
	if len(value) > 0 {
		current := &DRWAGovernanceConfig{}
		if err = json.Unmarshal(value, current); err != nil {
			return fmt.Errorf("corrupt governance config for token %s: %w", tokenID, err)
		}
		currentVersion = current.Version
	}

	matchVersion := cfg.Version
	if len(expectedVersion) > 0 {
		matchVersion = expectedVersion[0]
	}
	if matchVersion != currentVersion {
		return errDRWAGovernanceConfigVersionMismatch
	}

	toStore := cloneDRWAGovernanceConfig(cfg)
	toStore.Version = currentVersion + 1
	payload, err := json.Marshal(toStore)
	if err != nil {
		return err
	}

	if err = systemAccount.AccountDataHandler().SaveKeyValue(key, payload); err != nil {
		return err
	}
	cfg.Version = toStore.Version

	return s.accounts.SaveAccount(systemAccount)
}

func (s *drwaGovernanceTrieStore) GetRolloutThresholdConfig(tokenID string) (*drwaRolloutThresholdConfig, error) {
	cfg, err := s.GetGovernanceConfig(tokenID)
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg.RolloutThresholds == nil {
		return nil, nil
	}

	rollout := *cfg.RolloutThresholds
	return &rollout, nil
}

func (s *drwaGovernanceTrieStore) GetProposal(proposalID [32]byte) (*DRWAGovernanceProposal, error) {
	systemAccount, err := s.getSystemAccount()
	if err != nil {
		return nil, err
	}

	key := buildDRWAGovernanceProposalKey(proposalID)
	value, _, err := systemAccount.AccountDataHandler().RetrieveValue(key)
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		return nil, nil
	}

	proposal := &DRWAGovernanceProposal{}
	if err = json.Unmarshal(value, proposal); err != nil {
		return nil, fmt.Errorf("corrupt governance proposal %x: %w", proposalID, err)
	}

	return proposal, nil
}

func (s *drwaGovernanceTrieStore) SaveProposal(proposal *DRWAGovernanceProposal) error {
	if proposal == nil {
		return errDRWAGovernanceProposalNotFound
	}

	systemAccount, err := s.getSystemAccount()
	if err != nil {
		return err
	}

	payload, err := json.Marshal(proposal)
	if err != nil {
		return err
	}

	key := buildDRWAGovernanceProposalKey(proposal.ProposalID)
	if err = systemAccount.AccountDataHandler().SaveKeyValue(key, payload); err != nil {
		return err
	}

	return s.accounts.SaveAccount(systemAccount)
}

func (s *drwaGovernanceTrieStore) DeleteProposal(proposalID [32]byte) error {
	systemAccount, err := s.getSystemAccount()
	if err != nil {
		return err
	}

	key := buildDRWAGovernanceProposalKey(proposalID)
	// Write empty value to effectively delete. The trie treats zero-length
	// values as absent on subsequent reads.
	if err = systemAccount.AccountDataHandler().SaveKeyValue(key, nil); err != nil {
		return err
	}

	return s.accounts.SaveAccount(systemAccount)
}

// M-14: persist the compact audit record keyed by proposal ID. This
// record survives `PruneProposal` so the forensic trail outlives the
// full proposal payload.
func (s *drwaGovernanceTrieStore) SaveAuditRecord(record *DRWAGovernanceAuditRecord) error {
	if record == nil {
		return errDRWAGovernanceProposalNotFound
	}

	systemAccount, err := s.getSystemAccount()
	if err != nil {
		return err
	}

	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}

	key := buildDRWAGovernanceAuditKey(record.ProposalID)
	if err = systemAccount.AccountDataHandler().SaveKeyValue(key, payload); err != nil {
		return err
	}

	return s.accounts.SaveAccount(systemAccount)
}

// M-14: retrieve a previously-saved audit record. Returns (nil, nil)
// when no record exists so callers can distinguish "never executed"
// from "transport error."
func (s *drwaGovernanceTrieStore) GetAuditRecord(proposalID [32]byte) (*DRWAGovernanceAuditRecord, error) {
	systemAccount, err := s.getSystemAccount()
	if err != nil {
		return nil, err
	}

	key := buildDRWAGovernanceAuditKey(proposalID)
	value, _, err := systemAccount.AccountDataHandler().RetrieveValue(key)
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		return nil, nil
	}

	record := &DRWAGovernanceAuditRecord{}
	if err = json.Unmarshal(value, record); err != nil {
		return nil, fmt.Errorf("corrupt governance audit record %x: %w", proposalID, err)
	}

	return record, nil
}

func (s *drwaGovernanceTrieStore) getSystemAccount() (vmcommon.UserAccountHandler, error) {
	accountHandler, err := s.accounts.LoadAccount(core.SystemAccountAddress)
	if err != nil {
		return nil, err
	}

	userAccount, ok := accountHandler.(vmcommon.UserAccountHandler)
	if !ok {
		return nil, fmt.Errorf("system account is not UserAccountHandler")
	}

	return userAccount, nil
}
