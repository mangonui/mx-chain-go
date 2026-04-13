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

func (s *drwaGovernanceTrieStore) SaveGovernanceConfig(tokenID string, cfg *DRWAGovernanceConfig) error {
	if cfg == nil {
		return errDRWAGovernanceNilStore
	}

	systemAccount, err := s.getSystemAccount()
	if err != nil {
		return err
	}

	payload, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	key := buildDRWAGovernanceConfigKey(tokenID)
	if err = systemAccount.AccountDataHandler().SaveKeyValue(key, payload); err != nil {
		return err
	}

	return s.accounts.SaveAccount(systemAccount)
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
