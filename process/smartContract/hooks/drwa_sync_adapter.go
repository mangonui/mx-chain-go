package hooks

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"
	// F-023: keccak import removed — now using drwaKeccakPool from drwa_sync.go
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	builtInFunctions "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
)

// drwaBlockNonceProvider supplies the current block nonce to the state adapter.
// Implemented by BlockChainHookImpl; nil in test contexts where time-lock is
// not under test.
type drwaBlockNonceProvider interface {
	CurrentNonce() uint64
}

type drwaHookStateAdapter struct {
	accounts         state.AccountsAdapter
	nonceProvider    drwaBlockNonceProvider
	governanceEngine *DRWAGovernanceEngine
}

const (
	drwaStoredValueBinaryV1       byte   = 0x01
	drwaStoredValueNilBodyLength  uint32 = ^uint32(0)
	drwaStoredValueBinaryHeaderLen       = 1 + 8 + 4
)

func newDRWAHookStateAdapter(accounts state.AccountsAdapter) (*drwaHookStateAdapter, error) {
	if accounts == nil || accounts.IsInterfaceNil() {
		return nil, ErrNilDRWAAccountsAdapter
	}

	governanceStore, err := newDRWAGovernanceTrieStore(accounts)
	if err != nil {
		return nil, err
	}

	return &drwaHookStateAdapter{
		accounts:         accounts,
		governanceEngine: NewDRWAGovernanceEngine(governanceStore),
	}, nil
}

func ProvisionDRWAAuthorizedCaller(accounts state.AccountsAdapter, domain string, address []byte, version uint64) error {
	adapter, err := newDRWAHookStateAdapter(accounts)
	if err != nil {
		return err
	}

	return adapter.SetAuthorizedCallerAddressVersioned(domain, address, version)
}

// IsInterfaceNil returns true if there is no value under the interface
func (a *drwaHookStateAdapter) IsInterfaceNil() bool {
	return a == nil
}

// buildDRWATokenPolicyKey delegates to the canonical key builder in mx-chain-vm-common-go.
var buildDRWATokenPolicyKey = builtInFunctions.BuildDRWATokenPolicyKey

// buildDRWAHolderMirrorKey delegates to the canonical key builder in mx-chain-vm-common-go.
var buildDRWAHolderMirrorKey = builtInFunctions.BuildDRWAHolderMirrorKey

// buildDRWAHolderProfileKey delegates to the canonical key builder in mx-chain-vm-common-go.
var buildDRWAHolderProfileKey = builtInFunctions.BuildDRWAHolderProfileKey

// buildDRWAHolderAuditorAuthorizationKey delegates to the canonical key builder in mx-chain-vm-common-go.
var buildDRWAHolderAuditorAuthorizationKey = builtInFunctions.BuildDRWAHolderAuditorAuthorizationKey

var buildDRWAAssetRecordKey = builtInFunctions.BuildDRWAAssetRecordKey
var buildDRWAActiveKey = builtInFunctions.BuildDRWAActiveKey

func buildDRWAAuthorizedCallerKey(domain string) []byte {
	return []byte("drwa:auth:" + domain)
}

// drwaSyncEvidencePrefix is the storage namespace for all DRWA audit evidence.
// Using a dedicated prefix keeps evidence keys out of the token-policy namespace
// and allows targeted enumeration during forensic inspection.
const drwaSyncEvidencePrefix = "drwa:evidence:"

func buildDRWARecoveryEvidenceKey(tokenIdentifier []byte) []byte {
	return []byte(drwaSyncEvidencePrefix + hex.EncodeToString(tokenIdentifier) + ":recovery:latest")
}

func buildDRWARecoveryEvidenceHistoryKey(tokenIdentifier []byte, payloadHash []byte) []byte {
	return []byte(fmt.Sprintf("%s%s:recovery:history:%x", drwaSyncEvidencePrefix, hex.EncodeToString(tokenIdentifier), payloadHash))
}

func buildDRWARolloutEvidenceKey(tokenIdentifier []byte) []byte {
	return []byte(drwaSyncEvidencePrefix + hex.EncodeToString(tokenIdentifier) + ":rollout:latest")
}

func buildDRWARolloutEvidenceHistoryKey(tokenIdentifier []byte, payloadHash []byte) []byte {
	return []byte(fmt.Sprintf("%s%s:rollout:history:%x", drwaSyncEvidencePrefix, hex.EncodeToString(tokenIdentifier), payloadHash))
}

func buildDRWARolloutVerificationKey(tokenIdentifier []byte) []byte {
	return []byte(drwaSyncEvidencePrefix + hex.EncodeToString(tokenIdentifier) + ":rollout:verification:latest")
}

func buildDRWARolloutVerificationHistoryKey(tokenIdentifier []byte, payloadHash []byte) []byte {
	return []byte(fmt.Sprintf("%s%s:rollout:verification:history:%x", drwaSyncEvidencePrefix, hex.EncodeToString(tokenIdentifier), payloadHash))
}

func buildDRWAHolderDeleteAuditKey(tokenIdentifier []byte, address []byte, version uint64) []byte {
	return []byte(fmt.Sprintf("%s%s:holder-delete:%s:%d", drwaSyncEvidencePrefix, hex.EncodeToString(tokenIdentifier), hex.EncodeToString(address), version))
}

type drwaDeleteAuditRecord struct {
	TokenID string `json:"token_id"`
	Holder  string `json:"holder"`
	Version uint64 `json:"version"`
}

func (d *drwaHookStateAdapter) GetTokenPolicyVersion(tokenID string) (uint64, error) {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return 0, err
	}

	storedValue, err := d.readStoredValue(systemAccount, buildDRWATokenPolicyKey([]byte(tokenID)))
	if err != nil || storedValue == nil {
		return 0, err
	}

	return storedValue.Version, nil
}

func (d *drwaHookStateAdapter) GetTokenPolicyStored(tokenID string) (*drwaSyncStoredValue, error) {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return nil, err
	}

	return d.readStoredValue(systemAccount, buildDRWATokenPolicyKey([]byte(tokenID)))
}

func (d *drwaHookStateAdapter) GetAssetRecordVersion(tokenID string) (uint64, error) {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return 0, err
	}

	storedValue, err := d.readStoredValue(systemAccount, buildDRWAAssetRecordKey([]byte(tokenID)))
	if err != nil || storedValue == nil {
		return 0, err
	}

	return storedValue.Version, nil
}

func (d *drwaHookStateAdapter) GetHolderMirrorVersion(tokenID, holder string) (uint64, error) {
	holderAccount, err := d.getUserAccount([]byte(holder))
	if err != nil {
		return 0, err
	}

	storedValue, err := d.readStoredValue(holderAccount, buildDRWAHolderMirrorKey([]byte(tokenID), []byte(holder)))
	if err != nil || storedValue == nil {
		return 0, err
	}

	return storedValue.Version, nil
}

func (d *drwaHookStateAdapter) GetHolderMirrorStored(tokenID, holder string) (*drwaSyncStoredValue, error) {
	holderAccount, err := d.getUserAccount([]byte(holder))
	if err != nil {
		return nil, err
	}

	return d.readStoredValue(holderAccount, buildDRWAHolderMirrorKey([]byte(tokenID), []byte(holder)))
}

func (d *drwaHookStateAdapter) GetHolderProfileVersion(holder string) (uint64, error) {
	holderAccount, err := d.getUserAccount([]byte(holder))
	if err != nil {
		return 0, err
	}

	storedValue, err := d.readStoredValue(holderAccount, buildDRWAHolderProfileKey([]byte(holder)))
	if err != nil || storedValue == nil {
		return 0, err
	}

	return storedValue.Version, nil
}

func (d *drwaHookStateAdapter) GetHolderAuditorAuthorizationVersion(tokenID, holder string) (uint64, error) {
	holderAccount, err := d.getUserAccount([]byte(holder))
	if err != nil {
		return 0, err
	}

	storedValue, err := d.readStoredValue(holderAccount, buildDRWAHolderAuditorAuthorizationKey([]byte(tokenID), []byte(holder)))
	if err != nil || storedValue == nil {
		return 0, err
	}

	return storedValue.Version, nil
}

func (d *drwaHookStateAdapter) GetAuthorizedCallerAddress(domain string) ([]byte, error) {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return nil, err
	}

	value, _, err := d.retrieveValueAllowingFreshNilTrie(systemAccount, buildDRWAAuthorizedCallerKey(domain))
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		return nil, nil
	}

	record := &drwaAuthorizedCallerRecord{}
	if err = json.Unmarshal(value, record); err == nil && len(record.Address) > 0 {
		return append([]byte(nil), record.Address...), nil
	}

	return append([]byte(nil), value...), nil
}

func (d *drwaHookStateAdapter) GetAuthorizedCallerAddressVersioned(domain string) ([]byte, uint64, error) {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return nil, 0, err
	}

	value, _, err := d.retrieveValueAllowingFreshNilTrie(systemAccount, buildDRWAAuthorizedCallerKey(domain))
	if err != nil {
		return nil, 0, err
	}
	if len(value) == 0 {
		return nil, 0, nil
	}

	record := &drwaAuthorizedCallerRecord{}
	if err = json.Unmarshal(value, record); err == nil && len(record.Address) > 0 {
		return append([]byte(nil), record.Address...), record.Version, nil
	}

	return append([]byte(nil), value...), 0, nil
}

func (d *drwaHookStateAdapter) PutAuthorizedCallerAddress(domain string, address []byte) error {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}

	err = systemAccount.AccountDataHandler().SaveKeyValue(buildDRWAAuthorizedCallerKey(domain), append([]byte(nil), address...))
	if err != nil {
		return err
	}

	return d.accounts.SaveAccount(systemAccount)
}

func (d *drwaHookStateAdapter) SetDRWAActive(tokenID string) error {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}

	err = systemAccount.AccountDataHandler().SaveKeyValue(buildDRWAActiveKey([]byte(tokenID)), []byte{1})
	if err != nil {
		return err
	}

	return d.accounts.SaveAccount(systemAccount)
}

func (d *drwaHookStateAdapter) SetAuthorizedCallerAddressVersioned(domain string, address []byte, version uint64) error {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(&drwaAuthorizedCallerRecord{
		Version: version,
		Address: append([]byte(nil), address...),
	})
	if err != nil {
		return err
	}

	if err = systemAccount.AccountDataHandler().SaveKeyValue(buildDRWAAuthorizedCallerKey(domain), payload); err != nil {
		return err
	}

	return d.accounts.SaveAccount(systemAccount)
}

func (d *drwaHookStateAdapter) GetGovernanceEngine() *DRWAGovernanceEngine {
	return d.governanceEngine
}

func (d *drwaHookStateAdapter) GetCurrentBlockNonceForGovernance() (uint64, error) {
	return d.GetCurrentBlockNonce()
}

func (d *drwaHookStateAdapter) PutTokenPolicyBody(tokenID string, version uint64, body []byte) error {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}

	return d.writeStoredValue(systemAccount, buildDRWATokenPolicyKey([]byte(tokenID)), version, body)
}

func (d *drwaHookStateAdapter) PutAssetRecordBody(tokenID string, version uint64, body []byte) error {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}

	return d.writeStoredValue(systemAccount, buildDRWAAssetRecordKey([]byte(tokenID)), version, body)
}

func (d *drwaHookStateAdapter) PutHolderMirrorBody(tokenID, holder string, version uint64, body []byte) error {
	holderAccount, err := d.getUserAccount([]byte(holder))
	if err != nil {
		return err
	}

	return d.writeStoredValue(holderAccount, buildDRWAHolderMirrorKey([]byte(tokenID), []byte(holder)), version, body)
}

func (d *drwaHookStateAdapter) PutHolderProfileBody(holder string, version uint64, body []byte) error {
	holderAccount, err := d.getUserAccount([]byte(holder))
	if err != nil {
		return err
	}

	return d.writeStoredValue(holderAccount, buildDRWAHolderProfileKey([]byte(holder)), version, body)
}

func (d *drwaHookStateAdapter) PutHolderAuditorAuthorizationBody(tokenID, holder string, version uint64, body []byte) error {
	holderAccount, err := d.getUserAccount([]byte(holder))
	if err != nil {
		return err
	}

	return d.writeStoredValue(
		holderAccount,
		buildDRWAHolderAuditorAuthorizationKey([]byte(tokenID), []byte(holder)),
		version,
		body,
	)
}

func (d *drwaHookStateAdapter) DeleteHolderMirror(tokenID, holder string, version uint64) error {
	holderAccount, err := d.getUserAccount([]byte(holder))
	if err != nil {
		return err
	}

	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}

	// Write tombstone in the canonical stored-value wrapper with nil body.
	// Previous implementations used raw 8-byte big-endian versions or JSON;
	// readStoredValue remains backward-compatible with both older formats.
	tombstonePayload, encodeErr := encodeDRWASyncStoredValue(&drwaSyncStoredValue{
		Version: version,
		Body:    nil,
	})
	if encodeErr != nil {
		return encodeErr
	}
	err = holderAccount.AccountDataHandler().SaveKeyValue(buildDRWAHolderMirrorKey([]byte(tokenID), []byte(holder)), tombstonePayload)
	if err != nil {
		return err
	}

	// Prepare audit record on the system account BEFORE any SaveAccount call.
	// Both writes must succeed before either account is persisted, ensuring
	// atomicity: the holder tombstone and the audit record are committed together
	// or not at all (SH-3 fix).
	auditPayload, err := json.Marshal(&drwaDeleteAuditRecord{
		TokenID: tokenID,
		Holder:  holder,
		Version: version,
	})
	if err != nil {
		return err
	}
	err = systemAccount.AccountDataHandler().SaveKeyValue(buildDRWAHolderDeleteAuditKey([]byte(tokenID), []byte(holder), version), auditPayload)
	if err != nil {
		return err
	}

	// F-019: Wrap double SaveAccount in journal snapshot. If the second fails,
	// revert the first to maintain atomicity of holder tombstone + audit record.
	snapshot := d.accounts.JournalLen()

	err = d.accounts.SaveAccount(holderAccount)
	if err != nil {
		return err
	}

	err = d.accounts.SaveAccount(systemAccount)
	if err != nil {
		revertErr := d.accounts.RevertToSnapshot(snapshot)
		if revertErr != nil {
			recordDRWAMetric(drwaMetricDeleteHolderRevertFailure)
			return fmt.Errorf("DRWA DeleteHolderMirror: second SaveAccount failed (%w) and revert also failed (%v)", err, revertErr)
		}
		recordDRWAMetric(drwaMetricDeleteHolderRevertFailure)
		return err
	}

	return nil
}

func (d *drwaHookStateAdapter) PersistRecoveryEvidence(tokenID string, payload []byte) error {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}

	return d.persistArtifact(systemAccount, buildDRWARecoveryEvidenceKey([]byte(tokenID)), buildDRWARecoveryEvidenceHistoryKey, tokenID, payload)
}

func (d *drwaHookStateAdapter) PersistRolloutEvidence(tokenID string, payload []byte) error {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}

	return d.persistArtifact(systemAccount, buildDRWARolloutEvidenceKey([]byte(tokenID)), buildDRWARolloutEvidenceHistoryKey, tokenID, payload)
}

func (d *drwaHookStateAdapter) PersistRolloutVerification(tokenID string, payload []byte) error {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}

	return d.persistArtifact(systemAccount, buildDRWARolloutVerificationKey([]byte(tokenID)), buildDRWARolloutVerificationHistoryKey, tokenID, payload)
}

func (d *drwaHookStateAdapter) Snapshot() int {
	return d.accounts.JournalLen()
}

func (d *drwaHookStateAdapter) Rollback(snapshot int) error {
	return d.accounts.RevertToSnapshot(snapshot)
}

func (d *drwaHookStateAdapter) readStoredValue(account vmcommon.UserAccountHandler, key []byte) (*drwaSyncStoredValue, error) {
	value, _, err := d.retrieveValueAllowingFreshNilTrie(account, key)
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		return nil, nil
	}

	// Backward-compat: handle legacy 8-byte binary tombstones written before
	// wrapper formats were introduced. These are big-endian uint64 version
	// with nil body.
	if len(value) == 8 {
		ver := uint64(value[0])<<56 | uint64(value[1])<<48 | uint64(value[2])<<40 |
			uint64(value[3])<<32 | uint64(value[4])<<24 | uint64(value[5])<<16 |
			uint64(value[6])<<8 | uint64(value[7])
		return &drwaSyncStoredValue{Version: ver, Body: nil}, nil
	}

	if value[0] == drwaStoredValueBinaryV1 {
		return decodeDRWASyncStoredValue(value)
	}

	storedValue := &drwaSyncStoredValue{}
	err = json.Unmarshal(value, storedValue)
	if err != nil {
		return nil, err
	}

	return storedValue, nil
}

func (d *drwaHookStateAdapter) retrieveValueAllowingFreshNilTrie(account vmcommon.UserAccountHandler, key []byte) ([]byte, uint32, error) {
	value, trieDepth, err := account.AccountDataHandler().RetrieveValue(key)
	if err != nil {
		// Fresh accounts and freshly provisioned system-account mirrors can
		// legitimately have no materialized data trie yet. DRWA read paths treat
		// that as "missing value" and let the first write materialize the trie.
		if errors.Is(err, state.ErrNilTrie) {
			return nil, 0, nil
		}
		return nil, trieDepth, err
	}

	return value, trieDepth, nil
}

func (d *drwaHookStateAdapter) writeStoredValue(account vmcommon.UserAccountHandler, key []byte, version uint64, body []byte) error {
	payload, err := encodeDRWASyncStoredValue(&drwaSyncStoredValue{
		Version: version,
		Body:    body,
	})
	if err != nil {
		return err
	}

	err = account.AccountDataHandler().SaveKeyValue(key, payload)
	if err != nil {
		return err
	}

	return d.accounts.SaveAccount(account)
}

func encodeDRWASyncStoredValue(stored *drwaSyncStoredValue) ([]byte, error) {
	if stored == nil {
		return nil, errors.New("nil DRWA stored value")
	}
	if len(stored.Body) > drwaSyncMaxFieldBytes {
		return nil, fmt.Errorf("DRWA stored body exceeds %d bytes", drwaSyncMaxFieldBytes)
	}

	bodyLen := uint32(len(stored.Body))
	if stored.Body == nil {
		bodyLen = drwaStoredValueNilBodyLength
	}

	payload := make([]byte, drwaStoredValueBinaryHeaderLen+len(stored.Body))
	payload[0] = drwaStoredValueBinaryV1
	binary.BigEndian.PutUint64(payload[1:9], stored.Version)
	binary.BigEndian.PutUint32(payload[9:13], bodyLen)
	copy(payload[13:], stored.Body)

	return payload, nil
}

func decodeDRWASyncStoredValue(value []byte) (*drwaSyncStoredValue, error) {
	if len(value) < drwaStoredValueBinaryHeaderLen {
		return nil, errors.New("DRWA stored value binary payload too short")
	}
	if value[0] != drwaStoredValueBinaryV1 {
		return nil, fmt.Errorf("unsupported DRWA stored value format: %d", value[0])
	}

	version := binary.BigEndian.Uint64(value[1:9])
	bodyLen := binary.BigEndian.Uint32(value[9:13])

	if bodyLen == drwaStoredValueNilBodyLength {
		if len(value) != drwaStoredValueBinaryHeaderLen {
			return nil, errors.New("DRWA tombstone payload has trailing bytes")
		}
		return &drwaSyncStoredValue{Version: version, Body: nil}, nil
	}

	expectedLen := drwaStoredValueBinaryHeaderLen + int(bodyLen)
	if len(value) != expectedLen {
		return nil, fmt.Errorf("DRWA stored value length mismatch: expected=%d got=%d", expectedLen, len(value))
	}

	body := make([]byte, int(bodyLen))
	copy(body, value[13:])

	return &drwaSyncStoredValue{
		Version: version,
		Body:    body,
	}, nil
}

// getUserAccount loads an account from the shard-local AccountsAdapter.
// The adapter only has access to accounts in the current shard's trie, so cross-shard
// addresses will return an error from LoadAccount. The nil-account guard below is a
// defensive check: if LoadAccount succeeds but returns nil, it indicates a cross-shard
// address leaked past the adapter boundary — we record a metric and return an explicit error.
func (d *drwaHookStateAdapter) getUserAccount(address []byte) (vmcommon.UserAccountHandler, error) {
	accountHandler, err := d.accounts.LoadAccount(address)
	if err != nil {
		return nil, err
	}

	if accountHandler == nil {
		recordDRWAMetric(drwaMetricSyncAdapterCrossShardAttempt)
		return nil, fmt.Errorf("DRWA_ACCOUNT_NOT_IN_SHARD: address %s not found in local shard state", hex.EncodeToString(address))
	}

	userAccount, ok := accountHandler.(vmcommon.UserAccountHandler)
	if !ok {
		return nil, process.ErrWrongTypeAssertion
	}

	return userAccount, nil
}

func (d *drwaHookStateAdapter) persistArtifact(
	systemAccount vmcommon.UserAccountHandler,
	latestKey []byte,
	historyKeyBuilder func([]byte, []byte) []byte,
	tokenID string,
	payload []byte,
) error {
	payloadCopy := append([]byte(nil), payload...)
	// F-023: Reuse Keccak hasher from pool.
	hasher := drwaKeccakPool.Get().(interface{ Compute(string) []byte })
	payloadHash := hasher.Compute(string(payloadCopy))
	drwaKeccakPool.Put(hasher)

	// Both SaveKeyValue calls mutate the in-memory account trie. Perform both
	// before calling SaveAccount so that either both keys are committed or
	// neither is (SaveAccount is the single persistence point). If either
	// SaveKeyValue fails, we skip SaveAccount; the in-memory mutations are
	// discarded on transaction revert via RevertToSnapshot (C-7 / SH-2 fix).
	historyKey := historyKeyBuilder([]byte(tokenID), payloadHash)

	err := systemAccount.AccountDataHandler().SaveKeyValue(latestKey, payloadCopy)
	if err != nil {
		return err
	}

	err = systemAccount.AccountDataHandler().SaveKeyValue(historyKey, payloadCopy)
	if err != nil {
		rollbackErr := systemAccount.AccountDataHandler().SaveKeyValue(latestKey, nil)
		if rollbackErr != nil {
			log.Warn("persistArtifact: failed to roll back latest key after history write failure",
				"tokenID", tokenID,
				"rollbackErr", rollbackErr,
				"originalErr", err)
		}

		return err
	}

	return d.accounts.SaveAccount(systemAccount)
}

// --- C-1: drwaSyncRecoveryTimelockProvider implementation ---

// GetRecoveryLastBlock reads the block nonce of the last recovery_admin write
// for the given token from the system account. Returns 0 if no prior recovery.
func (d *drwaHookStateAdapter) GetRecoveryLastBlock(tokenID string) (uint64, error) {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return 0, err
	}

	value, _, err := d.retrieveValueAllowingFreshNilTrie(systemAccount, buildDRWARecoveryLastBlockKey(tokenID))
	if err != nil {
		return 0, err
	}
	if len(value) == 0 {
		return 0, nil
	}
	if len(value) != 8 {
		return 0, fmt.Errorf("corrupt recovery last block value: expected 8 bytes, got %d", len(value))
	}

	return binary.BigEndian.Uint64(value), nil
}

// PutRecoveryLastBlock writes the current block nonce as the last recovery
// block for the given token into the system account.
func (d *drwaHookStateAdapter) PutRecoveryLastBlock(tokenID string, blockNonce uint64) error {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, blockNonce)

	err = systemAccount.AccountDataHandler().SaveKeyValue(buildDRWARecoveryLastBlockKey(tokenID), buf)
	if err != nil {
		return err
	}

	return d.accounts.SaveAccount(systemAccount)
}

// GetCurrentBlockNonce returns the nonce of the block currently being processed.
// Returns an error if no block nonce provider was configured (test path should
// use the optional interface check in enforceDRWARecoveryTimelock instead).
func (d *drwaHookStateAdapter) GetCurrentBlockNonce() (uint64, error) {
	if d.nonceProvider == nil {
		return 0, fmt.Errorf("no block nonce provider configured")
	}
	return d.nonceProvider.CurrentNonce(), nil
}
