package hooks

// drwa_coverage_test.go — G-02, G-04, G-05, G-06, G-07, G-09: Additional tests
// to raise coverage to >=90% for the mx-chain-go/process/smartContract/hooks
// DRWA files.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmmock "github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// G-04: Test legacy 8-byte tombstone fallback in readStoredValue
// ---------------------------------------------------------------------------

func TestReadStoredValueLegacy8ByteTombstoneFallback(t *testing.T) {
	holderAddress := []byte("erd1legacy")
	holderAccount := state.NewAccountWrapMock(holderAddress)

	// Write a raw 8-byte big-endian uint64 (pre-JSON tombstone format).
	legacyTombstone := make([]byte, 8)
	binary.BigEndian.PutUint64(legacyTombstone, 42)
	require.NoError(t, holderAccount.AccountDataHandler().SaveKeyValue([]byte("drwa:test:legacy"), legacyTombstone))

	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			if string(address) == string(holderAddress) {
				return holderAccount, nil
			}
			return state.NewAccountWrapMock(address), nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	account, err := adapter.getUserAccount(holderAddress)
	require.NoError(t, err)

	stored, err := adapter.readStoredValue(account, []byte("drwa:test:legacy"))
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.Equal(t, uint64(42), stored.Version)
	require.Nil(t, stored.Body, "legacy tombstone body must be nil")
}

func TestReadStoredValueLegacy8ByteMaxVersion(t *testing.T) {
	holderAddress := []byte("erd1legacymax")
	holderAccount := state.NewAccountWrapMock(holderAddress)

	legacyTombstone := make([]byte, 8)
	binary.BigEndian.PutUint64(legacyTombstone, 0xFFFFFFFFFFFFFFFF)
	require.NoError(t, holderAccount.AccountDataHandler().SaveKeyValue([]byte("drwa:test:legacymax"), legacyTombstone))

	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			if string(address) == string(holderAddress) {
				return holderAccount, nil
			}
			return state.NewAccountWrapMock(address), nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	account, err := adapter.getUserAccount(holderAddress)
	require.NoError(t, err)

	stored, err := adapter.readStoredValue(account, []byte("drwa:test:legacymax"))
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.Equal(t, uint64(0xFFFFFFFFFFFFFFFF), stored.Version)
	require.Nil(t, stored.Body)
}

// Non-JSON, non-8-byte data should return an error.
func TestReadStoredValueRejectsNonJSONNon8ByteData(t *testing.T) {
	holderAddress := []byte("erd1bad")
	holderAccount := state.NewAccountWrapMock(holderAddress)

	require.NoError(t, holderAccount.AccountDataHandler().SaveKeyValue([]byte("drwa:test:bad"), []byte{0x01, 0x02, 0x03}))

	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			if string(address) == string(holderAddress) {
				return holderAccount, nil
			}
			return state.NewAccountWrapMock(address), nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	account, err := adapter.getUserAccount(holderAddress)
	require.NoError(t, err)

	_, err = adapter.readStoredValue(account, []byte("drwa:test:bad"))
	require.Error(t, err, "non-JSON non-8-byte data should cause an error")
}

// ---------------------------------------------------------------------------
// G-05: Test persistArtifact partial write failure
// persistArtifact calls SaveKeyValue twice (latest + history) before
// SaveAccount. We test that a failure on the second SaveKeyValue prevents
// SaveAccount from being called. The approach: use state.AccountWrapMock's
// AccountDataHandlerCalled to return a DataTrieTrackerStub with a controlled
// SaveKeyValueCalled callback.
// ---------------------------------------------------------------------------

func TestPersistArtifactPartialWriteFailure(t *testing.T) {
	systemAccount := state.NewAccountWrapMock(core.SystemAccountAddress)
	saveAccountCalls := 0
	saveKeyValueCalls := 0
	historyErr := errors.New("history write failed")
	var rollbackKey []byte
	var rollbackWasNil bool

	systemAccount.AccountDataHandlerCalled = func() vmcommon.AccountDataHandler {
		return &vmmock.DataTrieTrackerStub{
			SaveKeyValueCalled: func(key []byte, value []byte) error {
				saveKeyValueCalls++
				if saveKeyValueCalls == 2 {
					return historyErr
				}
				if saveKeyValueCalls == 3 {
					rollbackKey = append([]byte(nil), key...)
					rollbackWasNil = value == nil
				}
				return nil
			},
			RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
				return nil, 0, nil
			},
		}
	}

	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return systemAccount, nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error {
			saveAccountCalls++
			return nil
		},
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	err = adapter.PersistRecoveryEvidence("CARBON-1", []byte("evidence-payload"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "history write failed")
	require.Equal(t, 0, saveAccountCalls, "SaveAccount must not be called when history key write fails")
	require.Equal(t, 3, saveKeyValueCalls, "expected rollback write after history key failure")
	require.True(t, rollbackWasNil, "rollback must clear latest key with nil value")
	require.Equal(t, buildDRWARecoveryEvidenceKey([]byte("CARBON-1")), rollbackKey)
}

func TestPersistArtifactLatestKeyWriteFailure(t *testing.T) {
	systemAccount := state.NewAccountWrapMock(core.SystemAccountAddress)
	latestErr := errors.New("latest write failed")

	systemAccount.AccountDataHandlerCalled = func() vmcommon.AccountDataHandler {
		return &vmmock.DataTrieTrackerStub{
			SaveKeyValueCalled: func(key []byte, value []byte) error {
				return latestErr
			},
			RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
				return nil, 0, nil
			},
		}
	}

	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return systemAccount, nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	err = adapter.PersistRecoveryEvidence("CARBON-1", []byte("evidence-payload"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "latest write failed")
}

// ---------------------------------------------------------------------------
// G-06: Test GetCurrentBlockNonce nil provider
// ---------------------------------------------------------------------------

func TestGetCurrentBlockNonceNilProvider(t *testing.T) {
	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return state.NewAccountWrapMock(address), nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)
	// nonceProvider is nil by default
	require.Nil(t, adapter.nonceProvider)

	nonce, err := adapter.GetCurrentBlockNonce()
	require.Error(t, err)
	require.Contains(t, err.Error(), "no block nonce provider configured")
	require.Equal(t, uint64(0), nonce)
}

func TestGetCurrentBlockNonceWithProvider(t *testing.T) {
	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return state.NewAccountWrapMock(address), nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)
	adapter.nonceProvider = &mockBlockNonceProvider{nonce: 12345}

	nonce, err := adapter.GetCurrentBlockNonce()
	require.NoError(t, err)
	require.Equal(t, uint64(12345), nonce)
}

type mockBlockNonceProvider struct {
	nonce uint64
}

func (m *mockBlockNonceProvider) CurrentNonce() uint64 {
	return m.nonce
}

// ---------------------------------------------------------------------------
// G-07: Test recovery timelock commit failure now causes hard error
// ---------------------------------------------------------------------------

// mockTimelockAdapter embeds mockDRWASyncStateAdapter and adds timelock support.
type mockTimelockAdapter struct {
	*mockDRWASyncStateAdapter
	currentBlock     uint64
	lastBlocks       map[string]uint64
	failGetNonce     bool
	failPutLastBlock bool
}

func newMockTimelockAdapter() *mockTimelockAdapter {
	return &mockTimelockAdapter{
		mockDRWASyncStateAdapter: newMockDRWASyncStateAdapter(),
		lastBlocks:               make(map[string]uint64),
		currentBlock:             10000,
	}
}

func (m *mockTimelockAdapter) GetRecoveryLastBlock(tokenID string) (uint64, error) {
	return m.lastBlocks[tokenID], nil
}

func (m *mockTimelockAdapter) PutRecoveryLastBlock(tokenID string, blockNonce uint64) error {
	if m.failPutLastBlock {
		return errors.New("timelock persist failed")
	}
	m.lastBlocks[tokenID] = blockNonce
	return nil
}

func (m *mockTimelockAdapter) GetCurrentBlockNonce() (uint64, error) {
	if m.failGetNonce {
		return 0, errors.New("nonce unavailable")
	}
	return m.currentBlock, nil
}

func TestCommitDRWARecoveryTimelockBlockFailureCausesError(t *testing.T) {
	adapter := newMockTimelockAdapter()
	adapter.failPutLastBlock = true

	ops := []drwaSyncOperation{
		{TokenID: "CARBON-1", OperationType: drwaSyncOpTokenPolicy},
	}

	err := commitDRWARecoveryTimelockBlock(adapter, ops)
	require.Error(t, err)
	require.Contains(t, err.Error(), "timelock persist failed")
}

func TestCommitDRWARecoveryTimelockBlockGetNonceFailure(t *testing.T) {
	adapter := newMockTimelockAdapter()
	adapter.failGetNonce = true

	ops := []drwaSyncOperation{
		{TokenID: "CARBON-1", OperationType: drwaSyncOpTokenPolicy},
	}

	err := commitDRWARecoveryTimelockBlock(adapter, ops)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot read current block")
}

func TestCommitDRWARecoveryTimelockBlockSuccess(t *testing.T) {
	adapter := newMockTimelockAdapter()

	ops := []drwaSyncOperation{
		{TokenID: "CARBON-1", OperationType: drwaSyncOpTokenPolicy},
		{TokenID: "CARBON-1", OperationType: drwaSyncOpHolderMirror}, // duplicate token
		{TokenID: "CARBON-2", OperationType: drwaSyncOpTokenPolicy},
	}

	err := commitDRWARecoveryTimelockBlock(adapter, ops)
	require.NoError(t, err)
	require.Equal(t, uint64(10000), adapter.lastBlocks["CARBON-1"])
	require.Equal(t, uint64(10000), adapter.lastBlocks["CARBON-2"])
}

func TestCommitDRWARecoveryTimelockBlockSkipsNonTimelockAdapter(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()

	ops := []drwaSyncOperation{
		{TokenID: "CARBON-1", OperationType: drwaSyncOpTokenPolicy},
	}

	// Non-timelock adapter should return nil (skip).
	err := commitDRWARecoveryTimelockBlock(adapter, ops)
	require.NoError(t, err)
}

// Test that applyDRWASyncEnvelope fails and rolls back if timelock commit fails.
func TestApplyDRWASyncEnvelopeTimelockCommitFailureRollsBack(t *testing.T) {
	adapter := newMockTimelockAdapter()
	adapter.failPutLastBlock = true

	ops := []drwaSyncOperation{
		{OperationType: drwaSyncOpTokenPolicy, TokenID: "CARBON-1", Version: 1, Body: []byte(`{}`)},
	}
	hash, err := computeDRWASyncHash(drwaSyncCallerRecoveryAdmin, ops)
	require.NoError(t, err)

	envelope := &drwaSyncEnvelope{
		CallerDomain:  drwaSyncCallerRecoveryAdmin,
		PayloadHash:   hash,
		Operations:    ops,
		RecoveryScope: []string{"CARBON-1"},
	}

	_, err = applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerRecoveryAdmin))
	require.Error(t, err)
	require.Contains(t, err.Error(), "timelock persist failed")
}

// ---------------------------------------------------------------------------
// G-02: Coverage for enforceDRWARecoveryTimelock paths
// ---------------------------------------------------------------------------

func TestEnforceDRWARecoveryTimelockPaths(t *testing.T) {
	t.Run("timelock_active", func(t *testing.T) {
		adapter := newMockTimelockAdapter()
		adapter.currentBlock = 100
		adapter.lastBlocks["CARBON-1"] = 50 // gap = 50, less than 600

		ops := []drwaSyncOperation{
			{TokenID: "CARBON-1", OperationType: drwaSyncOpTokenPolicy},
		}
		err := enforceDRWARecoveryTimelock(adapter, ops)
		require.Error(t, err)
		require.ErrorIs(t, err, errDRWARecoveryTimelockActive)
	})

	t.Run("timelock_elapsed", func(t *testing.T) {
		adapter := newMockTimelockAdapter()
		adapter.currentBlock = 1000
		adapter.lastBlocks["CARBON-1"] = 100 // gap = 900, more than 600

		ops := []drwaSyncOperation{
			{TokenID: "CARBON-1", OperationType: drwaSyncOpTokenPolicy},
		}
		err := enforceDRWARecoveryTimelock(adapter, ops)
		require.NoError(t, err)
	})

	t.Run("no_prior_recovery", func(t *testing.T) {
		adapter := newMockTimelockAdapter()
		adapter.currentBlock = 100

		ops := []drwaSyncOperation{
			{TokenID: "NEW-TOKEN", OperationType: drwaSyncOpTokenPolicy},
		}
		err := enforceDRWARecoveryTimelock(adapter, ops)
		require.NoError(t, err)
	})

	t.Run("chain_reorg_conservative_denial", func(t *testing.T) {
		adapter := newMockTimelockAdapter()
		adapter.currentBlock = 50
		adapter.lastBlocks["CARBON-1"] = 100 // currentBlock < lastBlock

		ops := []drwaSyncOperation{
			{TokenID: "CARBON-1", OperationType: drwaSyncOpTokenPolicy},
		}
		err := enforceDRWARecoveryTimelock(adapter, ops)
		require.Error(t, err)
		require.ErrorIs(t, err, errDRWARecoveryTimelockActive)
	})

	t.Run("get_nonce_error", func(t *testing.T) {
		adapter := newMockTimelockAdapter()
		adapter.failGetNonce = true

		ops := []drwaSyncOperation{
			{TokenID: "CARBON-1", OperationType: drwaSyncOpTokenPolicy},
		}
		err := enforceDRWARecoveryTimelock(adapter, ops)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot read current block")
	})

	t.Run("deduplicates_tokens", func(t *testing.T) {
		adapter := newMockTimelockAdapter()
		adapter.currentBlock = 10000

		ops := []drwaSyncOperation{
			{TokenID: "CARBON-1", OperationType: drwaSyncOpTokenPolicy},
			{TokenID: "CARBON-1", OperationType: drwaSyncOpHolderMirror},
		}
		err := enforceDRWARecoveryTimelock(adapter, ops)
		require.NoError(t, err)
	})
}

// ---------------------------------------------------------------------------
// G-02: Coverage for buildDRWARecoveryLastBlockKey
// ---------------------------------------------------------------------------

func TestBuildDRWARecoveryLastBlockKey(t *testing.T) {
	t.Parallel()

	key := buildDRWARecoveryLastBlockKey("CARBON-1")
	require.Equal(t, []byte("drwa:recovery:lastBlock:CARBON-1"), key)
}

// ---------------------------------------------------------------------------
// G-02: Coverage for buildDRWARolloutStageKey
// ---------------------------------------------------------------------------

func TestBuildDRWARolloutStageKey(t *testing.T) {
	t.Parallel()

	key := buildDRWARolloutStageKey("CARBON-1")
	require.Equal(t, []byte("drwa:rollout:stage:CARBON-1"), key)
}

// ---------------------------------------------------------------------------
// G-02: Coverage for buildDRWAAssetRecordKey
// ---------------------------------------------------------------------------

func TestBuildDRWAAssetRecordKey(t *testing.T) {
	t.Parallel()

	key := buildDRWAAssetRecordKey([]byte("CARBON-1"))
	require.Contains(t, string(key), "drwa:asset:")
	require.Contains(t, string(key), ":record")
}

// ---------------------------------------------------------------------------
// G-02: Coverage for GetAssetRecordVersion
// ---------------------------------------------------------------------------

func TestGetAssetRecordVersion(t *testing.T) {
	// Use vmmock for full in-memory storage without trie dependency.
	systemAccount := vmmock.NewAccountWrapMock(core.SystemAccountAddress)
	stored, _ := json.Marshal(&drwaSyncStoredValue{Version: 7, Body: []byte(`{}`)})
	require.NoError(t, systemAccount.SaveKeyValue(buildDRWAAssetRecordKey([]byte("CARBON-1")), stored))

	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return systemAccount, nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	v, err := adapter.GetAssetRecordVersion("CARBON-1")
	require.NoError(t, err)
	require.Equal(t, uint64(7), v)

	// Missing key → version 0
	v, err = adapter.GetAssetRecordVersion("MISSING")
	require.NoError(t, err)
	require.Equal(t, uint64(0), v)
}

// ---------------------------------------------------------------------------
// G-02: Coverage for PutAssetRecordBody
// ---------------------------------------------------------------------------

func TestPutAssetRecordBody(t *testing.T) {
	// Use vmmock.NewAccountWrapMock which has simple in-memory storage without trie.
	systemAccount := vmmock.NewAccountWrapMock(core.SystemAccountAddress)
	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return systemAccount, nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	require.NoError(t, adapter.PutAssetRecordBody("CARBON-1", 1, []byte(`{"wind_down_initiated":true}`)))

	v, err := adapter.GetAssetRecordVersion("CARBON-1")
	require.NoError(t, err)
	require.Equal(t, uint64(1), v)
}

// ---------------------------------------------------------------------------
// G-02: Coverage for GetRecoveryLastBlock and PutRecoveryLastBlock
// ---------------------------------------------------------------------------

func TestGetPutRecoveryLastBlock(t *testing.T) {
	// Use vmmock for full in-memory storage without trie dependency.
	systemAccount := vmmock.NewAccountWrapMock(core.SystemAccountAddress)

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, 500)
	require.NoError(t, systemAccount.SaveKeyValue(buildDRWARecoveryLastBlockKey("CARBON-1"), buf))

	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return systemAccount, nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	block, err := adapter.GetRecoveryLastBlock("CARBON-1")
	require.NoError(t, err)
	require.Equal(t, uint64(500), block)

	// Missing key → 0
	block, err = adapter.GetRecoveryLastBlock("MISSING")
	require.NoError(t, err)
	require.Equal(t, uint64(0), block)
}

func TestGetRecoveryLastBlockCorruptValue(t *testing.T) {
	systemAccount := vmmock.NewAccountWrapMock(core.SystemAccountAddress)
	// Write a 5-byte value (neither 0 nor 8 bytes)
	require.NoError(t, systemAccount.SaveKeyValue(
		buildDRWARecoveryLastBlockKey("CARBON-1"),
		[]byte{1, 2, 3, 4, 5},
	))

	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return systemAccount, nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	_, err = adapter.GetRecoveryLastBlock("CARBON-1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "corrupt recovery last block value")
}

// ---------------------------------------------------------------------------
// G-02: Coverage for getUserAccount nil account guard
// ---------------------------------------------------------------------------

func TestGetUserAccountNilAccountGuard(t *testing.T) {
	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return nil, nil // LoadAccount succeeds but returns nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	_, err = adapter.getUserAccount([]byte("any-address"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "DRWA_ACCOUNT_NOT_IN_SHARD")
}

// ---------------------------------------------------------------------------
// G-02: Coverage for verifyDRWANoopEnvelopeHash success path
// ---------------------------------------------------------------------------

func TestVerifyDRWANoopEnvelopeHashSuccess(t *testing.T) {
	hash, err := computeDRWASyncHash(drwaSyncCallerPolicyRegistry, nil)
	require.NoError(t, err)

	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		PayloadHash:  hash,
	}
	require.NoError(t, verifyDRWANoopEnvelopeHash(envelope))
}

func TestVerifyDRWANoopEnvelopeHashMismatch(t *testing.T) {
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		PayloadHash:  []byte("wrong-hash"),
	}
	err := verifyDRWANoopEnvelopeHash(envelope)
	require.Error(t, err)
	require.Contains(t, err.Error(), "noop envelope hash mismatch")
}

// ---------------------------------------------------------------------------
// G-02: Coverage for validateDRWASyncField paths
// ---------------------------------------------------------------------------

func TestValidateDRWASyncFieldPaths(t *testing.T) {
	t.Parallel()

	require.Error(t, validateDRWASyncField("", 10))
	require.Error(t, validateDRWASyncField("toolong", 3))
	require.Error(t, validateDRWASyncField("has\x00null", 20))
	require.Error(t, validateDRWASyncField("has\x01ctrl", 20))
	require.NoError(t, validateDRWASyncField("valid", 10))
}

// ---------------------------------------------------------------------------
// G-02: Coverage for readDRWABinaryLenPrefixed zero-length field
// ---------------------------------------------------------------------------

func TestReadDRWABinaryLenPrefixedZeroLength(t *testing.T) {
	t.Parallel()

	reader := bytes.NewReader([]byte{0, 0, 0, 0})
	result, err := readDRWABinaryLenPrefixed(reader)
	require.NoError(t, err)
	require.Equal(t, []byte{}, result)
}

func TestReadDRWABinaryLenPrefixedOversized(t *testing.T) {
	t.Parallel()

	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, uint32(drwaSyncMaxFieldBytes+1))
	_, err := readDRWABinaryLenPrefixed(bytes.NewReader(data))
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds max")
}

// ---------------------------------------------------------------------------
// G-02: Coverage for applyDRWASyncOperation — asset_record path
// ---------------------------------------------------------------------------

func TestApplyDRWASyncOperationAssetRecord(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()

	err := applyDRWASyncOperation(adapter, drwaSyncOperation{
		OperationType: drwaSyncOpAssetRecord,
		TokenID:       "CARBON-1",
		Version:       1,
		Body:          []byte(`{}`),
	})
	require.NoError(t, err)
	require.Equal(t, uint64(1), adapter.assetVersions["CARBON-1"])
}

// ---------------------------------------------------------------------------
// G-02: Coverage for applyDRWASyncOperation — holder_auditor_auth path
// ---------------------------------------------------------------------------

func TestApplyDRWASyncOperationHolderAuditorAuth(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()

	err := applyDRWASyncOperation(adapter, drwaSyncOperation{
		OperationType: drwaSyncOpHolderAuditorAuth,
		TokenID:       "CARBON-1",
		Holder:        "holder1",
		Version:       1,
		Body:          []byte(`{}`),
	})
	require.NoError(t, err)
	require.Equal(t, uint64(1), adapter.holderAuditorAuthVersions["CARBON-1|holder1"])
}

// ---------------------------------------------------------------------------
// G-02: Coverage for applyDRWASyncOperation — holder_mirror_delete path
// ---------------------------------------------------------------------------

func TestApplyDRWASyncOperationHolderMirrorDelete(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()
	adapter.holderVersions["CARBON-1|holder1"] = 1
	adapter.holderBodies["CARBON-1|holder1"] = []byte(`{}`)

	err := applyDRWASyncOperation(adapter, drwaSyncOperation{
		OperationType: drwaSyncOpHolderMirrorDelete,
		TokenID:       "CARBON-1",
		Holder:        "holder1",
		Version:       2,
	})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// G-02: Coverage for isDRWASyncCallerAuthorized — recovery_admin invalid op
// ---------------------------------------------------------------------------

func TestIsDRWASyncCallerAuthorizedRecoveryAdminRejectsInvalidOp(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()

	// recovery_admin can do token_policy, holder_mirror, holder_mirror_delete — but NOT holder_profile
	result := isDRWASyncCallerAuthorized(adapter, drwaSyncCallerRecoveryAdmin, []drwaSyncOperation{
		{OperationType: drwaSyncOpHolderProfile},
	}, testDRWACallerAddress(drwaSyncCallerRecoveryAdmin))
	require.False(t, result)
}

func TestIsDRWASyncCallerAuthorizedAssetManagerAcceptsAssetRecord(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()

	result := isDRWASyncCallerAuthorized(adapter, drwaSyncCallerAssetManager, []drwaSyncOperation{
		{OperationType: drwaSyncOpAssetRecord},
	}, testDRWACallerAddress(drwaSyncCallerAssetManager))
	require.True(t, result)
}

func TestIsDRWASyncCallerAuthorizedAssetManagerRejectsTokenPolicy(t *testing.T) {
	adapter := newMockDRWASyncStateAdapter()

	result := isDRWASyncCallerAuthorized(adapter, drwaSyncCallerAssetManager, []drwaSyncOperation{
		{OperationType: drwaSyncOpTokenPolicy},
	}, testDRWACallerAddress(drwaSyncCallerAssetManager))
	require.False(t, result)
}

// ---------------------------------------------------------------------------
// G-02: Coverage for verifyDRWAPreRecoveryStateHash
// ---------------------------------------------------------------------------

// plainSyncAdapter only implements drwaSyncStateAdapter, NOT drwaMigrationStateReader.
type plainSyncAdapter struct{}

func (p *plainSyncAdapter) GetTokenPolicyVersion(string) (uint64, error)          { return 0, nil }
func (p *plainSyncAdapter) GetAssetRecordVersion(string) (uint64, error)          { return 0, nil }
func (p *plainSyncAdapter) GetHolderMirrorVersion(string, string) (uint64, error) { return 0, nil }
func (p *plainSyncAdapter) GetHolderProfileVersion(string) (uint64, error)        { return 0, nil }
func (p *plainSyncAdapter) GetHolderAuditorAuthorizationVersion(string, string) (uint64, error) {
	return 0, nil
}
func (p *plainSyncAdapter) GetAuthorizedCallerAddress(string) ([]byte, error) { return nil, nil }
func (p *plainSyncAdapter) GetAuthorizedCallerAddressVersioned(string) ([]byte, uint64, error) {
	return nil, 0, nil
}
func (p *plainSyncAdapter) SetAuthorizedCallerAddressVersioned(string, []byte, uint64) error {
	return nil
}
func (p *plainSyncAdapter) PutTokenPolicyBody(string, uint64, []byte) error          { return nil }
func (p *plainSyncAdapter) PutAssetRecordBody(string, uint64, []byte) error          { return nil }
func (p *plainSyncAdapter) PutHolderMirrorBody(string, string, uint64, []byte) error { return nil }
func (p *plainSyncAdapter) PutHolderProfileBody(string, uint64, []byte) error        { return nil }
func (p *plainSyncAdapter) SetDRWAActive(string) error                               { return nil }
func (p *plainSyncAdapter) PutHolderAuditorAuthorizationBody(string, string, uint64, []byte) error {
	return nil
}
func (p *plainSyncAdapter) DeleteHolderMirror(string, string, uint64) error { return nil }
func (p *plainSyncAdapter) Snapshot() int                                   { return 0 }
func (p *plainSyncAdapter) Rollback(int) error                              { return nil }
func (p *plainSyncAdapter) IsInterfaceNil() bool                            { return p == nil }

func TestVerifyDRWAPreRecoveryStateHashSkipsNonReader(t *testing.T) {
	// plainSyncAdapter does NOT implement drwaMigrationStateReader — should skip.
	resetDRWAMetrics()
	adapter := &plainSyncAdapter{}
	envelope := &drwaSyncEnvelope{
		CallerDomain:         drwaSyncCallerRecoveryAdmin,
		PreRecoveryStateHash: []byte("some-hash"),
		Operations: []drwaSyncOperation{
			{OperationType: drwaSyncOpTokenPolicy, TokenID: "CARBON-1", Version: 1},
		},
	}
	err := verifyDRWAPreRecoveryStateHash(adapter, envelope)
	require.NoError(t, err, "non-migration-reader adapter should skip check")

	metrics := snapshotDRWAMetrics()
	require.Equal(t, uint64(1), metrics[drwaMetricRecoveryStateHashSkipped])
}

// ---------------------------------------------------------------------------
// G-02: Coverage for drwaHookStateAdapter — newDRWAHookStateAdapter nil
// ---------------------------------------------------------------------------

func TestNewDRWAHookStateAdapterRejectsNil(t *testing.T) {
	_, err := newDRWAHookStateAdapter(nil)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// G-02: Coverage for DeleteHolderMirror through the real adapter
// ---------------------------------------------------------------------------

func TestDeleteHolderMirrorSaveAccountFailure(t *testing.T) {
	systemAccount := state.NewAccountWrapMock(core.SystemAccountAddress)
	holderAddress := []byte("erd1delholder")
	holderAccount := state.NewAccountWrapMock(holderAddress)
	saveCount := 0
	saveErr := errors.New("save failed")

	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			switch string(address) {
			case string(core.SystemAccountAddress):
				return systemAccount, nil
			case string(holderAddress):
				return holderAccount, nil
			default:
				return state.NewAccountWrapMock(address), nil
			}
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error {
			saveCount++
			if saveCount == 1 {
				return saveErr // fail on first SaveAccount (holder)
			}
			return nil
		},
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	err = adapter.DeleteHolderMirror("CARBON-1", string(holderAddress), 1)
	require.ErrorIs(t, err, saveErr)
}

// ---------------------------------------------------------------------------
// G-02: Coverage for PutAuthorizedCallerAddress failure paths
// ---------------------------------------------------------------------------

func TestPutAuthorizedCallerAddressSaveFailure(t *testing.T) {
	systemAccount := vmmock.NewAccountWrapMock(core.SystemAccountAddress)
	saveErr := errors.New("save boom")

	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return systemAccount, nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error {
			return saveErr
		},
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	err = adapter.PutAuthorizedCallerAddress("test_domain", []byte("addr"))
	require.ErrorIs(t, err, saveErr)
}

// ---------------------------------------------------------------------------
// G-09: Fuzz target for custom bech32 decoder
// ---------------------------------------------------------------------------

func FuzzDRWABech32Decode(f *testing.F) {
	// Valid erd1 address (erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu)
	f.Add("erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu")
	// Too short
	f.Add("erd1")
	// Empty
	f.Add("")
	// No separator
	f.Add("abcdef")
	// Invalid checksum
	f.Add("erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq000000")
	// Invalid character
	f.Add("erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqb!c")
	// Too long (>90 chars)
	f.Add("erd1" + "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
	// Wrong HRP
	f.Add("btc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu")

	f.Fuzz(func(t *testing.T, input string) {
		// Must never panic.
		_, _, _ = bech32Decode(input)
		_, _ = decodeBech32Address(input)
	})
}

// ---------------------------------------------------------------------------
// F9 (closes C1): legacy 8-byte tombstone re-enrollment round-trip
//
// Round-3 audit found that the legacy tombstone *decoder* was tested
// (TestReadStoredValueLegacy8ByteTombstoneFallback) but no test exercised
// the full re-enrollment path: load a legacy tombstone, then submit a sync
// envelope at version+1 to confirm validateDRWASyncVersion accepts it. If
// the legacy decoder ever produced an off-by-one version, the holder would
// be permanently stuck with no recovery path. This test closes that gap.
// ---------------------------------------------------------------------------

func TestLegacyTombstoneReenrollmentRoundTrip(t *testing.T) {
	const (
		f9TokenID       = "CARBON-1"
		f9HolderAddress = "erd1legacyholder"
		f9LegacyVersion = uint64(7)
	)

	holderAddrBytes := []byte(f9HolderAddress)
	holderAccount := state.NewAccountWrapMock(holderAddrBytes)
	systemAccount := state.NewAccountWrapMock(core.SystemAccountAddress)

	// Step 1: write a raw 8-byte big-endian tombstone at the canonical
	// holder mirror key — the same key the production reader checks. This
	// simulates state left over from a pre-JSON deployment.
	mirrorKey := buildDRWAHolderMirrorKey([]byte(f9TokenID), holderAddrBytes)
	require.NotNil(t, mirrorKey, "key builder must not return nil")
	legacyTombstone := make([]byte, 8)
	binary.BigEndian.PutUint64(legacyTombstone, f9LegacyVersion)
	require.NoError(t, holderAccount.AccountDataHandler().SaveKeyValue(mirrorKey, legacyTombstone))

	// Step 2: register the asset_manager authorized caller on the system
	// account so the re-enrollment envelope can pass authorization.
	authKey := buildDRWAAuthorizedCallerKey(drwaSyncCallerAssetManager)
	require.NoError(t, systemAccount.AccountDataHandler().SaveKeyValue(authKey, testDRWACallerAddress(drwaSyncCallerAssetManager)))

	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			if string(address) == string(core.SystemAccountAddress) {
				return systemAccount, nil
			}
			if string(address) == string(holderAddrBytes) {
				return holderAccount, nil
			}
			return state.NewAccountWrapMock(address), nil
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	// Step 3: confirm the legacy decoder produces the expected version.
	// This is the load-bearing assertion: GetHolderMirrorVersion must return
	// f9LegacyVersion exactly so that the next sync envelope at
	// f9LegacyVersion+1 passes validateDRWASyncVersion.
	currentVersion, err := adapter.GetHolderMirrorVersion(f9TokenID, f9HolderAddress)
	require.NoError(t, err)
	require.Equal(t, f9LegacyVersion, currentVersion, "legacy 8-byte tombstone must decode to the original version exactly")

	// Step 4: build a re-enrollment envelope at the next version. The body
	// is a re-issued holder mirror restoring the holder to compliant state.
	reenrollmentBody := []byte(`{"kyc_status":"approved","aml_status":"approved","transfer_locked":false,"receive_locked":false,"auditor_authorized":true}`)
	ops := []drwaSyncOperation{{
		OperationType: drwaSyncOpHolderMirror,
		TokenID:       f9TokenID,
		Holder:        f9HolderAddress,
		Version:       f9LegacyVersion + 1,
		Body:          reenrollmentBody,
	}}
	hash, err := computeDRWASyncHash(drwaSyncCallerAssetManager, ops)
	require.NoError(t, err)
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerAssetManager,
		PayloadHash:  hash,
		Operations:   ops,
	}

	// Step 5: apply the envelope. If the legacy decoder had produced an
	// off-by-one version, validateDRWASyncVersion would reject this with
	// drwaSyncRejectVersionGap and the holder would be permanently stuck.
	result, err := applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerAssetManager))
	require.NoError(t, err, "re-enrollment from legacy tombstone must succeed")
	require.Equal(t, 1, result.AppliedOperations)

	// Step 6: confirm the holder mirror is now at the new version, and that
	// the stored value is in the canonical wrapped format (not the legacy
	// 8-byte tombstone anymore). This proves the round-trip wrote new state,
	// not just passed validation.
	newVersion, err := adapter.GetHolderMirrorVersion(f9TokenID, f9HolderAddress)
	require.NoError(t, err)
	require.Equal(t, f9LegacyVersion+1, newVersion)

	storedAfter, _, err := holderAccount.AccountDataHandler().RetrieveValue(mirrorKey)
	require.NoError(t, err)
	require.NotEmpty(t, storedAfter)
	require.Equal(t, drwaStoredValueBinaryV1, storedAfter[0], "stored value after re-enrollment must be canonical wrapped format, not legacy 8-byte format")

	// Step 7: confirm the body is recoverable as a parseable wrapper containing
	// the new compliance state.
	wrapper, err := decodeDRWASyncStoredValue(storedAfter)
	require.NoError(t, err)
	require.Equal(t, f9LegacyVersion+1, wrapper.Version)
	require.Equal(t, reenrollmentBody, wrapper.Body)
}
