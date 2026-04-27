package hooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmmock "github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

func TestDRWAHookStateAdapterAuthorizedCallerDeleteAndArtifacts(t *testing.T) {
	systemAccount := state.NewAccountWrapMock(core.SystemAccountAddress)
	holderAddress := []byte("erd1holder")
	holderAccount := state.NewAccountWrapMock(holderAddress)

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
			return nil
		},
		JournalLenCalled: func() int {
			return 9
		},
		RevertToSnapshotCalled: func(snapshot int) error {
			require.Equal(t, 9, snapshot)
			return nil
		},
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	require.NoError(t, adapter.PutAuthorizedCallerAddress(drwaSyncCallerAttestation, []byte("attestation_sc")))
	address, err := adapter.GetAuthorizedCallerAddress(drwaSyncCallerAttestation)
	require.NoError(t, err)
	require.Equal(t, []byte("attestation_sc"), address)

	require.NoError(t, adapter.PutHolderMirrorBody("CARBON-1", string(holderAddress), 2, []byte(`{"kyc_status":"approved"}`)))
	require.NoError(t, adapter.DeleteHolderMirror("CARBON-1", string(holderAddress), 3))

	// After deletion, a canonical stored-value tombstone is written instead of
	// raw nil. This prevents re-enrollment at version 1.
	deletedValue, _, err := holderAccount.AccountDataHandler().RetrieveValue(buildDRWAHolderMirrorKey([]byte("CARBON-1"), holderAddress))
	require.NoError(t, err)
	require.NotEmpty(t, deletedValue, "expected tombstone after deletion")

	tombstone, err := decodeDRWASyncStoredValue(deletedValue)
	require.NoError(t, err, "tombstone must be decodable")
	require.Equal(t, uint64(3), tombstone.Version, "tombstone version must match delete version")
	require.Nil(t, tombstone.Body, "tombstone body must be null")

	auditPayload, _, err := systemAccount.AccountDataHandler().RetrieveValue(buildDRWAHolderDeleteAuditKey([]byte("CARBON-1"), holderAddress, 3))
	require.NoError(t, err)
	require.NotEmpty(t, auditPayload)

	auditRecord := &drwaDeleteAuditRecord{}
	require.NoError(t, json.Unmarshal(auditPayload, auditRecord))
	require.Equal(t, "CARBON-1", auditRecord.TokenID)
	require.Equal(t, string(holderAddress), auditRecord.Holder)
	require.Equal(t, uint64(3), auditRecord.Version)

	require.NoError(t, adapter.PersistRecoveryEvidence("CARBON-1", []byte("recovery-proof")))
	require.NoError(t, adapter.PersistRolloutEvidence("CARBON-1", []byte("rollout-proof")))
	require.NoError(t, adapter.PersistRolloutVerification("CARBON-1", []byte("rollout-verified")))

	recoveryLatest, _, err := systemAccount.AccountDataHandler().RetrieveValue(buildDRWARecoveryEvidenceKey([]byte("CARBON-1")))
	require.NoError(t, err)
	require.Equal(t, []byte("recovery-proof"), recoveryLatest)

	rolloutLatest, _, err := systemAccount.AccountDataHandler().RetrieveValue(buildDRWARolloutEvidenceKey([]byte("CARBON-1")))
	require.NoError(t, err)
	require.Equal(t, []byte("rollout-proof"), rolloutLatest)

	verificationLatest, _, err := systemAccount.AccountDataHandler().RetrieveValue(buildDRWARolloutVerificationKey([]byte("CARBON-1")))
	require.NoError(t, err)
	require.Equal(t, []byte("rollout-verified"), verificationLatest)

	require.Equal(t, 9, adapter.Snapshot())
	require.NoError(t, adapter.Rollback(9))
	require.False(t, adapter.IsInterfaceNil())
}

func TestDRWAHookStateAdapterVersionReadersAndSaveFailures(t *testing.T) {
	systemAccount := vmmock.NewAccountWrapMock(core.SystemAccountAddress)
	holderAddress := []byte("erd1holder")
	holderAccount := vmmock.NewAccountWrapMock(holderAddress)
	saveErr := errors.New("save failed")
	failSave := false

	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			switch string(address) {
			case string(core.SystemAccountAddress):
				return systemAccount, nil
			case string(holderAddress):
				return holderAccount, nil
			default:
				return vmmock.NewAccountWrapMock(address), nil
			}
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error {
			if failSave {
				return saveErr
			}
			return nil
		},
		JournalLenCalled:       func() int { return 1 },
		RevertToSnapshotCalled: func(snapshot int) error { return nil },
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	version, err := adapter.GetTokenPolicyVersion("missing")
	require.NoError(t, err)
	require.Equal(t, uint64(0), version)

	version, err = adapter.GetHolderMirrorVersion("CARBON-1", string(holderAddress))
	require.NoError(t, err)
	require.Equal(t, uint64(0), version)

	version, err = adapter.GetHolderProfileVersion(string(holderAddress))
	require.NoError(t, err)
	require.Equal(t, uint64(0), version)

	version, err = adapter.GetHolderAuditorAuthorizationVersion("CARBON-1", string(holderAddress))
	require.NoError(t, err)
	require.Equal(t, uint64(0), version)

	storedPolicy, err := adapter.GetTokenPolicyStored("missing")
	require.NoError(t, err)
	require.Nil(t, storedPolicy)

	storedMirror, err := adapter.GetHolderMirrorStored("CARBON-1", string(holderAddress))
	require.NoError(t, err)
	require.Nil(t, storedMirror)

	failSave = false
	require.NoError(t, adapter.PutTokenPolicyBody("CARBON-1", 3, []byte(`{"regulated":true}`)))
	require.NoError(t, adapter.PutHolderMirrorBody("CARBON-1", string(holderAddress), 4, []byte(`{"kyc":"approved"}`)))

	storedPolicy, err = adapter.GetTokenPolicyStored("CARBON-1")
	require.NoError(t, err)
	require.NotNil(t, storedPolicy)
	require.Equal(t, uint64(3), storedPolicy.Version)
	require.Equal(t, []byte(`{"regulated":true}`), storedPolicy.Body)

	storedMirror, err = adapter.GetHolderMirrorStored("CARBON-1", string(holderAddress))
	require.NoError(t, err)
	require.NotNil(t, storedMirror)
	require.Equal(t, uint64(4), storedMirror.Version)
	require.Equal(t, []byte(`{"kyc":"approved"}`), storedMirror.Body)

	failSave = true
	require.ErrorIs(t, adapter.PutTokenPolicyBody("CARBON-1", 1, []byte(`{}`)), saveErr)
	require.ErrorIs(t, adapter.PutHolderMirrorBody("CARBON-1", string(holderAddress), 1, []byte(`{}`)), saveErr)
	require.ErrorIs(t, adapter.PutHolderProfileBody(string(holderAddress), 1, []byte(`{}`)), saveErr)
	require.ErrorIs(t, adapter.PutHolderAuditorAuthorizationBody("CARBON-1", string(holderAddress), 1, []byte(`{}`)), saveErr)
}

func TestDRWAHookStateAdapterVersionReadersTreatFreshNilTrieAsMissing(t *testing.T) {
	systemAccount := state.NewAccountWrapMock(core.SystemAccountAddress)
	holderAddress := []byte("erd1holder")
	holderAccount := state.NewAccountWrapMock(holderAddress)

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
		SaveAccountCalled:      func(account vmcommon.AccountHandler) error { return nil },
		JournalLenCalled:       func() int { return 1 },
		RevertToSnapshotCalled: func(snapshot int) error { return nil },
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	version, err := adapter.GetTokenPolicyVersion("CARBON-1")
	require.NoError(t, err)
	require.Equal(t, uint64(0), version)

	version, err = adapter.GetAssetRecordVersion("CARBON-1")
	require.NoError(t, err)
	require.Equal(t, uint64(0), version)

	version, err = adapter.GetHolderMirrorVersion("CARBON-1", string(holderAddress))
	require.NoError(t, err)
	require.Equal(t, uint64(0), version)

	version, err = adapter.GetHolderProfileVersion(string(holderAddress))
	require.NoError(t, err)
	require.Equal(t, uint64(0), version)

	version, err = adapter.GetHolderAuditorAuthorizationVersion("CARBON-1", string(holderAddress))
	require.NoError(t, err)
	require.Equal(t, uint64(0), version)

	address, err := adapter.GetAuthorizedCallerAddress(drwaSyncCallerIdentityRegistry)
	require.NoError(t, err)
	require.Nil(t, address)

	address, version, err = func() ([]byte, uint64, error) {
		return adapter.GetAuthorizedCallerAddressVersioned(drwaSyncCallerIdentityRegistry)
	}()
	require.NoError(t, err)
	require.Nil(t, address)
	require.Equal(t, uint64(0), version)

	recoveryLastBlock, err := adapter.GetRecoveryLastBlock("CARBON-1")
	require.NoError(t, err)
	require.Equal(t, uint64(0), recoveryLastBlock)
}

func TestEncodeDecodeDRWASyncStoredValueBinaryRoundTrip(t *testing.T) {
	t.Parallel()

	payload, err := encodeDRWASyncStoredValue(&drwaSyncStoredValue{
		Version: 7,
		Body:    []byte(`{"regulated":true}`),
	})
	require.NoError(t, err)
	require.Equal(t, drwaStoredValueBinaryV1, payload[0])

	decoded, err := decodeDRWASyncStoredValue(payload)
	require.NoError(t, err)
	require.Equal(t, uint64(7), decoded.Version)
	require.Equal(t, []byte(`{"regulated":true}`), decoded.Body)
}

func TestEncodeDecodeDRWASyncStoredValueBinaryTombstoneRoundTrip(t *testing.T) {
	t.Parallel()

	payload, err := encodeDRWASyncStoredValue(&drwaSyncStoredValue{
		Version: 11,
		Body:    nil,
	})
	require.NoError(t, err)
	require.Equal(t, drwaStoredValueBinaryV1, payload[0])

	decoded, err := decodeDRWASyncStoredValue(payload)
	require.NoError(t, err)
	require.Equal(t, uint64(11), decoded.Version)
	require.Nil(t, decoded.Body)
}

func TestVerifyDRWAPreRecoveryStateHashWithRealAdapter(t *testing.T) {
	systemAccount := vmmock.NewAccountWrapMock(core.SystemAccountAddress)
	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			switch string(address) {
			case string(core.SystemAccountAddress):
				return systemAccount, nil
			default:
				return vmmock.NewAccountWrapMock(address), nil
			}
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
		JournalLenCalled:  func() int { return 5 },
		RevertToSnapshotCalled: func(snapshot int) error {
			require.Equal(t, 5, snapshot)
			return nil
		},
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)
	require.NoError(t, adapter.PutTokenPolicyBody("CARBON-R4", 1, []byte(`{"regulated":true}`)))

	manifest := &drwaRecoveryManifest{
		TokenID:       "CARBON-R4",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{"regulated":true}`),
	}
	stateHash, err := computeDRWARecoveryStateHash(adapter, manifest)
	require.NoError(t, err)

	envelope := &drwaSyncEnvelope{
		CallerDomain:         drwaSyncCallerRecoveryAdmin,
		PreRecoveryStateHash: stateHash,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "CARBON-R4",
			Version:       2,
			Body:          []byte(`{"regulated":false}`),
		}},
	}
	require.NoError(t, verifyDRWAPreRecoveryStateHash(adapter, envelope))

	envelope.PreRecoveryStateHash = []byte("stale-hash")
	require.ErrorIs(t, verifyDRWAPreRecoveryStateHash(adapter, envelope), errDRWARecoveryStateChanged)
}

func TestDRWAHookStateAdapterAuthorizedCallerVersionedRoundTrip(t *testing.T) {
	systemAccount := vmmock.NewAccountWrapMock(core.SystemAccountAddress)
	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			switch string(address) {
			case string(core.SystemAccountAddress):
				return systemAccount, nil
			default:
				return vmmock.NewAccountWrapMock(address), nil
			}
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
		JournalLenCalled:  func() int { return 5 },
		RevertToSnapshotCalled: func(snapshot int) error {
			require.Equal(t, 5, snapshot)
			return nil
		},
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	require.NoError(t, adapter.PutAuthorizedCallerAddress("legacy_domain", []byte("legacy_addr")))
	addr, version, err := adapter.GetAuthorizedCallerAddressVersioned("legacy_domain")
	require.NoError(t, err)
	require.Equal(t, []byte("legacy_addr"), addr)
	require.Equal(t, uint64(0), version)

	require.NoError(t, adapter.SetAuthorizedCallerAddressVersioned("auth_admin", []byte("new_auth_admin"), 2))
	addr, version, err = adapter.GetAuthorizedCallerAddressVersioned("auth_admin")
	require.NoError(t, err)
	require.Equal(t, []byte("new_auth_admin"), addr)
	require.Equal(t, uint64(2), version)

	rawAddr, err := adapter.GetAuthorizedCallerAddress("auth_admin")
	require.NoError(t, err)
	require.Equal(t, []byte("new_auth_admin"), rawAddr)
}

func TestBlockChainHookApplyDRWASyncEnvelopeBytes(t *testing.T) {
	hook := &BlockChainHookImpl{}
	operations := []drwaSyncOperation{{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "CARBON-APPLY",
		Version:       1,
		Body:          []byte(`{"regulated":true}`),
	}}

	payload, err := serializeDRWASyncEnvelopePayload(drwaSyncCallerPolicyRegistry, operations)
	require.NoError(t, err)
	hash, err := computeDRWASyncHash(drwaSyncCallerPolicyRegistry, operations)
	require.NoError(t, err)

	hookPayload := append(append([]byte(nil), hash...), payload...)
	require.ErrorIs(t, hook.ApplyDRWASyncEnvelopeBytes(hookPayload, testDRWACallerAddress(drwaSyncCallerPolicyRegistry)), ErrNilDRWAAccountsAdapter)
}

func TestBlockChainHookApplyDRWASyncEnvelopeBytesRejectsMalformedPayload(t *testing.T) {
	hook := &BlockChainHookImpl{}
	require.Error(t, hook.ApplyDRWASyncEnvelopeBytes([]byte("bad-payload"), []byte("caller")))
}

func TestBlockChainHookApplyDRWASyncEnvelopeBytesRejectsMalformedCallerAddress(t *testing.T) {
	hook := &BlockChainHookImpl{}
	operations := []drwaSyncOperation{{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "CARBON-APPLY",
		Version:       1,
		Body:          []byte(`{"regulated":true}`),
	}}

	payload, err := serializeDRWASyncEnvelopePayload(drwaSyncCallerPolicyRegistry, operations)
	require.NoError(t, err)
	hash, err := computeDRWASyncHash(drwaSyncCallerPolicyRegistry, operations)
	require.NoError(t, err)

	hookPayload := append(append([]byte(nil), hash...), payload...)
	resetDRWAMetrics()

	err = hook.ApplyDRWASyncEnvelopeBytes(hookPayload, []byte("short-caller"))
	require.EqualError(t, err, drwaSyncRejectUnauthorizedCaller)
	require.Equal(t, uint64(1), snapshotDRWAMetrics()[drwaMetricAuthorizedCallerMalformed])
}

func TestBlockChainHookApplyDRWASyncEnvelopeBytesAuthAdminVersionedUpdate(t *testing.T) {
	systemAccount := vmmock.NewAccountWrapMock(core.SystemAccountAddress)
	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			switch string(address) {
			case string(core.SystemAccountAddress):
				return systemAccount, nil
			default:
				return vmmock.NewAccountWrapMock(address), nil
			}
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
		JournalLenCalled:  func() int { return 5 },
		RevertToSnapshotCalled: func(snapshot int) error {
			require.Equal(t, 5, snapshot)
			return nil
		},
	}

	newAddressHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	operations := []drwaSyncOperation{{
		OperationType: drwaSyncOpAuthorizedCallerUpdate,
		TokenID:       drwaSyncCallerPolicyRegistry,
		Version:       1,
		Body:          []byte(newAddressHex),
	}}

	hook := &BlockChainHookImpl{
		accounts:      accountsStub,
		currentHdr:    &block.Header{},
		epochStartHdr: &block.Header{},
	}
	seedAdapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)
	require.NoError(t, seedAdapter.SetAuthorizedCallerAddressVersioned(drwaSyncCallerAuthAdmin, testDRWACallerAddress(drwaSyncCallerAuthAdmin), 1))

	hookPayload := buildBinaryEnvelope(t, drwaSyncCallerAuthAdmin, operations)
	require.NoError(t, hook.ApplyDRWASyncEnvelopeBytes(hookPayload, testDRWACallerAddress(drwaSyncCallerAuthAdmin)))

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)

	expectedAddress, err := NormalizeDRWAAuthorizedCallerAddress(newAddressHex)
	require.NoError(t, err)

	address, version, err := adapter.GetAuthorizedCallerAddressVersioned(drwaSyncCallerPolicyRegistry)
	require.NoError(t, err)
	require.Equal(t, expectedAddress, address)
	require.Equal(t, uint64(1), version)

	rawStored, _, err := systemAccount.AccountDataHandler().RetrieveValue(buildDRWAAuthorizedCallerKey(drwaSyncCallerPolicyRegistry))
	require.NoError(t, err)
	require.NotEmpty(t, rawStored)
	require.True(t, bytes.Contains(rawStored, []byte(`"version":1`)))
}

func TestBlockChainHookApplyDRWASyncEnvelopeBytesAuthAdminRejectsStaleVersion(t *testing.T) {
	systemAccount := vmmock.NewAccountWrapMock(core.SystemAccountAddress)
	accountsStub := &state.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			switch string(address) {
			case string(core.SystemAccountAddress):
				return systemAccount, nil
			default:
				return vmmock.NewAccountWrapMock(address), nil
			}
		},
		SaveAccountCalled: func(account vmcommon.AccountHandler) error { return nil },
		JournalLenCalled:  func() int { return 5 },
		RevertToSnapshotCalled: func(snapshot int) error {
			require.Equal(t, 5, snapshot)
			return nil
		},
	}

	adapter, err := newDRWAHookStateAdapter(accountsStub)
	require.NoError(t, err)
	require.NoError(t, adapter.SetAuthorizedCallerAddressVersioned(drwaSyncCallerPolicyRegistry, []byte("existing"), 2))
	require.NoError(t, adapter.SetAuthorizedCallerAddressVersioned(drwaSyncCallerAuthAdmin, testDRWACallerAddress(drwaSyncCallerAuthAdmin), 1))

	stalePayload := buildBinaryEnvelope(t, drwaSyncCallerAuthAdmin, []drwaSyncOperation{{
		OperationType: drwaSyncOpAuthorizedCallerUpdate,
		TokenID:       drwaSyncCallerPolicyRegistry,
		Version:       2,
		Body:          []byte("0x1111111111111111111111111111111111111111111111111111111111111111"),
	}})

	hook := &BlockChainHookImpl{
		accounts:      accountsStub,
		currentHdr:    &block.Header{},
		epochStartHdr: &block.Header{},
	}

	err = hook.ApplyDRWASyncEnvelopeBytes(stalePayload, testDRWACallerAddress(drwaSyncCallerAuthAdmin))
	require.Error(t, err)
	require.Contains(t, err.Error(), drwaSyncRejectReplayDuplicate)

	address, version, err := adapter.GetAuthorizedCallerAddressVersioned(drwaSyncCallerPolicyRegistry)
	require.NoError(t, err)
	require.Equal(t, []byte("existing"), address)
	require.Equal(t, uint64(2), version)
}
