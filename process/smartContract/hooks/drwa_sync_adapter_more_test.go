package hooks

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/testscommon/state"
	vmmock "github.com/multiversx/mx-chain-vm-common-go/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
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

	// After deletion, a JSON tombstone ({"version":N,"body":null}) is written
	// instead of nil. This prevents re-enrollment at version 1.
	deletedValue, _, err := holderAccount.AccountDataHandler().RetrieveValue(buildDRWAHolderMirrorKey([]byte("CARBON-1"), holderAddress))
	require.NoError(t, err)
	require.NotEmpty(t, deletedValue, "expected JSON tombstone after deletion")

	tombstone := &drwaSyncStoredValue{}
	require.NoError(t, json.Unmarshal(deletedValue, tombstone), "tombstone must be valid JSON")
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
		JournalLenCalled: func() int { return 1 },
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

	failSave = true
	require.ErrorIs(t, adapter.PutTokenPolicyBody("CARBON-1", 1, []byte(`{}`)), saveErr)
	require.ErrorIs(t, adapter.PutHolderMirrorBody("CARBON-1", string(holderAddress), 1, []byte(`{}`)), saveErr)
	require.ErrorIs(t, adapter.PutHolderProfileBody(string(holderAddress), 1, []byte(`{}`)), saveErr)
	require.ErrorIs(t, adapter.PutHolderAuditorAuthorizationBody("CARBON-1", string(holderAddress), 1, []byte(`{}`)), saveErr)
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
	require.ErrorIs(t, hook.ApplyDRWASyncEnvelopeBytes(hookPayload, []byte("policy_registry")), ErrNilDRWAAccountsAdapter)
}

func TestBlockChainHookApplyDRWASyncEnvelopeBytesRejectsMalformedPayload(t *testing.T) {
	hook := &BlockChainHookImpl{}
	require.Error(t, hook.ApplyDRWASyncEnvelopeBytes([]byte("bad-payload"), []byte("caller")))
}
