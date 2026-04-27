package hooks

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type erroringDRWASyncAdapter struct {
	drwaSyncStateAdapter
	getAuthorizedCallerErr error
}

func (e *erroringDRWASyncAdapter) GetAuthorizedCallerAddress(domain string) ([]byte, error) {
	if e.getAuthorizedCallerErr != nil {
		return nil, e.getAuthorizedCallerErr
	}
	return []byte("ok"), nil
}

func (e *erroringDRWASyncAdapter) GetAuthorizedCallerAddressVersioned(domain string) ([]byte, uint64, error) {
	if e.getAuthorizedCallerErr != nil {
		return nil, 0, e.getAuthorizedCallerErr
	}
	return []byte("ok"), 0, nil
}

func (e *erroringDRWASyncAdapter) SetAuthorizedCallerAddressVersioned(domain string, address []byte, version uint64) error {
	return nil
}

func TestDRWASyncTagDecodersCoverAllValidCases(t *testing.T) {
	t.Parallel()

	for tag, expected := range map[byte]string{
		0: drwaSyncCallerPolicyRegistry,
		1: drwaSyncCallerAssetManager,
		2: drwaSyncCallerIdentityRegistry,
		3: drwaSyncCallerAttestation,
		4: drwaSyncCallerRecoveryAdmin,
		5: drwaSyncCallerAuthAdmin,
	} {
		actual, err := drwaCallerDomainFromTag(tag)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}

	for tag, expected := range map[byte]drwaSyncOperationType{
		0: drwaSyncOpTokenPolicy,
		1: drwaSyncOpAssetRecord,
		2: drwaSyncOpHolderMirror,
		3: drwaSyncOpHolderProfile,
		4: drwaSyncOpHolderAuditorAuth,
		5: drwaSyncOpHolderMirrorDelete,
		6: drwaSyncOpAuthorizedCallerUpdate,
		7: drwaSyncOpGovernanceApprove,
		8: drwaSyncOpGovernanceExecute,
	} {
		actual, err := drwaOperationTypeFromTag(tag)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
}

func TestApplyDRWASyncOperationAllSupportedTypes(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()

	require.NoError(t, applyDRWASyncOperation(adapter, drwaSyncOperation{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "CARBON-1",
		Version:       1,
		Body:          []byte(`{"regulated":true}`),
	}))
	require.NoError(t, applyDRWASyncOperation(adapter, drwaSyncOperation{
		OperationType: drwaSyncOpAssetRecord,
		TokenID:       "CARBON-1",
		Version:       1,
		Body:          []byte(`{"regulated":true}`),
	}))
	require.NoError(t, applyDRWASyncOperation(adapter, drwaSyncOperation{
		OperationType: drwaSyncOpHolderMirror,
		TokenID:       "CARBON-1",
		Holder:        "erd1holder",
		Version:       1,
		Body:          []byte(`{"kyc":"approved"}`),
	}))
	require.NoError(t, applyDRWASyncOperation(adapter, drwaSyncOperation{
		OperationType: drwaSyncOpHolderProfile,
		TokenID:       "CARBON-1",
		Holder:        "erd1holder",
		Version:       1,
		Body:          []byte(`{"kyc":"approved"}`),
	}))
	require.NoError(t, applyDRWASyncOperation(adapter, drwaSyncOperation{
		OperationType: drwaSyncOpHolderAuditorAuth,
		TokenID:       "CARBON-1",
		Holder:        "erd1holder",
		Version:       1,
		Body:          []byte(`{"auditor_authorized":true}`),
	}))
	require.NoError(t, applyDRWASyncOperation(adapter, drwaSyncOperation{
		OperationType: drwaSyncOpHolderMirrorDelete,
		TokenID:       "CARBON-1",
		Holder:        "erd1holder",
		Version:       2,
	}))
}

func TestApplyDRWASyncOperationRejectsReplayConflicts(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["CARBON-1"] = 2
	err := applyDRWASyncOperation(adapter, drwaSyncOperation{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "CARBON-1",
		Version:       2,
	})
	require.Error(t, err)

	err = applyDRWASyncOperation(adapter, drwaSyncOperation{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       "CARBON-1",
		Version:       1,
	})
	require.Error(t, err)
}

func TestIsDRWASyncCallerAuthorizedHandlesAdapterErrors(t *testing.T) {
	t.Parallel()

	adapter := &erroringDRWASyncAdapter{getAuthorizedCallerErr: errors.New("read failed")}
	allowed := isDRWASyncCallerAuthorized(adapter, drwaSyncCallerPolicyRegistry, []drwaSyncOperation{
		{OperationType: drwaSyncOpTokenPolicy},
	}, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	require.False(t, allowed)
}
