package hooks

import (
	"bytes"
	"math/big"
	"testing"

	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/statistics"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/state"
	stateDisabled "github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/state/factory"
	"github.com/multiversx/mx-chain-go/state/iteratorChannelsProvider"
	"github.com/multiversx/mx-chain-go/state/lastSnapshotMarker"
	"github.com/multiversx/mx-chain-go/state/stateAccesses"
	"github.com/multiversx/mx-chain-go/state/storagePruningManager"
	"github.com/multiversx/mx-chain-go/state/storagePruningManager/evictionWaitingList"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	teststate "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/testscommon/storage"
	"github.com/multiversx/mx-chain-go/trie"
)

func createRealAccountsDBForDRWATest(t *testing.T) *state.AccountsDB {
	t.Helper()

	enableEpochsHandler := &enableEpochsHandlerMock.EnableEpochsHandlerStub{}
	db := testscommon.NewSnapshotPruningStorerMock()
	marshaller := storage.GetStorageManagerArgs().Marshalizer
	hasher := storage.GetStorageManagerArgs().Hasher

	args := storage.GetStorageManagerArgs()
	args.MainStorer = db
	trieStorage, err := trie.NewTrieStorageManager(args)
	require.NoError(t, err)

	tr, err := trie.NewTrie(trieStorage, marshaller, hasher, enableEpochsHandler, 5)
	require.NoError(t, err)

	ewl, err := evictionWaitingList.NewMemoryEvictionWaitingList(evictionWaitingList.MemoryEvictionWaitingListArgs{
		RootHashesSize: 100,
		HashesSize:     10000,
	})
	require.NoError(t, err)

	spm, err := storagePruningManager.NewStoragePruningManager(ewl, config.TrieStorageManagerConfig{
		PruningBufferLen:      1000,
		SnapshotsBufferLen:    10,
		SnapshotsGoroutineNum: 1,
	}.PruningBufferLen)
	require.NoError(t, err)

	accountFactory, err := factory.NewAccountCreator(factory.ArgsAccountCreator{
		Hasher:                 hasher,
		Marshaller:             marshaller,
		EnableEpochsHandler:    enableEpochsHandler,
		StateAccessesCollector: &teststate.StateAccessesCollectorStub{},
	})
	require.NoError(t, err)

	snapshotsManager, err := state.NewSnapshotsManager(state.ArgsNewSnapshotsManager{
		ProcessingMode:       common.Normal,
		Marshaller:           marshaller,
		AddressConverter:     &testscommon.PubkeyConverterMock{},
		ProcessStatusHandler: &testscommon.ProcessStatusHandlerStub{},
		StateMetrics:         &teststate.StateMetricsStub{},
		AccountFactory:       accountFactory,
		ChannelsProvider:     iteratorChannelsProvider.NewUserStateIteratorChannelsProvider(),
		LastSnapshotMarker:   lastSnapshotMarker.NewLastSnapshotMarker(),
		StateStatsHandler:    statistics.NewStateStatistics(),
	})
	require.NoError(t, err)

	collector, err := stateAccesses.NewCollector(
		stateDisabled.NewDisabledStateAccessesStorer(),
		stateAccesses.WithCollectWrite(),
	)
	require.NoError(t, err)

	adb, err := state.NewAccountsDB(state.ArgsAccountsDB{
		Trie:                   tr,
		Hasher:                 hasher,
		Marshaller:             marshaller,
		AccountFactory:         accountFactory,
		StoragePruningManager:  spm,
		AddressConverter:       &testscommon.PubkeyConverterMock{},
		SnapshotsManager:       snapshotsManager,
		StateAccessesCollector: collector,
	})
	require.NoError(t, err)

	return adb
}

func TestDRWAHookStateAdapterRealAccountsDBWritesHolderProfileOnFreshAccount(t *testing.T) {
	adb := createRealAccountsDBForDRWATest(t)
	adapter, err := newDRWAHookStateAdapter(adb)
	require.NoError(t, err)

	holderAddress := teststate.NewAccountWrapMock(make([]byte, 32)).AddressBytes()

	version, err := adapter.GetHolderProfileVersion(string(holderAddress))
	require.NoError(t, err)
	require.Equal(t, uint64(0), version)

	err = adapter.PutHolderProfileBody(string(holderAddress), 1, []byte(`{"kyc_status":"approved"}`))
	require.NoError(t, err)

	version, err = adapter.GetHolderProfileVersion(string(holderAddress))
	require.NoError(t, err)
	require.Equal(t, uint64(1), version)
}

func TestDRWAHookStateAdapterRealAccountsDBWritesHolderProfileOnExistingAccountWithoutDataTrie(t *testing.T) {
	adb := createRealAccountsDBForDRWATest(t)
	adapter, err := newDRWAHookStateAdapter(adb)
	require.NoError(t, err)

	holderAddress := bytes.Repeat([]byte{0x39}, drwaAuthorizedCallerAddressLen)

	account, err := adb.LoadAccount(holderAddress)
	require.NoError(t, err)

	userAccount, ok := account.(vmcommon.UserAccountHandler)
	require.True(t, ok)
	require.NoError(t, userAccount.AddToBalance(big.NewInt(1)))
	require.NoError(t, adb.SaveAccount(userAccount))

	version, err := adapter.GetHolderProfileVersion(string(holderAddress))
	require.NoError(t, err)
	require.Equal(t, uint64(0), version)

	err = adapter.PutHolderProfileBody(string(holderAddress), 1, []byte(`{"kyc_status":"approved"}`))
	require.NoError(t, err)

	version, err = adapter.GetHolderProfileVersion(string(holderAddress))
	require.NoError(t, err)
	require.Equal(t, uint64(1), version)
}

func TestDRWAApplySyncEnvelopeRealAccountsDBFreshHolderProfile(t *testing.T) {
	adb := createRealAccountsDBForDRWATest(t)
	adapter, err := newDRWAHookStateAdapter(adb)
	require.NoError(t, err)

	callerAddress := bytes.Repeat([]byte{0x11}, drwaAuthorizedCallerAddressLen)
	require.NoError(t, adapter.SetAuthorizedCallerAddressVersioned(drwaSyncCallerIdentityRegistry, callerAddress, 1))

	holderAddress := bytes.Repeat([]byte{0x22}, drwaAuthorizedCallerAddressLen)
	profileBody := []byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 8, 'a', 'p', 'p', 'r', 'o', 'v', 'e', 'd', 0, 0, 0, 5, 'c', 'l', 'e', 'a', 'r', 0, 0, 0, 0, 0, 0, 0, 2, 'U', 'S', 0, 0, 0, 0, 0, 0, 0, 0}
	operations := []drwaSyncOperation{{
		OperationType: drwaSyncOpHolderProfile,
		TokenID:       "",
		Holder:        string(holderAddress),
		Version:       1,
		Body:          profileBody,
	}}

	payloadHash, err := computeDRWASyncHash(drwaSyncCallerIdentityRegistry, operations)
	require.NoError(t, err)

	result, err := applyDRWASyncEnvelope(adapter, &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerIdentityRegistry,
		PayloadHash:  payloadHash,
		Operations:   operations,
	}, drwaSyncMaxOperations, callerAddress)
	require.NoError(t, err)
	require.Equal(t, 1, result.AppliedOperations)

	version, err := adapter.GetHolderProfileVersion(string(holderAddress))
	require.NoError(t, err)
	require.Equal(t, uint64(1), version)
}
