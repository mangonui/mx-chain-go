package chainSimulator

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/errors"
	chainSimulatorCommon "github.com/multiversx/mx-chain-go/integrationTests/chainSimulator"
	"github.com/multiversx/mx-chain-go/node/chainSimulator/components/api"
	"github.com/multiversx/mx-chain-go/node/chainSimulator/configs"
	"github.com/multiversx/mx-chain-go/node/chainSimulator/dtos"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	defaultPathToInitialConfig = "../../cmd/node/config/"
)

func TestNewChainSimulator(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	startTime := time.Now().Unix()
	roundDurationInMillis := uint64(6000)
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck: true,
		TempDir:                t.TempDir(),
		PathToInitialConfig:    defaultPathToInitialConfig,
		NumOfShards:            3,
		GenesisTimestamp:       startTime,
		RoundDurationInMillis:  roundDurationInMillis,
		RoundsPerEpoch: core.OptionalUint64{
			HasValue: true,
			Value:    20,
		},
		ApiInterface:      api.NewNoApiInterface(),
		MinNodesPerShard:  3,
		MetaChainMinNodes: 3,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	for i := 0; i < 8; i++ {
		err = chainSimulator.ForceChangeOfEpoch()
		require.Nil(t, err)
	}

	err = chainSimulator.GenerateBlocks(50)
	require.Nil(t, err)

	time.Sleep(time.Second)

	chainSimulator.Close()
}

func TestChainSimulator_GenerateBlocksShouldWork(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	startTime := time.Now().Unix()
	roundDurationInMillis := uint64(6000)
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck: true,
		TempDir:                t.TempDir(),
		PathToInitialConfig:    defaultPathToInitialConfig,
		NumOfShards:            3,
		GenesisTimestamp:       startTime,
		RoundDurationInMillis:  roundDurationInMillis,
		RoundsPerEpoch: core.OptionalUint64{
			HasValue: true,
			Value:    20,
		},
		ApiInterface:      api.NewNoApiInterface(),
		MinNodesPerShard:  1,
		MetaChainMinNodes: 1,
		InitialRound:      200000000,
		InitialEpoch:      100,
		InitialNonce:      100,
		AlterConfigsFunction: func(cfg *config.Configs) {
			// we need to enable this as this test skips a lot of epoch activations events, and it will fail otherwise
			// because the owner of a BLS key coming from genesis is not set
			// (the owner is not set at genesis anymore because we do not enable the staking v2 in that phase)
			cfg.EpochConfig.EnableEpochs.StakingV2EnableEpoch = 0
		},
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)
	defer chainSimulator.Close()

	time.Sleep(time.Second)

	err = chainSimulator.GenerateBlocks(50)
	require.Nil(t, err)

	heartBeats, err := chainSimulator.GetNodeHandler(0).GetFacadeHandler().GetHeartbeats()
	require.Nil(t, err)
	require.Equal(t, 4, len(heartBeats))

}

func TestChainSimulator_GenerateBlocksAndEpochChangeShouldWork(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	startTime := time.Now().Unix()
	roundDurationInMillis := uint64(6000)
	roundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    20,
	}
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck: true,
		TempDir:                t.TempDir(),
		PathToInitialConfig:    defaultPathToInitialConfig,
		NumOfShards:            3,
		GenesisTimestamp:       startTime,
		RoundDurationInMillis:  roundDurationInMillis,
		RoundsPerEpoch:         roundsPerEpoch,
		ApiInterface:           api.NewNoApiInterface(),
		MinNodesPerShard:       100,
		MetaChainMinNodes:      100,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	defer chainSimulator.Close()

	facade, err := NewChainSimulatorFacade(chainSimulator)
	require.Nil(t, err)

	genesisBalances := make(map[string]*big.Int)
	for _, stakeWallet := range chainSimulator.initialWalletKeys.StakeWallets {
		initialAccount, errGet := facade.GetExistingAccountFromBech32AddressString(stakeWallet.Address.Bech32)
		require.Nil(t, errGet)

		genesisBalances[stakeWallet.Address.Bech32] = initialAccount.GetBalance()
	}

	time.Sleep(time.Second)

	err = chainSimulator.GenerateBlocks(80)
	require.Nil(t, err)

	numAccountsWithIncreasedBalances := 0
	for _, stakeWallet := range chainSimulator.initialWalletKeys.StakeWallets {
		account, errGet := facade.GetExistingAccountFromBech32AddressString(stakeWallet.Address.Bech32)
		require.Nil(t, errGet)

		if account.GetBalance().Cmp(genesisBalances[stakeWallet.Address.Bech32]) > 0 {
			numAccountsWithIncreasedBalances++
		}
	}

	assert.True(t, numAccountsWithIncreasedBalances > 0)
}

func TestSimulator_TriggerChangeOfEpoch(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	startTime := time.Now().Unix()
	roundDurationInMillis := uint64(6000)
	roundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    15000,
	}
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck: true,
		TempDir:                t.TempDir(),
		PathToInitialConfig:    defaultPathToInitialConfig,
		NumOfShards:            3,
		GenesisTimestamp:       startTime,
		RoundDurationInMillis:  roundDurationInMillis,
		RoundsPerEpoch:         roundsPerEpoch,
		ApiInterface:           api.NewNoApiInterface(),
		MinNodesPerShard:       100,
		MetaChainMinNodes:      100,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	defer chainSimulator.Close()

	err = chainSimulator.ForceChangeOfEpoch()
	require.Nil(t, err)

	err = chainSimulator.ForceChangeOfEpoch()
	require.Nil(t, err)

	err = chainSimulator.ForceChangeOfEpoch()
	require.Nil(t, err)

	err = chainSimulator.ForceChangeOfEpoch()
	require.Nil(t, err)

	metaNode := chainSimulator.GetNodeHandler(core.MetachainShardId)
	currentEpoch := metaNode.GetProcessComponents().EpochStartTrigger().Epoch()
	require.Equal(t, uint32(4), currentEpoch)
}

func TestChainSimulator_SetState(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	startTime := time.Now().Unix()
	roundDurationInMillis := uint64(6000)
	roundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    20,
	}
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck: true,
		TempDir:                t.TempDir(),
		PathToInitialConfig:    defaultPathToInitialConfig,
		NumOfShards:            3,
		GenesisTimestamp:       startTime,
		RoundDurationInMillis:  roundDurationInMillis,
		RoundsPerEpoch:         roundsPerEpoch,
		ApiInterface:           api.NewNoApiInterface(),
		MinNodesPerShard:       1,
		MetaChainMinNodes:      1,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	defer chainSimulator.Close()

	chainSimulatorCommon.CheckSetState(t, chainSimulator, chainSimulator.GetNodeHandler(0))
}

func TestChainSimulator_SetStateMultiple_SystemAccountReplicatesAcrossShards(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	startTime := time.Now().Unix()
	roundDurationInMillis := uint64(6000)
	roundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    20,
	}
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck: true,
		TempDir:                t.TempDir(),
		PathToInitialConfig:    defaultPathToInitialConfig,
		NumOfShards:            3,
		GenesisTimestamp:       startTime,
		RoundDurationInMillis:  roundDurationInMillis,
		RoundsPerEpoch:         roundsPerEpoch,
		ApiInterface:           api.NewNoApiInterface(),
		MinNodesPerShard:       1,
		MetaChainMinNodes:      1,
	})
	require.NoError(t, err)
	require.NotNil(t, chainSimulator)
	defer chainSimulator.Close()

	const systemAccount = "erd1lllllllllllllllllllllllllllllllllllllllllllllllllllsckry7t"
	const authKey = "drwa:auth:identity_registry"
	const authValue = "0000000000000000050020ff05831a43c822781252791020a395abdbcc54ed60"

	addressConverter := chainSimulator.GetNodeHandler(core.MetachainShardId).GetCoreComponents().AddressPubKeyConverter()
	systemAccountBytes, err := addressConverter.Decode(systemAccount)
	require.NoError(t, err)
	require.Equal(t, core.SystemAccountAddress, systemAccountBytes)

	err = chainSimulator.SetStateMultiple([]*dtos.AddressState{
		{
			Address: systemAccount,
			Pairs: map[string]string{
				hex.EncodeToString([]byte(authKey)): authValue,
			},
		},
	})
	require.NoError(t, err)

	expectedValue, err := hex.DecodeString(authValue)
	require.NoError(t, err)

	for _, shardID := range []uint32{0, 1, 2, core.MetachainShardId} {
		nodeHandler := chainSimulator.GetNodeHandler(shardID)
		account, loadErr := nodeHandler.GetStateComponents().AccountsAdapter().LoadAccount(core.SystemAccountAddress)
		require.NoError(t, loadErr, "shard %d should load system account", shardID)
		userAccount, ok := account.(state.UserAccountHandler)
		require.True(t, ok, "shard %d system account should be a user account", shardID)
		require.NotEmpty(t, userAccount.GetRootHash(), "shard %d system account should have a data trie root hash after SetStateMultiple", shardID)

		value, _, retrieveErr := userAccount.RetrieveValue([]byte(authKey))
		require.NoError(t, retrieveErr, "shard %d should retrieve DRWA authorized caller key", shardID)
		require.Equal(t, expectedValue, value, "shard %d should have replicated DRWA authorized caller value", shardID)
	}
}

func TestChainSimulator_SetKeyValueForAddress_SystemAccountReplicatesAcrossShards(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	startTime := time.Now().Unix()
	roundDurationInMillis := uint64(6000)
	roundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    20,
	}
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck: true,
		TempDir:                t.TempDir(),
		PathToInitialConfig:    defaultPathToInitialConfig,
		NumOfShards:            3,
		GenesisTimestamp:       startTime,
		RoundDurationInMillis:  roundDurationInMillis,
		RoundsPerEpoch:         roundsPerEpoch,
		ApiInterface:           api.NewNoApiInterface(),
		MinNodesPerShard:       1,
		MetaChainMinNodes:      1,
	})
	require.NoError(t, err)
	require.NotNil(t, chainSimulator)
	defer chainSimulator.Close()

	const systemAccount = "erd1lllllllllllllllllllllllllllllllllllllllllllllllllllsckry7t"
	const authKey = "drwa:auth:identity_registry"
	const authValue = "0000000000000000050020ff05831a43c822781252791020a395abdbcc54ed60"

	addressConverter := chainSimulator.GetNodeHandler(core.MetachainShardId).GetCoreComponents().AddressPubKeyConverter()
	systemAccountBytes, err := addressConverter.Decode(systemAccount)
	require.NoError(t, err)
	require.Equal(t, core.SystemAccountAddress, systemAccountBytes)

	err = chainSimulator.SetKeyValueForAddress(systemAccount, map[string]string{
		hex.EncodeToString([]byte(authKey)): authValue,
	})
	require.NoError(t, err)

	expectedValue, err := hex.DecodeString(authValue)
	require.NoError(t, err)

	for _, shardID := range []uint32{0, 1, 2, core.MetachainShardId} {
		nodeHandler := chainSimulator.GetNodeHandler(shardID)
		account, loadErr := nodeHandler.GetStateComponents().AccountsAdapter().LoadAccount(core.SystemAccountAddress)
		require.NoError(t, loadErr, "shard %d should load system account", shardID)
		userAccount, ok := account.(state.UserAccountHandler)
		require.True(t, ok, "shard %d system account should be a user account", shardID)
		require.NotEmpty(t, userAccount.GetRootHash(), "shard %d system account should have a data trie root hash after SetKeyValueForAddress", shardID)

		value, _, retrieveErr := userAccount.RetrieveValue([]byte(authKey))
		require.NoError(t, retrieveErr, "shard %d should retrieve DRWA authorized caller key", shardID)
		require.Equal(t, expectedValue, value, "shard %d should have replicated DRWA authorized caller value", shardID)
	}
}

func TestChainSimulator_setKeyValueSystemAccount_ReplicatesAcrossShards(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	startTime := time.Now().Unix()
	roundDurationInMillis := uint64(6000)
	roundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    20,
	}
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck: true,
		TempDir:                t.TempDir(),
		PathToInitialConfig:    defaultPathToInitialConfig,
		NumOfShards:            3,
		GenesisTimestamp:       startTime,
		RoundDurationInMillis:  roundDurationInMillis,
		RoundsPerEpoch:         roundsPerEpoch,
		ApiInterface:           api.NewNoApiInterface(),
		MinNodesPerShard:       1,
		MetaChainMinNodes:      1,
	})
	require.NoError(t, err)
	require.NotNil(t, chainSimulator)
	defer chainSimulator.Close()

	const authKey = "drwa:auth:identity_registry"
	const authValue = "0000000000000000050020ff05831a43c822781252791020a395abdbcc54ed60"

	err = chainSimulator.setKeyValueSystemAccount(map[string]string{
		hex.EncodeToString([]byte(authKey)): authValue,
	})
	require.NoError(t, err)

	expectedValue, err := hex.DecodeString(authValue)
	require.NoError(t, err)

	for _, shardID := range []uint32{0, 1, 2, core.MetachainShardId} {
		nodeHandler := chainSimulator.GetNodeHandler(shardID)
		account, loadErr := nodeHandler.GetStateComponents().AccountsAdapter().LoadAccount(core.SystemAccountAddress)
		require.NoError(t, loadErr, "shard %d should load system account", shardID)
		userAccount, ok := account.(state.UserAccountHandler)
		require.True(t, ok, "shard %d system account should be a user account", shardID)
		require.NotEmpty(t, userAccount.GetRootHash(), "shard %d system account should have a data trie root hash after setKeyValueSystemAccount", shardID)

		value, _, retrieveErr := userAccount.RetrieveValue([]byte(authKey))
		require.NoError(t, retrieveErr, "shard %d should retrieve DRWA authorized caller key", shardID)
		require.Equal(t, expectedValue, value, "shard %d should have replicated DRWA authorized caller value", shardID)
	}
}

func TestChainSimulator_setKeyValueSystemAccount_WithSimulatorMutexHeld_ReplicatesAcrossShards(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	startTime := time.Now().Unix()
	roundDurationInMillis := uint64(6000)
	roundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    20,
	}
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck: true,
		TempDir:                t.TempDir(),
		PathToInitialConfig:    defaultPathToInitialConfig,
		NumOfShards:            3,
		GenesisTimestamp:       startTime,
		RoundDurationInMillis:  roundDurationInMillis,
		RoundsPerEpoch:         roundsPerEpoch,
		ApiInterface:           api.NewNoApiInterface(),
		MinNodesPerShard:       1,
		MetaChainMinNodes:      1,
	})
	require.NoError(t, err)
	require.NotNil(t, chainSimulator)
	defer chainSimulator.Close()

	const authKey = "drwa:auth:identity_registry"
	const authValue = "0000000000000000050020ff05831a43c822781252791020a395abdbcc54ed60"

	chainSimulator.mutex.Lock()
	err = chainSimulator.setKeyValueSystemAccount(map[string]string{
		hex.EncodeToString([]byte(authKey)): authValue,
	})
	chainSimulator.mutex.Unlock()
	require.NoError(t, err)

	expectedValue, err := hex.DecodeString(authValue)
	require.NoError(t, err)

	for _, shardID := range []uint32{0, 1, 2, core.MetachainShardId} {
		nodeHandler := chainSimulator.GetNodeHandler(shardID)
		account, loadErr := nodeHandler.GetStateComponents().AccountsAdapter().LoadAccount(core.SystemAccountAddress)
		require.NoError(t, loadErr, "shard %d should load system account", shardID)
		userAccount, ok := account.(state.UserAccountHandler)
		require.True(t, ok, "shard %d system account should be a user account", shardID)
		require.NotEmpty(t, userAccount.GetRootHash(), "shard %d system account should have a data trie root hash after locked setKeyValueSystemAccount", shardID)

		value, _, retrieveErr := userAccount.RetrieveValue([]byte(authKey))
		require.NoError(t, retrieveErr, "shard %d should retrieve DRWA authorized caller key", shardID)
		require.Equal(t, expectedValue, value, "shard %d should have replicated DRWA authorized caller value", shardID)
	}
}

func TestChainSimulator_SystemAccountDirectSaveAccountPersistsAcrossCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	startTime := time.Now().Unix()
	roundDurationInMillis := uint64(6000)
	roundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    20,
	}
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck: true,
		TempDir:                t.TempDir(),
		PathToInitialConfig:    defaultPathToInitialConfig,
		NumOfShards:            3,
		GenesisTimestamp:       startTime,
		RoundDurationInMillis:  roundDurationInMillis,
		RoundsPerEpoch:         roundsPerEpoch,
		ApiInterface:           api.NewNoApiInterface(),
		MinNodesPerShard:       1,
		MetaChainMinNodes:      1,
	})
	require.NoError(t, err)
	require.NotNil(t, chainSimulator)
	defer chainSimulator.Close()

	const authKey = "drwa:auth:identity_registry"
	const authValueHex = "0000000000000000050020ff05831a43c822781252791020a395abdbcc54ed60"

	authValue, err := hex.DecodeString(authValueHex)
	require.NoError(t, err)

	nodeHandler := chainSimulator.GetNodeHandler(0)
	accountsAdapter := nodeHandler.GetStateComponents().AccountsAdapter()

	account, err := accountsAdapter.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	userAccount, ok := account.(state.UserAccountHandler)
	require.True(t, ok)

	err = userAccount.SaveKeyValue([]byte(authKey), authValue)
	require.NoError(t, err)
	err = accountsAdapter.SaveAccount(userAccount)
	require.NoError(t, err)

	accountBeforeCommit, err := accountsAdapter.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	userAccountBeforeCommit, ok := accountBeforeCommit.(state.UserAccountHandler)
	require.True(t, ok)
	t.Logf("before commit system root hash: %x", userAccountBeforeCommit.GetRootHash())

	valueBeforeCommit, _, err := userAccountBeforeCommit.RetrieveValue([]byte(authKey))
	require.NoError(t, err)
	t.Logf("before commit system value len: %d", len(valueBeforeCommit))

	_, err = accountsAdapter.Commit()
	require.NoError(t, err)

	accountAfterCommit, err := accountsAdapter.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	userAccountAfterCommit, ok := accountAfterCommit.(state.UserAccountHandler)
	require.True(t, ok)
	t.Logf("after commit system root hash: %x", userAccountAfterCommit.GetRootHash())

	valueAfterCommit, _, err := userAccountAfterCommit.RetrieveValue([]byte(authKey))
	require.NoError(t, err)
	t.Logf("after commit system value len: %d", len(valueAfterCommit))

	loadedAccountAfterCommit, err := accountsAdapter.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	loadedUserAccountAfterCommit, ok := loadedAccountAfterCommit.(state.UserAccountHandler)
	require.True(t, ok)
	t.Logf("after commit via LoadAccount root hash: %x", loadedUserAccountAfterCommit.GetRootHash())

	loadedValueAfterCommit, _, err := loadedUserAccountAfterCommit.RetrieveValue([]byte(authKey))
	require.NoError(t, err)
	t.Logf("after commit via LoadAccount value len: %d", len(loadedValueAfterCommit))
}

func TestChainSimulator_SystemAccountSequentialNodeWritesDoNotEraseEarlierShard(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	startTime := time.Now().Unix()
	roundDurationInMillis := uint64(6000)
	roundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    20,
	}
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck: true,
		TempDir:                t.TempDir(),
		PathToInitialConfig:    defaultPathToInitialConfig,
		NumOfShards:            3,
		GenesisTimestamp:       startTime,
		RoundDurationInMillis:  roundDurationInMillis,
		RoundsPerEpoch:         roundsPerEpoch,
		ApiInterface:           api.NewNoApiInterface(),
		MinNodesPerShard:       1,
		MetaChainMinNodes:      1,
	})
	require.NoError(t, err)
	require.NotNil(t, chainSimulator)
	defer chainSimulator.Close()

	const authKey = "drwa:auth:identity_registry"
	const authValueHex = "0000000000000000050020ff05831a43c822781252791020a395abdbcc54ed60"

	authValue, err := hex.DecodeString(authValueHex)
	require.NoError(t, err)

	writeOnNode := func(shardID uint32) {
		nodeHandler := chainSimulator.GetNodeHandler(shardID)
		accountsAdapter := nodeHandler.GetStateComponents().AccountsAdapter()
		account, loadErr := accountsAdapter.LoadAccount(core.SystemAccountAddress)
		require.NoError(t, loadErr)
		userAccount, ok := account.(state.UserAccountHandler)
		require.True(t, ok)
		require.NoError(t, userAccount.SaveKeyValue([]byte(authKey), authValue))
		require.NoError(t, accountsAdapter.SaveAccount(userAccount))
		_, commitErr := accountsAdapter.Commit()
		require.NoError(t, commitErr)
	}

	readFromShardZero := func() ([]byte, []byte) {
		nodeHandler := chainSimulator.GetNodeHandler(0)
		account, loadErr := nodeHandler.GetStateComponents().AccountsAdapter().GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, loadErr)
		userAccount, ok := account.(state.UserAccountHandler)
		require.True(t, ok)
		value, _, retrieveErr := userAccount.RetrieveValue([]byte(authKey))
		require.NoError(t, retrieveErr)
		return userAccount.GetRootHash(), value
	}

	writeOnNode(0)
	rootHashAfterShard0, valueAfterShard0 := readFromShardZero()
	t.Logf("after shard0 write root=%x valueLen=%d", rootHashAfterShard0, len(valueAfterShard0))
	require.NotEmpty(t, rootHashAfterShard0)
	require.Equal(t, authValue, valueAfterShard0)

	writeOnNode(1)
	rootHashAfterShard1, valueAfterShard1 := readFromShardZero()
	t.Logf("after shard1 write root=%x valueLen=%d", rootHashAfterShard1, len(valueAfterShard1))
	require.NotEmpty(t, rootHashAfterShard1)
	require.Equal(t, authValue, valueAfterShard1)

	writeOnNode(2)
	rootHashAfterShard2, valueAfterShard2 := readFromShardZero()
	t.Logf("after shard2 write root=%x valueLen=%d", rootHashAfterShard2, len(valueAfterShard2))
	require.NotEmpty(t, rootHashAfterShard2)
	require.Equal(t, authValue, valueAfterShard2)

	writeOnNode(core.MetachainShardId)
	rootHashAfterMeta, valueAfterMeta := readFromShardZero()
	t.Logf("after metachain write root=%x valueLen=%d", rootHashAfterMeta, len(valueAfterMeta))
	require.NotEmpty(t, rootHashAfterMeta)
	require.Equal(t, authValue, valueAfterMeta)
}

func TestChainSimulator_SetEntireState(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	startTime := time.Now().Unix()
	roundDurationInMillis := uint64(6000)
	roundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    20,
	}
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck: true,
		TempDir:                t.TempDir(),
		PathToInitialConfig:    defaultPathToInitialConfig,
		NumOfShards:            3,
		GenesisTimestamp:       startTime,
		RoundDurationInMillis:  roundDurationInMillis,
		RoundsPerEpoch:         roundsPerEpoch,
		ApiInterface:           api.NewNoApiInterface(),
		MinNodesPerShard:       1,
		MetaChainMinNodes:      1,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	defer chainSimulator.Close()

	balance := "431271308732096033771131"
	contractAddress := "erd1qqqqqqqqqqqqqpgqmzzm05jeav6d5qvna0q2pmcllelkz8xddz3syjszx5"
	accountState := &dtos.AddressState{
		Address:          contractAddress,
		Nonce:            new(uint64),
		Balance:          balance,
		Code:             "0061736d010000000129086000006000017f60027f7f017f60027f7f0060017f0060037f7f7f017f60037f7f7f0060017f017f0290020b03656e7619626967496e74476574556e7369676e6564417267756d656e74000303656e760f6765744e756d417267756d656e7473000103656e760b7369676e616c4572726f72000303656e76126d42756666657253746f726167654c6f6164000203656e76176d427566666572546f426967496e74556e7369676e6564000203656e76196d42756666657246726f6d426967496e74556e7369676e6564000203656e76136d42756666657253746f7261676553746f7265000203656e760f6d4275666665725365744279746573000503656e760e636865636b4e6f5061796d656e74000003656e7614626967496e7446696e697368556e7369676e6564000403656e7609626967496e744164640006030b0a010104070301000000000503010003060f027f0041a080080b7f0041a080080b074607066d656d6f7279020004696e697400110667657453756d00120361646400130863616c6c4261636b00140a5f5f646174615f656e6403000b5f5f686561705f6261736503010aca010a0e01017f4100100c2200100020000b1901017f419c8008419c800828020041016b220036020020000b1400100120004604400f0b4180800841191002000b16002000100c220010031a2000100c220010041a20000b1401017f100c2202200110051a2000200210061a0b1301017f100c220041998008410310071a20000b1401017f10084101100d100b210010102000100f0b0e0010084100100d1010100e10090b2201037f10084101100d100b210110102202100e220020002001100a20022000100f0b0300010b0b2f0200418080080b1c77726f6e67206e756d626572206f6620617267756d656e747373756d00419c80080b049cffffff",
		CodeHash:         "n9EviPlHS6EV+3Xp0YqP28T0IUfeAFRFBIRC1Jw6pyU=",
		RootHash:         "76cr5Jhn6HmBcDUMIzikEpqFgZxIrOzgNkTHNatXzC4=",
		CodeMetadata:     "BQY=",
		Owner:            "erd1ss6u80ruas2phpmr82r42xnkd6rxy40g9jl69frppl4qez9w2jpsqj8x97",
		DeveloperRewards: "5401004999998",
		Pairs: map[string]string{
			"73756d": "0a",
		},
	}

	chainSimulatorCommon.CheckSetEntireState(t, chainSimulator, chainSimulator.GetNodeHandler(1), accountState)
}

func TestChainSimulator_SetEntireStateWithRemoval(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	startTime := time.Now().Unix()
	roundDurationInMillis := uint64(6000)
	roundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    20,
	}
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck: true,
		TempDir:                t.TempDir(),
		PathToInitialConfig:    defaultPathToInitialConfig,
		NumOfShards:            3,
		GenesisTimestamp:       startTime,
		RoundDurationInMillis:  roundDurationInMillis,
		RoundsPerEpoch:         roundsPerEpoch,
		ApiInterface:           api.NewNoApiInterface(),
		MinNodesPerShard:       1,
		MetaChainMinNodes:      1,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	defer chainSimulator.Close()

	balance := "431271308732096033771131"
	contractAddress := "erd1qqqqqqqqqqqqqpgqmzzm05jeav6d5qvna0q2pmcllelkz8xddz3syjszx5"
	accountState := &dtos.AddressState{
		Address:          contractAddress,
		Nonce:            new(uint64),
		Balance:          balance,
		Code:             "0061736d010000000129086000006000017f60027f7f017f60027f7f0060017f0060037f7f7f017f60037f7f7f0060017f017f0290020b03656e7619626967496e74476574556e7369676e6564417267756d656e74000303656e760f6765744e756d417267756d656e7473000103656e760b7369676e616c4572726f72000303656e76126d42756666657253746f726167654c6f6164000203656e76176d427566666572546f426967496e74556e7369676e6564000203656e76196d42756666657246726f6d426967496e74556e7369676e6564000203656e76136d42756666657253746f7261676553746f7265000203656e760f6d4275666665725365744279746573000503656e760e636865636b4e6f5061796d656e74000003656e7614626967496e7446696e697368556e7369676e6564000403656e7609626967496e744164640006030b0a010104070301000000000503010003060f027f0041a080080b7f0041a080080b074607066d656d6f7279020004696e697400110667657453756d00120361646400130863616c6c4261636b00140a5f5f646174615f656e6403000b5f5f686561705f6261736503010aca010a0e01017f4100100c2200100020000b1901017f419c8008419c800828020041016b220036020020000b1400100120004604400f0b4180800841191002000b16002000100c220010031a2000100c220010041a20000b1401017f100c2202200110051a2000200210061a0b1301017f100c220041998008410310071a20000b1401017f10084101100d100b210010102000100f0b0e0010084100100d1010100e10090b2201037f10084101100d100b210110102202100e220020002001100a20022000100f0b0300010b0b2f0200418080080b1c77726f6e67206e756d626572206f6620617267756d656e747373756d00419c80080b049cffffff",
		CodeHash:         "n9EviPlHS6EV+3Xp0YqP28T0IUfeAFRFBIRC1Jw6pyU=",
		RootHash:         "eqIumOaMn7G5cNSViK3XHZIW/C392ehfHxOZkHGp+Gc=", // root hash with auto balancing enabled
		CodeMetadata:     "BQY=",
		Owner:            "erd1ss6u80ruas2phpmr82r42xnkd6rxy40g9jl69frppl4qez9w2jpsqj8x97",
		DeveloperRewards: "5401004999998",
		Pairs: map[string]string{
			"73756d": "0a",
		},
	}
	chainSimulatorCommon.CheckSetEntireStateWithRemoval(t, chainSimulator, chainSimulator.GetNodeHandler(1), accountState)
}

func TestChainSimulator_GetAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	startTime := time.Now().Unix()
	roundDurationInMillis := uint64(6000)
	roundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    20,
	}
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck: true,
		TempDir:                t.TempDir(),
		PathToInitialConfig:    defaultPathToInitialConfig,
		NumOfShards:            3,
		GenesisTimestamp:       startTime,
		RoundDurationInMillis:  roundDurationInMillis,
		RoundsPerEpoch:         roundsPerEpoch,
		ApiInterface:           api.NewNoApiInterface(),
		MinNodesPerShard:       1,
		MetaChainMinNodes:      1,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	// the facade's GetAccount method requires that at least one block was produced over the genesis block
	_ = chainSimulator.GenerateBlocks(1)

	defer chainSimulator.Close()

	chainSimulatorCommon.CheckGetAccount(t, chainSimulator)
}

func TestSimulator_SendTransactions(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	startTime := time.Now().Unix()
	roundDurationInMillis := uint64(6000)
	roundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    20,
	}
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck: true,
		TempDir:                t.TempDir(),
		PathToInitialConfig:    defaultPathToInitialConfig,
		NumOfShards:            3,
		GenesisTimestamp:       startTime,
		RoundDurationInMillis:  roundDurationInMillis,
		RoundsPerEpoch:         roundsPerEpoch,
		ApiInterface:           api.NewNoApiInterface(),
		MinNodesPerShard:       1,
		MetaChainMinNodes:      1,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	defer chainSimulator.Close()

	chainSimulatorCommon.CheckGenerateTransactions(t, chainSimulator)
}

func TestSimulator_SentMoveBalanceNoGasForFee(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	startTime := time.Now().Unix()
	roundDurationInMillis := uint64(6000)
	roundsPerEpoch := core.OptionalUint64{
		HasValue: true,
		Value:    20,
	}
	chainSimulator, err := NewChainSimulator(ArgsChainSimulator{
		BypassTxSignatureCheck: true,
		TempDir:                t.TempDir(),
		PathToInitialConfig:    defaultPathToInitialConfig,
		NumOfShards:            3,
		GenesisTimestamp:       startTime,
		RoundDurationInMillis:  roundDurationInMillis,
		RoundsPerEpoch:         roundsPerEpoch,
		ApiInterface:           api.NewNoApiInterface(),
		MinNodesPerShard:       1,
		MetaChainMinNodes:      1,
	})
	require.Nil(t, err)
	require.NotNil(t, chainSimulator)

	defer chainSimulator.Close()

	wallet0, err := chainSimulator.GenerateAndMintWalletAddress(0, big.NewInt(0))
	require.Nil(t, err)

	ftx := &transaction.Transaction{
		Nonce:     0,
		Value:     big.NewInt(0),
		SndAddr:   wallet0.Bytes,
		RcvAddr:   wallet0.Bytes,
		Data:      []byte(""),
		GasLimit:  50_000,
		GasPrice:  1_000_000_000,
		ChainID:   []byte(configs.ChainID),
		Version:   1,
		Signature: []byte("010101"),
	}
	_, err = chainSimulator.sendTx(ftx)
	require.True(t, strings.Contains(err.Error(), errors.ErrInsufficientFunds.Error()))
}
