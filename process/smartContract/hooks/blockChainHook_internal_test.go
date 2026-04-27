package hooks

import (
	"testing"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/stretchr/testify/assert"
)

func TestCollectActivationEpochs(t *testing.T) {
	t.Parallel()

	enableEpochs := &config.EnableEpochs{
		DoNotReturnOldBlockInBlockchainHookEnableEpoch: 0,
		ESDTEnableEpoch:                                10,
		IsPayableBySCEnableEpoch:                       11,
		MaxNodesChangeEnableEpoch: []config.MaxNodesChangeConfig{
			{EpochEnable: 7},
		},
		BLSMultiSignerEnableEpoch: []config.MultiSignerConfig{
			{EnableEpoch: 8},
		},
	}

	activationEpochs, skippedFields := collectActivationEpochs(enableEpochs)

	assert.Len(t, activationEpochs, 3)
	assert.Contains(t, activationEpochs, uint32(0))
	assert.Contains(t, activationEpochs, uint32(10))
	assert.Contains(t, activationEpochs, uint32(11))
	assert.Contains(t, skippedFields, "MaxNodesChangeEnableEpoch")
	assert.Contains(t, skippedFields, "BLSMultiSignerEnableEpoch")
}
