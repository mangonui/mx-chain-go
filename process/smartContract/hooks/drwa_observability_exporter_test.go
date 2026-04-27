package hooks

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetDRWASyncMetricsExporter_RecordDRWAMetricInvokesExporter(t *testing.T) {
	resetDRWAMetrics()
	SetDRWASyncMetricsExporter(nil)
	defer SetDRWASyncMetricsExporter(nil)

	var calledMetric string
	var calledDelta uint64
	SetDRWASyncMetricsExporter(func(metric string, delta uint64) {
		calledMetric = metric
		calledDelta = delta
	})

	recordDRWAMetric(drwaMetricSyncApplySuccess)

	require.Equal(t, drwaMetricSyncApplySuccess, calledMetric)
	require.Equal(t, uint64(1), calledDelta)
	require.Equal(t, uint64(1), SnapshotDRWASyncMetrics()[drwaMetricSyncApplySuccess])
}

func TestSetDRWASyncMetricsExporter_ExporterPanicDoesNotBreakCounterUpdate(t *testing.T) {
	resetDRWAMetrics()
	SetDRWASyncMetricsExporter(nil)
	defer SetDRWASyncMetricsExporter(nil)

	SetDRWASyncMetricsExporter(func(metric string, delta uint64) {
		panic("boom")
	})

	recordDRWAMetric(drwaMetricSyncApplyFailure)

	require.Equal(t, uint64(1), SnapshotDRWASyncMetrics()[drwaMetricSyncApplyFailure])
}
