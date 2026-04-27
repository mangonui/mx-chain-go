package statusHandler

import "strings"

// StatusMetricsMap will return all metrics in a map
func (sm *statusMetrics) StatusMetricsMap() map[string]interface{} {
	return sm.getMetricsWithKeyFilterMutexProtected(func(_ string) bool {
		return true
	})
}

func DrwaGateMetricsSnapshotProviderForTests() func() map[string]uint64 {
	return drwaGateMetricsSnapshotProvider
}

func SetDrwaGateMetricsSnapshotProviderForTests(provider func() map[string]uint64) {
	drwaGateMetricsSnapshotProvider = provider
}

func DrwaSyncMetricsSnapshotProviderForTests() func() map[string]uint64 {
	return drwaSyncMetricsSnapshotProvider
}

func SetDrwaSyncMetricsSnapshotProviderForTests(provider func() map[string]uint64) {
	drwaSyncMetricsSnapshotProvider = provider
}

func AppendSnapshotPrometheusMetricsForTests(builder *strings.Builder, shardID uint64, prefix string, metrics map[string]uint64) {
	appendSnapshotPrometheusMetrics(builder, shardID, prefix, metrics)
}
