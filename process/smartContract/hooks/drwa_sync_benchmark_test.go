package hooks

import (
	"testing"
)

func BenchmarkApplyDRWASyncEnvelope_TokenPolicySingle(b *testing.B) {
	adapter := newMockDRWASyncStateAdapter()
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "CARBON-1",
			Version:       1,
			Body:          []byte(`{"drwa_enabled":true,"global_pause":false}`),
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		adapter.tokenVersions["CARBON-1"] = 0
		_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
		if err != nil {
			b.Fatalf("apply sync: %v", err)
		}
	}
}

func BenchmarkApplyDRWASyncEnvelope_HolderMirrorBatch8(b *testing.B) {
	adapter := newMockDRWASyncStateAdapter()
	operations := make([]drwaSyncOperation, 0, 8)
	for i := 0; i < 8; i++ {
		operations = append(operations, drwaSyncOperation{
			OperationType: drwaSyncOpHolderMirror,
			TokenID:       "CARBON-1",
			Holder:        "holder-" + string(rune('a'+i)),
			Version:       1,
			Body:          []byte(`{"kyc_status":"approved","aml_status":"approved"}`),
		})
	}

	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerAssetManager,
		Operations:   operations,
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, op := range operations {
			adapter.holderVersions[op.TokenID+"|"+op.Holder] = 0
		}
		_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerAssetManager))
		if err != nil {
			b.Fatalf("apply sync batch: %v", err)
		}
	}
}

func BenchmarkApplyDRWASyncEnvelope_AuthorizedCallerUpdate(b *testing.B) {
	adapter := newMockDRWASyncStateAdapter()
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerAuthAdmin,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpAuthorizedCallerUpdate,
			TokenID:       drwaSyncCallerPolicyRegistry,
			Version:       1,
			Body:          []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		adapter.authorizedCallerVersions[drwaSyncCallerPolicyRegistry] = 0
		_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerAuthAdmin))
		if err != nil {
			b.Fatalf("apply sync: %v", err)
		}
	}
}
