package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Helper function to get counter value
func getCounterValue(counter prometheus.Counter) float64 {
	metric := &dto.Metric{}
	counter.Write(metric)
	return metric.Counter.GetValue()
}

// Helper function to get counter vec value
func getCounterVecValue(counterVec *prometheus.CounterVec, labels ...string) float64 {
	counter, err := counterVec.GetMetricWithLabelValues(labels...)
	if err != nil {
		return 0
	}
	metric := &dto.Metric{}
	counter.Write(metric)
	return metric.Counter.GetValue()
}

// Helper function to get gauge value
func getGaugeValue(gauge prometheus.Gauge) float64 {
	metric := &dto.Metric{}
	gauge.Write(metric)
	return metric.Gauge.GetValue()
}

// Helper function to get histogram count
func getHistogramCount(histogram prometheus.Histogram) uint64 {
	metric := &dto.Metric{}
	histogram.Write(metric)
	return metric.Histogram.GetSampleCount()
}

// Helper function to get histogram sum
func getHistogramSum(histogram prometheus.Histogram) float64 {
	metric := &dto.Metric{}
	histogram.Write(metric)
	return metric.Histogram.GetSampleSum()
}

func TestRecordEvent(t *testing.T) {
	// Reset metrics
	EventsTotal.Reset()

	tests := []struct {
		name   string
		action string
		count  int
	}{
		{
			name:   "record allow",
			action: "allow",
			count:  1,
		},
		{
			name:   "record deny",
			action: "deny",
			count:  1,
		},
		{
			name:   "record log",
			action: "log",
			count:  1,
		},
		{
			name:   "multiple allows",
			action: "allow",
			count:  5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initialValue := getCounterVecValue(EventsTotal, tt.action)

			for i := 0; i < tt.count; i++ {
				RecordEvent(tt.action)
			}

			finalValue := getCounterVecValue(EventsTotal, tt.action)
			expected := initialValue + float64(tt.count)

			if finalValue != expected {
				t.Errorf("EventsTotal[%s] = %v, want %v", tt.action, finalValue, expected)
			}
		})
	}
}

func TestRecordCacheHit(t *testing.T) {
	// Reset metrics
	CacheHitsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "warmor_cache_hits_total_test",
		Help: "Test counter",
	})

	initialValue := getCounterValue(CacheHitsTotal)

	// Record multiple hits
	for i := 0; i < 10; i++ {
		RecordCacheHit()
	}

	finalValue := getCounterValue(CacheHitsTotal)
	expected := initialValue + 10

	if finalValue != expected {
		t.Errorf("CacheHitsTotal = %v, want %v", finalValue, expected)
	}
}

func TestRecordCacheMiss(t *testing.T) {
	// Reset metrics
	CacheMissesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "warmor_cache_misses_total_test",
		Help: "Test counter",
	})

	initialValue := getCounterValue(CacheMissesTotal)

	// Record multiple misses
	for i := 0; i < 5; i++ {
		RecordCacheMiss()
	}

	finalValue := getCounterValue(CacheMissesTotal)
	expected := initialValue + 5

	if finalValue != expected {
		t.Errorf("CacheMissesTotal = %v, want %v", finalValue, expected)
	}
}

func TestUpdateCacheSize(t *testing.T) {
	// Reset metrics
	CacheSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "warmor_cache_size_test",
		Help: "Test gauge",
	})

	tests := []struct {
		name string
		size int
	}{
		{
			name: "zero size",
			size: 0,
		},
		{
			name: "small size",
			size: 10,
		},
		{
			name: "medium size",
			size: 100,
		},
		{
			name: "large size",
			size: 10000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			UpdateCacheSize(tt.size)

			value := getGaugeValue(CacheSize)
			expected := float64(tt.size)

			if value != expected {
				t.Errorf("CacheSize = %v, want %v", value, expected)
			}
		})
	}
}

func TestRecordLatency(t *testing.T) {
	// Reset metrics
	EvaluationLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "warmor_evaluation_latency_microseconds_test",
		Help:    "Test histogram",
		Buckets: []float64{10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000},
	})

	tests := []struct {
		name          string
		latencies     []float64
		expectedSum   float64
		expectedCount uint64
	}{
		{
			name:          "single latency",
			latencies:     []float64{100},
			expectedSum:   100,
			expectedCount: 1,
		},
		{
			name:          "multiple latencies",
			latencies:     []float64{10, 25, 50, 100},
			expectedSum:   185,
			expectedCount: 4,
		},
		{
			name:          "high latencies",
			latencies:     []float64{1000, 2500, 5000},
			expectedSum:   8500,
			expectedCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset histogram
			EvaluationLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
				Name:    "warmor_evaluation_latency_microseconds_test_" + tt.name,
				Help:    "Test histogram",
				Buckets: []float64{10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000},
			})

			for _, latency := range tt.latencies {
				RecordLatency(latency)
			}

			count := getHistogramCount(EvaluationLatency)
			sum := getHistogramSum(EvaluationLatency)

			if count != tt.expectedCount {
				t.Errorf("EvaluationLatency count = %v, want %v", count, tt.expectedCount)
			}

			if sum != tt.expectedSum {
				t.Errorf("EvaluationLatency sum = %v, want %v", sum, tt.expectedSum)
			}
		})
	}
}

func TestSetPolicyInfo(t *testing.T) {
	// Reset metrics
	PolicyInfo.Reset()

	tests := []struct {
		name    string
		path    string
		version string
	}{
		{
			name:    "basic policy",
			path:    "/etc/warmor/policy.wasm",
			version: "1.0.0",
		},
		{
			name:    "different path",
			path:    "/opt/warmor/custom.wasm",
			version: "2.0.0",
		},
		{
			name:    "version update",
			path:    "/etc/warmor/policy.wasm",
			version: "1.1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetPolicyInfo(tt.path, tt.version)

			// Verify the metric was set (value should be 1)
			gauge, err := PolicyInfo.GetMetricWithLabelValues(tt.path, tt.version)
			if err != nil {
				t.Fatalf("Failed to get metric: %v", err)
			}

			metric := &dto.Metric{}
			gauge.Write(metric)
			value := metric.Gauge.GetValue()

			if value != 1 {
				t.Errorf("PolicyInfo value = %v, want 1", value)
			}
		})
	}
}

func TestRecordProcessingError(t *testing.T) {
	// Reset metrics
	EventsProcessingErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "warmor_events_processing_errors_total_test",
		Help: "Test counter",
	})

	initialValue := getCounterValue(EventsProcessingErrors)

	// Record multiple errors
	for i := 0; i < 3; i++ {
		RecordProcessingError()
	}

	finalValue := getCounterValue(EventsProcessingErrors)
	expected := initialValue + 3

	if finalValue != expected {
		t.Errorf("EventsProcessingErrors = %v, want %v", finalValue, expected)
	}
}

func TestMetricsIntegration(t *testing.T) {
	// Reset all metrics
	EventsTotal.Reset()
	CacheHitsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "warmor_cache_hits_total_integration",
		Help: "Test counter",
	})
	CacheMissesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "warmor_cache_misses_total_integration",
		Help: "Test counter",
	})
	CacheSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "warmor_cache_size_integration",
		Help: "Test gauge",
	})
	EvaluationLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "warmor_evaluation_latency_microseconds_integration",
		Help:    "Test histogram",
		Buckets: []float64{10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000},
	})

	// Simulate a typical workflow
	// 1. Process some events
	RecordEvent("allow")
	RecordEvent("allow")
	RecordEvent("deny")
	RecordEvent("log")

	// 2. Record cache operations
	RecordCacheHit()
	RecordCacheHit()
	RecordCacheMiss()
	UpdateCacheSize(2)

	// 3. Record latencies
	RecordLatency(50)
	RecordLatency(100)
	RecordLatency(75)

	// Verify all metrics were updated
	allowCount := getCounterVecValue(EventsTotal, "allow")
	if allowCount != 2 {
		t.Errorf("allow events = %v, want 2", allowCount)
	}

	denyCount := getCounterVecValue(EventsTotal, "deny")
	if denyCount != 1 {
		t.Errorf("deny events = %v, want 1", denyCount)
	}

	logCount := getCounterVecValue(EventsTotal, "log")
	if logCount != 1 {
		t.Errorf("log events = %v, want 1", logCount)
	}

	hits := getCounterValue(CacheHitsTotal)
	if hits != 2 {
		t.Errorf("cache hits = %v, want 2", hits)
	}

	misses := getCounterValue(CacheMissesTotal)
	if misses != 1 {
		t.Errorf("cache misses = %v, want 1", misses)
	}

	size := getGaugeValue(CacheSize)
	if size != 2 {
		t.Errorf("cache size = %v, want 2", size)
	}

	latencyCount := getHistogramCount(EvaluationLatency)
	if latencyCount != 3 {
		t.Errorf("latency observations = %v, want 3", latencyCount)
	}

	latencySum := getHistogramSum(EvaluationLatency)
	expectedSum := 50.0 + 100.0 + 75.0
	if latencySum != expectedSum {
		t.Errorf("latency sum = %v, want %v", latencySum, expectedSum)
	}
}

func BenchmarkRecordEvent(b *testing.B) {
	EventsTotal.Reset()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		RecordEvent("allow")
	}
}

func BenchmarkRecordCacheHit(b *testing.B) {
	CacheHitsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "warmor_cache_hits_total_bench",
		Help: "Bench counter",
	})
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		RecordCacheHit()
	}
}

func BenchmarkRecordLatency(b *testing.B) {
	EvaluationLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "warmor_evaluation_latency_microseconds_bench",
		Help:    "Bench histogram",
		Buckets: []float64{10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000},
	})
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		RecordLatency(100)
	}
}

func BenchmarkUpdateCacheSize(b *testing.B) {
	CacheSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "warmor_cache_size_bench",
		Help: "Bench gauge",
	})
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		UpdateCacheSize(i % 1000)
	}
}


