package server

import (
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"nazr/api/internal/ipintel"
)

// registry is dedicated to nazr so tests and embedders never touch the
// global default registry.
var registry = prometheus.NewRegistry()

var (
	requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nazr_requests_total", Help: "HTTP requests by route and status.",
	}, []string{"route", "status"})
	requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "nazr_request_duration_seconds", Help: "HTTP request latency by route.",
		Buckets: prometheus.DefBuckets,
	}, []string{"route"})
	parseErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nazr_fingerprint_parse_errors_total", Help: "Fingerprint capture failures by kind (tls, h2).",
	}, []string{"kind"})
	classificationTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nazr_classification_total", Help: "Classifications emitted by /thumbmark.",
	}, []string{"tor", "vpn", "bot", "datacenter", "private_relay"})
	listStaleDesc = prometheus.NewDesc("nazr_list_stale",
		"1 when an intelligence source is not loaded or its last refresh failed.", []string{"source"}, nil)
)

// statusFunc is the source-status provider of the most recently built server,
// read at scrape time by the nazr_list_stale collector.
var statusFunc atomic.Pointer[func() map[string]ipintel.SourceStatus]

type listStaleCollector struct{}

func (listStaleCollector) Describe(ch chan<- *prometheus.Desc) { ch <- listStaleDesc }

func (listStaleCollector) Collect(ch chan<- prometheus.Metric) {
	f := statusFunc.Load()
	if f == nil {
		return
	}
	for name, st := range (*f)() {
		v := 0.0
		if !st.Loaded || st.LastError != "" {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(listStaleDesc, prometheus.GaugeValue, v, name)
	}
}

func init() {
	registry.MustRegister(requestsTotal, requestDuration, parseErrorsTotal, classificationTotal,
		listStaleCollector{},
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}

// NewMetricsHandler serves the nazr Prometheus registry. Mount it on the
// metrics listener (NAZR_METRICS_ADDR), not the public one.
func NewMetricsHandler() http.Handler {
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}

func setStatusSource(intel IntelAPI) {
	if intel == nil {
		return
	}
	f := intel.Status
	statusFunc.Store(&f)
}

// statusRecorder captures the response status for metrics.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// withMetrics records request count and latency under route. A panic passing
// through is counted as 500 and re-raised for the recover middleware.
func withMetrics(route string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		defer func() {
			p := recover()
			status := rec.status
			if p != nil {
				status = http.StatusInternalServerError
			} else if status == 0 {
				status = http.StatusOK
			}
			requestsTotal.WithLabelValues(route, strconv.Itoa(status)).Inc()
			requestDuration.WithLabelValues(route).Observe(time.Since(start).Seconds())
			if p != nil {
				panic(p)
			}
		}()
		next.ServeHTTP(rec, r)
	})
}
