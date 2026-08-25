package model

// NDJSON record types.
//
// A component record carries no record_type at all: that is what every line
// was before the other three existed, and a consumer written against that
// still reads a modern stream unchanged. The constant exists anyway, because
// the manifest's counts map is keyed by record type and "component" has to be
// spelled the same way in the collector and in the server that checks it.
const (
	RecordComponent = "component"
	RecordHeartbeat = "heartbeat"
	RecordExposure  = "exposure"
	RecordContainer = "container"
	RecordLink      = "link"
)
