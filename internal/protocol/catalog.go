package protocol

type ExitInfo struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Type              string   `json:"type"`
	Health            string   `json:"health"`
	LatencyMS         int64    `json:"latency_ms"`
	ActiveConnections int      `json:"active_connections"`
	Capacity          int      `json:"capacity"`
	Features          []string `json:"features,omitempty"`
	HeartbeatTime     int64    `json:"heartbeat_time"`
}

type Catalog struct {
	Exits []ExitInfo `json:"exits"`
}
