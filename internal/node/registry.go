package node

import (
	"sort"
	"sync"
	"time"

	"lnproxy/internal/protocol"
)

type Registry struct {
	mu       sync.RWMutex
	exits    map[string]*exitEntry
	staleFor time.Duration
}

type exitEntry struct {
	info       protocol.ExitInfo
	heartbeat  time.Time
	persistent bool
}

func NewRegistry(staleFor time.Duration) *Registry {
	if staleFor <= 0 {
		staleFor = 45 * time.Second
	}
	return &Registry{
		exits:    make(map[string]*exitEntry),
		staleFor: staleFor,
	}
}

func (r *Registry) Add(info protocol.ExitInfo, health string) {
	r.add(info, health, false)
}

func (r *Registry) AddPersistent(info protocol.ExitInfo, health string) {
	r.add(info, health, true)
}

func (r *Registry) add(info protocol.ExitInfo, health string, persistent bool) {
	now := time.Now()
	info.Health = health
	info.HeartbeatTime = now.UnixMilli()
	r.mu.Lock()
	r.exits[info.ID] = &exitEntry{info: info, heartbeat: now, persistent: persistent}
	r.mu.Unlock()
}

func (r *Registry) Heartbeat(heartbeat protocol.Heartbeat) {
	now := time.Now()
	r.mu.Lock()
	if entry := r.exits[heartbeat.ExitID]; entry != nil {
		entry.heartbeat = now
		entry.info.ActiveConnections = heartbeat.Active
		if heartbeat.Capacity > 0 {
			entry.info.Capacity = heartbeat.Capacity
		}
		entry.info.HeartbeatTime = now.UnixMilli()
		entry.info.Health = healthFor(entry.info.ActiveConnections, entry.info.Capacity)
	}
	r.mu.Unlock()
}

func (r *Registry) Remove(id string) {
	r.mu.Lock()
	delete(r.exits, id)
	r.mu.Unlock()
}

func (r *Registry) Expire() []protocol.ExitInfo {
	now := time.Now()
	r.mu.Lock()
	for id, entry := range r.exits {
		if entry.persistent {
			continue
		}
		if now.Sub(entry.heartbeat) > r.staleFor {
			delete(r.exits, id)
		}
	}
	r.mu.Unlock()
	return r.Snapshot()
}

func (r *Registry) Snapshot() []protocol.ExitInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]protocol.ExitInfo, 0, len(r.exits))
	for _, entry := range r.exits {
		info := entry.info
		info.Features = append([]string(nil), info.Features...)
		result = append(result, info)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result
}

func (r *Registry) Get(id string) (protocol.ExitInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry := r.exits[id]
	if entry == nil {
		return protocol.ExitInfo{}, false
	}
	return entry.info, true
}

func (r *Registry) Select(exitID string, fallback bool) (protocol.ExitInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if exitID == "" || exitID == "auto" {
		var selected *protocol.ExitInfo
		score := int64(-1)
		for _, entry := range r.exits {
			info := entry.info
			if info.Health != "healthy" || info.ActiveConnections >= info.Capacity {
				continue
			}
			available := int64(info.Capacity - info.ActiveConnections)
			currentScore := available*1000 - info.LatencyMS
			if selected == nil || currentScore > score || (currentScore == score && info.ID < selected.ID) {
				copyInfo := info
				selected = &copyInfo
				score = currentScore
			}
		}
		if selected == nil {
			return protocol.ExitInfo{}, ErrNoExit
		}
		return *selected, nil
	}
	entry := r.exits[exitID]
	if entry == nil || entry.info.Health != "healthy" || entry.info.ActiveConnections >= entry.info.Capacity {
		if !fallback {
			return protocol.ExitInfo{}, ErrExitUnavailable
		}
		return r.selectAny()
	}
	return entry.info, nil
}

// Caller must hold r.mu.
func (r *Registry) selectAny() (protocol.ExitInfo, error) {
	for _, entry := range r.exits {
		if entry.info.Health == "healthy" && entry.info.ActiveConnections < entry.info.Capacity {
			return entry.info, nil
		}
	}
	return protocol.ExitInfo{}, ErrNoExit
}

func healthFor(active, capacity int) string {
	if capacity <= 0 || active >= capacity {
		return "at-capacity"
	}
	if active*100 > capacity*90 {
		return "degraded"
	}
	return "healthy"
}
