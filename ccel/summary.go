// Copyright 2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package ccel

import (
	"encoding/json"

	"gitlab.com/real-cis/cc/go-trust/pkg/tcg"
	"gitlab.com/real-cis/cc/go-trust/pkg/uefi"
)

// Compact, display/export friendly view of a single event.
type EventSummary struct {
	RTMRIndex   int     `json:"rtmr_index"`
	EventType   string  `json:"event_type"`
	Digest      []byte  `json:"digest"`
	EFIVariable *string `json:"efi_variable,omitempty"`
}

// Aggregate view of an event log: all events + replayed RTMR values
type EventLogSummary struct {
	Events []EventSummary `json:"events"`
	RTMRs  map[int][]byte `json:"rtmrs"` // index -> SHA-384 value
}

// check if event is a UEFI_VARIABLE_DATA structure, to extract the variable name
func isEfiVariableEvent(t tcg.EventType) bool {
	switch t {
	case tcg.EvEfiVariableDriverConfig,
		tcg.EvEfiVariableBoot,
		tcg.EvEfiVariableBoot2,
		tcg.EvEfiVariableAuthority:
		return true
	}
	return false
}

// returns SHA-384 digest if present, otherwise the first available digest
func pickDigest(digests []tcg.Digest) []byte {
	if len(digests) == 0 {
		return nil
	}
	for _, d := range digests {
		if d.AlgID == tcg.AlgSHA384 {
			return d.Hash
		}
	}
	return digests[0].Hash
}

func NewEventSummary(e FormattedTcgEvent) EventSummary {
	s := EventSummary{
		RTMRIndex: int(e.GetRtmrIndex()),
		EventType: e.GetEventType().String(),
		Digest:    pickDigest(e.GetDigests()),
	}

	if isEfiVariableEvent(e.GetEventType()) {
		if v, err := uefi.NewUefiVariableDataFromBytes(e.GetEvent()); err == nil {
			name := v.Name.String()
			s.EFIVariable = &name
		}
	}

	return s
}

// returns the summary as JSON; best effort, empty on error.
func (s *EventLogSummary) JSON() string {
	b, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return string(b)
}

// returns the aggregate, display/export friendly view of the event log
func (l *EventLogger) Summary() *EventLogSummary {
	events := make([]EventSummary, 0, len(l.tcgEventLogs))
	for _, e := range l.tcgEventLogs {
		events = append(events, NewEventSummary(e))
	}

	rtmrs := make(map[int][]byte)
	for idx, algMap := range l.Replay() {
		if val, ok := algMap[tcg.AlgSHA384]; ok {
			rtmrs[idx] = val
		}
	}

	return &EventLogSummary{
		Events: events,
		RTMRs:  rtmrs,
	}
}
