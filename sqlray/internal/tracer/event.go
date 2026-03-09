package tracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
)

const MaxSQLLen = 512

const (
	EventQuery = iota
	EventParse
	EventBind
)

type Event struct {
	Pid       uint32
	Len       uint32
	EventType uint32
	Buf       [MaxSQLLen]byte
}

const EventSize = 4 + 4 + 4 + MaxSQLLen

type stmtKey struct {
	pid  uint32
	stmt string
}

var queryTemplates = make(map[stmtKey]string)

func DecodeEvent(raw []byte) (*Event, error) {
	if len(raw) < EventSize {
		return nil, fmt.Errorf("event too short: %d bytes", len(raw))
	}
	event := &Event{
		Pid:       binary.LittleEndian.Uint32(raw[0:4]),
		Len:       binary.LittleEndian.Uint32(raw[4:8]),
		EventType: binary.LittleEndian.Uint32(raw[8:12]),
	}
	copy(event.Buf[:], raw[12:])
	return event, nil
}

func HandleEvent(event *Event) {
	dataLen := min(event.Len, MaxSQLLen)
	data := event.Buf[:dataLen]

	switch event.EventType {
	case EventQuery:
		fmt.Printf("[PID %d] SQL: %s\n", event.Pid, TrimNull(data))

	case EventParse:
		stmtName, query := ExtractQuery(data)
		if query != "" {
			queryTemplates[stmtKey{event.Pid, stmtName}] = query
		}

	case EventBind:
		stmtName, params, err := ParseBindMessage(data)
		if err != nil {
			log.Printf("[PID %d] bind parse error: %v", event.Pid, err)
			return
		}
		key := stmtKey{event.Pid, stmtName}
		if tmpl, ok := queryTemplates[key]; ok {
			fmt.Printf("[PID %d] SQL: %s\n", event.Pid, SubstituteParams(tmpl, params))
			delete(queryTemplates, key)
		}
	}
}

func ExtractQuery(data []byte) (stmtName, query string) {
	stmtEnd := bytes.IndexByte(data, 0)
	if stmtEnd < 0 || stmtEnd+1 >= len(data) {
		return "", ""
	}
	stmtName = string(data[:stmtEnd])
	queryData := data[stmtEnd+1:]
	queryEnd := bytes.IndexByte(queryData, 0)
	if queryEnd <= 0 {
		return stmtName, ""
	}
	return stmtName, string(queryData[:queryEnd])
}

func TrimNull(data []byte) string {
	return string(bytes.TrimRight(data, "\x00"))
}
