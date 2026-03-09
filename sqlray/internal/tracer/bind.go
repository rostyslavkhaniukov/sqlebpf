package tracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func ParseBindMessage(data []byte) (stmtName string, params []string, err error) {
	stmtName, params, err = parseBindInner(data)
	return
}

func ParseBindParams(data []byte) ([]string, error) {
	_, params, err := parseBindInner(data)
	return params, err
}

func parseBindInner(data []byte) (string, []string, error) {
	if len(data) < 2 {
		return "", nil, fmt.Errorf("bind data too short")
	}

	off := 0

	idx := bytes.IndexByte(data[off:], 0)
	if idx < 0 {
		return "", nil, fmt.Errorf("reading portal name")
	}
	off += idx + 1

	idx = bytes.IndexByte(data[off:], 0)
	if idx < 0 {
		return "", nil, fmt.Errorf("reading statement name")
	}
	stmtName := string(data[off : off+idx])
	off += idx + 1

	if off+2 > len(data) {
		return "", nil, fmt.Errorf("reading format code count")
	}
	numFormats := int(binary.BigEndian.Uint16(data[off:]))
	off += 2

	off += numFormats * 2
	if off > len(data) {
		return "", nil, fmt.Errorf("reading format codes")
	}

	if off+2 > len(data) {
		return "", nil, fmt.Errorf("reading param count")
	}
	numParams := int(binary.BigEndian.Uint16(data[off:]))
	off += 2

	params := make([]string, 0, numParams)
	for i := range numParams {
		if off+4 > len(data) {
			return "", nil, fmt.Errorf("reading param %d length", i)
		}
		paramLen := int32(binary.BigEndian.Uint32(data[off:]))
		off += 4

		if paramLen == -1 {
			params = append(params, "NULL")
			continue
		}
		if paramLen < 0 {
			return "", nil, fmt.Errorf("invalid param %d length: %d", i, paramLen)
		}
		end := off + int(paramLen)
		if end > len(data) {
			return "", nil, fmt.Errorf("reading param %d data", i)
		}
		params = append(params, string(data[off:end]))
		off = end
	}

	return stmtName, params, nil
}
