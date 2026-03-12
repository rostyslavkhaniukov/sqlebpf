package tracer

import (
	"testing"
)

func TestParseBindParams(t *testing.T) {
	data := []byte{
		0,    // portal name ""
		0,    // stmt name ""
		0, 1, // 1 format code
		0, 0, // format code 0 (text)
		0, 2, // 2 params
		0, 0, 0, 5, // param 0: len=5
		'h', 'e', 'l', 'l', 'o', // param 0: "hello"
		0xFF, 0xFF, 0xFF, 0xFF, // param 1: len=-1 (NULL)
	}

	params, err := ParseBindParams(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(params) != 2 {
		t.Fatalf("len(params) = %d, want 2", len(params))
	}
	if params[0] != "hello" {
		t.Errorf("params[0] = %q, want %q", params[0], "hello")
	}
	if params[1] != "NULL" {
		t.Errorf("params[1] = %q, want %q", params[1], "NULL")
	}
}

func TestParseBindParamsNoParams(t *testing.T) {
	data := []byte{
		0,    // portal
		0,    // stmt
		0, 0, // 0 format codes
		0, 0, // 0 params
	}

	params, err := ParseBindParams(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(params) != 0 {
		t.Errorf("len(params) = %d, want 0", len(params))
	}
}

func TestParseBindParamsNamedPortalAndStmt(t *testing.T) {
	data := []byte{
		'p', '1', 0, // portal "p1"
		's', '1', 0, // stmt "s1"
		0, 0, // 0 format codes
		0, 1, // 1 param
		0, 0, 0, 1, // param 0: len=1
		'x', // param 0: "x"
	}

	params, err := ParseBindParams(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(params) != 1 {
		t.Fatalf("len(params) = %d, want 1", len(params))
	}
	if params[0] != "x" {
		t.Errorf("params[0] = %q, want %q", params[0], "x")
	}
}

func TestParseBindParamsTruncated(t *testing.T) {
	data := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 5, 'h'}
	_, err := ParseBindParams(data)
	if err == nil {
		t.Fatal("expected error for truncated param data")
	}
}

func TestParseBindParamsNegativeLen(t *testing.T) {
	data := []byte{
		0,    // portal
		0,    // stmt
		0, 0, // 0 format codes
		0, 1, // 1 param
		0xFF, 0xFF, 0xFF, 0xFE, // param len = -2
	}
	_, err := ParseBindParams(data)
	if err == nil {
		t.Fatal("expected error for negative param length")
	}
}

func TestParseBindParamsTooShort(t *testing.T) {
	_, err := ParseBindParams([]byte{0})
	if err == nil {
		t.Fatal("expected error for short data")
	}
}
