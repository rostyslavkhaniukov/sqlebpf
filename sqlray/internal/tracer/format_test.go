package tracer

import (
	"testing"
)

func TestSubstituteParams(t *testing.T) {
	tests := []struct {
		tmpl   string
		params []string
		want   string
	}{
		{
			"SELECT * FROM t WHERE id = $1",
			[]string{"42"},
			"SELECT * FROM t WHERE id = '42'",
		},
		{
			"SELECT * FROM t WHERE id = $1 AND name = $2",
			[]string{"42", "Alice"},
			"SELECT * FROM t WHERE id = '42' AND name = 'Alice'",
		},
		{
			"SELECT $1, $2, $10",
			[]string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"},
			"SELECT 'a', 'b', 'j'",
		},
		{
			"SELECT $1",
			[]string{"NULL"},
			"SELECT NULL",
		},
		{
			"SELECT $1",
			[]string{"it's"},
			"SELECT 'it''s'",
		},
		{
			"SELECT $99",
			[]string{"only_one"},
			"SELECT $99",
		},
		{
			"SELECT 1",
			nil,
			"SELECT 1",
		},
	}

	for _, tt := range tests {
		got := SubstituteParams(tt.tmpl, tt.params)
		if got != tt.want {
			t.Errorf("SubstituteParams(%q, %v) = %q, want %q", tt.tmpl, tt.params, got, tt.want)
		}
	}
}

func TestQuoteParam(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"hello", "'hello'"},
		{"it's", "'it''s'"},
		{"NULL", "NULL"},
		{"", "''"},
	}
	for _, tt := range tests {
		if got := quoteParam(tt.in); got != tt.want {
			t.Errorf("quoteParam(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
