package tracer

import "strings"

func SubstituteParams(tmpl string, params []string) string {
	var b strings.Builder
	b.Grow(len(tmpl))

	i := 0
	for i < len(tmpl) {
		if tmpl[i] == '$' && i+1 < len(tmpl) && tmpl[i+1] >= '1' && tmpl[i+1] <= '9' {
			j := i + 1
			num := 0
			for j < len(tmpl) && tmpl[j] >= '0' && tmpl[j] <= '9' {
				num = num*10 + int(tmpl[j]-'0')
				j++
			}
			if num >= 1 && num <= len(params) {
				b.WriteString(quoteParam(params[num-1]))
			} else {
				b.WriteString(tmpl[i:j])
			}
			i = j
		} else {
			b.WriteByte(tmpl[i])
			i++
		}
	}

	return b.String()
}

func quoteParam(val string) string {
	if val == "NULL" {
		return "NULL"
	}
	return "'" + strings.ReplaceAll(val, "'", "''") + "'"
}
