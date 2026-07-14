// Package httpmsg parses raw HTTP/1.1 messages from files: request or
// response, start line, ordered header fields, and the verbatim body.
//
// It is deliberately not net/http: signature verification needs the
// exact field order, duplicate fields, and untouched body bytes, none of
// which survive net/http's canonicalization.
package httpmsg

import (
	"fmt"
	"strconv"
	"strings"
)

// Header is one field line, order-preserving.
type Header struct {
	Name  string // as written
	Value string // trimmed, obs-fold joined
}

// Message is a parsed HTTP request or response.
type Message struct {
	IsResponse bool

	// Request fields.
	Method        string
	RequestTarget string // exactly as written in the request line

	// Response fields.
	StatusCode int

	Proto   string
	Headers []Header
	Body    []byte // verbatim bytes after the blank line
}

// Values returns every value of the named field, in order,
// case-insensitively.
func (m *Message) Values(name string) []string {
	var out []string
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, name) {
			out = append(out, h.Value)
		}
	}
	return out
}

// Get returns the first value of the named field.
func (m *Message) Get(name string) (string, bool) {
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value, true
		}
	}
	return "", false
}

// Parse reads a raw HTTP message. Both CRLF and bare-LF line endings are
// accepted in the head section (files are usually saved with LF); the
// body is returned byte-for-byte as it appears after the blank line.
func Parse(raw []byte) (*Message, error) {
	head, body := splitHead(raw)
	lines := splitLines(head)
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, fmt.Errorf("empty message: no start line")
	}

	m := &Message{Body: body}
	if err := parseStartLine(m, lines[0]); err != nil {
		return nil, err
	}
	if err := parseHeaders(m, lines[1:]); err != nil {
		return nil, err
	}
	return m, nil
}

// splitHead separates the header section from the body at the first
// blank line, tolerating CRLF and LF.
func splitHead(raw []byte) (head string, body []byte) {
	s := string(raw)
	for _, sep := range []string{"\r\n\r\n", "\n\n"} {
		if i := strings.Index(s, sep); i >= 0 {
			return s[:i], raw[i+len(sep):]
		}
	}
	return s, nil
}

func splitLines(head string) []string {
	lines := strings.Split(head, "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	// Drop trailing empty lines left by a file that ends in a newline
	// but has no body.
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func parseStartLine(m *Message, line string) error {
	if strings.HasPrefix(line, "HTTP/") {
		m.IsResponse = true
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			return fmt.Errorf("malformed status line %q", line)
		}
		code, err := strconv.Atoi(parts[1])
		if err != nil || code < 100 || code > 599 {
			return fmt.Errorf("malformed status code in %q", line)
		}
		m.Proto = parts[0]
		m.StatusCode = code
		return nil
	}
	parts := strings.Split(line, " ")
	if len(parts) != 3 {
		return fmt.Errorf("malformed request line %q (want METHOD TARGET PROTO)", line)
	}
	if !strings.HasPrefix(parts[2], "HTTP/") {
		return fmt.Errorf("malformed request line %q: protocol must start with HTTP/", line)
	}
	m.Method = parts[0]
	m.RequestTarget = parts[1]
	m.Proto = parts[2]
	return nil
}

func parseHeaders(m *Message, lines []string) error {
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			return fmt.Errorf("blank line inside header section (line %d)", i+2)
		}
		if line[0] == ' ' || line[0] == '\t' {
			// obs-fold continuation: joined onto the previous field
			// value with a single space, per RFC 9110 §5.5.
			if len(m.Headers) == 0 {
				return fmt.Errorf("continuation line before any header field (line %d)", i+2)
			}
			last := &m.Headers[len(m.Headers)-1]
			last.Value = strings.TrimRight(last.Value, " \t") + " " + strings.Trim(line, " \t")
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return fmt.Errorf("header line %d has no colon: %q", i+2, line)
		}
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, " \t") {
			return fmt.Errorf("invalid header field name on line %d: %q", i+2, line)
		}
		m.Headers = append(m.Headers, Header{
			Name:  name,
			Value: strings.Trim(value, " \t"),
		})
	}
	return nil
}
