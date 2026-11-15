package tokenprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// pathStep is one segment of a JSONPath subset: an object key or array index.
type pathStep struct {
	key   string
	index int
	isIdx bool
}

// parsePath parses the supported JSONPath subset:
//
//	$.a.b   $.a[0].b   $['a-b'].c   a.b (leading $ optional)
func parsePath(p string) ([]pathStep, error) {
	s := strings.TrimSpace(p)
	if s == "" {
		return nil, errors.New("empty path")
	}
	s = strings.TrimPrefix(s, "$")
	var steps []pathStep
	for len(s) > 0 {
		switch s[0] {
		case '.':
			s = s[1:]
			end := strings.IndexAny(s, ".[")
			if end < 0 {
				end = len(s)
			}
			if end == 0 {
				return nil, fmt.Errorf("invalid path %q: empty key", p)
			}
			steps = append(steps, pathStep{key: s[:end]})
			s = s[end:]
		case '[':
			end := strings.IndexByte(s, ']')
			if end < 0 {
				return nil, fmt.Errorf("invalid path %q: unclosed [", p)
			}
			inner := strings.TrimSpace(s[1:end])
			s = s[end+1:]
			if len(inner) >= 2 && (inner[0] == '\'' || inner[0] == '"') && inner[len(inner)-1] == inner[0] {
				steps = append(steps, pathStep{key: inner[1 : len(inner)-1]})
				continue
			}
			n, err := strconv.Atoi(inner)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("invalid path %q: bad index %q", p, inner)
			}
			steps = append(steps, pathStep{index: n, isIdx: true})
		default:
			// Bare leading key: "data.token".
			if len(steps) == 0 {
				s = "." + s
				continue
			}
			return nil, fmt.Errorf("invalid path %q", p)
		}
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("invalid path %q: selects the whole document", p)
	}
	return steps, nil
}

func walkPath(doc any, steps []pathStep) (any, bool) {
	cur := doc
	for _, st := range steps {
		if st.isIdx {
			arr, ok := cur.([]any)
			if !ok || st.index >= len(arr) {
				return nil, false
			}
			cur = arr[st.index]
			continue
		}
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = obj[st.key]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// extractValue applies one rule to a response. Returns "" when absent.
func extractValue(rule string, header http.Header, body []byte, doc any) (string, error) {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return "", nil
	}
	if h, ok := strings.CutPrefix(rule, "header:"); ok {
		return strings.TrimSpace(header.Get(strings.TrimSpace(h))), nil
	}
	if expr, ok := strings.CutPrefix(rule, "regex:"); ok {
		re, err := regexp.Compile(expr)
		if err != nil {
			return "", err
		}
		m := re.FindSubmatch(body)
		if m == nil {
			return "", nil
		}
		if len(m) > 1 {
			return string(m[1]), nil
		}
		return string(m[0]), nil
	}
	steps, err := parsePath(rule)
	if err != nil {
		return "", err
	}
	if doc == nil {
		return "", nil
	}
	v, ok := walkPath(doc, steps)
	if !ok || v == nil {
		return "", nil
	}
	switch t := v.(type) {
	case string:
		return t, nil
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(t), nil
	default:
		b, _ := json.Marshal(t)
		return string(b), nil
	}
}
