package tokenprovider

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// JWTInfo is a decoded (NOT verified) JWT. The scanner never trusts these
// claims for its own decisions beyond scheduling refresh; they are shown to
// the operator and given to the agent as test context.
type JWTInfo struct {
	Header map[string]any `json:"header"`
	Claims map[string]any `json:"claims"`
	// Expiry is from the "exp" claim (zero when absent).
	Expiry time.Time `json:"expiry,omitempty"`
	// IssuedAt is from the "iat" claim (zero when absent).
	IssuedAt time.Time `json:"issued_at,omitempty"`
}

// DecodeJWT decodes a compact JWS without verifying it. Returns nil when s is
// not a three-part base64url token with JSON header and payload.
func DecodeJWT(s string) *JWTInfo {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "Bearer "), "bearer ")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil
	}
	var hdr, claims map[string]any
	if !decodeSegment(parts[0], &hdr) || !decodeSegment(parts[1], &claims) {
		return nil
	}
	info := &JWTInfo{Header: hdr, Claims: claims}
	if t, ok := numericDate(claims["exp"]); ok {
		info.Expiry = t
	}
	if t, ok := numericDate(claims["iat"]); ok {
		info.IssuedAt = t
	}
	return info
}

func decodeSegment(seg string, into *map[string]any) bool {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return false
	}
	return json.Unmarshal(b, into) == nil && *into != nil
}

func numericDate(v any) (time.Time, bool) {
	switch t := v.(type) {
	case float64:
		if t <= 0 {
			return time.Time{}, false
		}
		sec := int64(t)
		return time.Unix(sec, int64((t-float64(sec))*1e9)), true
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return time.Time{}, false
		}
		return numericDate(f)
	}
	return time.Time{}, false
}
