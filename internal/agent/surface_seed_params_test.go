package agent

import (
	"testing"

	"github.com/barhaterahul/ai-dast-ing/v4/internal/attacksurface"
)

func TestParamHypothesesFromCollectionLocations(t *testing.T) {
	e := attacksurface.Endpoint{
		Method: "PATCH",
		Path:   "https://api.test/users/1",
		Params: []string{"id", "callbackUrl", "profile.role", "q"},
		ParamLocations: map[string]string{
			"id": "path", "callbackUrl": "body", "profile.role": "body", "q": "query",
		},
	}
	hs := paramHypotheses(e, "api.test", "/users/1", "authenticated", "context:postman")
	got := map[string]string{}
	for _, h := range hs {
		got[h.VulnClass] = h.Parameter
	}
	if got["ssrf"] != "callbackUrl" || got["auth_bypass"] != "profile.role" || got["sqli"] != "q" {
		t.Fatalf("hypotheses = %+v", got)
	}
	// GET cannot mass-assign; GraphQL/XML bodies get their own checks.
	e.Method = "GET"
	e.BodyMode = "graphql"
	hs = paramHypotheses(e, "api.test", "/graphql", "anonymous", "context:bruno")
	got = map[string]string{}
	for _, h := range hs {
		got[h.VulnClass] = h.Parameter
	}
	if _, ok := got["auth_bypass"]; ok {
		t.Fatal("GET must not seed mass assignment")
	}
	if _, ok := got["info_disclosure"]; !ok {
		t.Fatal("graphql check missing")
	}
	if paramHypotheses(attacksurface.Endpoint{Method: "GET"}, "h", "/", "anonymous", "x") != nil {
		t.Fatal("no params → no hypotheses")
	}
}
