package web

import "net/http"

// handleExplorationCombined serves GET /api/exploration/combined.
// PLACEHOLDER — implemented by the combined-graph agent.
func (s *Server) handleExplorationCombined(w http.ResponseWriter, r *http.Request) {
	writeJSONStatus(w, http.StatusNotImplemented, map[string]string{"error": "not implemented"})
}
