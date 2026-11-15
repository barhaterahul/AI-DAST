package web

import "net/http"

// handleExplorationOverview serves GET /api/exploration/overview.
// PLACEHOLDER — implemented by the overview agent.
func (s *Server) handleExplorationOverview(w http.ResponseWriter, r *http.Request) {
	writeJSONStatus(w, http.StatusNotImplemented, map[string]string{"error": "not implemented"})
}
