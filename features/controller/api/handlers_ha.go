package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/cfgis/cfgms/features/controller/ha"
)

// HAStatusResponse represents the response for HA status endpoint
type HAStatusResponse struct {
	NodeID   string `json:"node_id"`
	IsLeader bool   `json:"is_leader"`
	Mode     string `json:"mode"`
	Health   string `json:"health"`
}

// HAClusterResponse represents the response for HA cluster endpoint
type HAClusterResponse struct {
	Leader string        `json:"leader"`
	Nodes  []ha.NodeInfo `json:"nodes"`
	Health string        `json:"health"`
}

// HALeaderResponse represents the response for HA leader endpoint
type HALeaderResponse struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name,omitempty"`
	Health string `json:"health"`
}

// HANodesResponse represents the response for HA nodes endpoint
type HANodesResponse struct {
	Nodes []ha.NodeInfo `json:"nodes"`
	Count int           `json:"count"`
}

// handleHAStatus handles GET /api/v1/ha/status
func (s *Server) handleHAStatus(w http.ResponseWriter, r *http.Request) {
	// Get HA manager from the server
	haManager := s.getHAManager()
	if haManager == nil {
		s.respondError(w, http.StatusServiceUnavailable, "HA manager not available")
		return
	}

	// Get HA status
	localNode := haManager.GetLocalNode()
	nodeID := ""
	if localNode != nil {
		nodeID = localNode.ID
	}

	// Critical NodeID trace logging for API response
	log.Printf("DEBUG: NodeID Trace - API Response Generation: endpoint=/api/v1/ha/status, local_node_nil=%t, node_id=%s, node_id_empty=%t, local_node_id=%s",
		localNode == nil, nodeID, nodeID == "", func() string { if localNode != nil { return localNode.ID } else { return "NIL" } }())
	isLeader := haManager.IsLeader()
	mode := haManager.GetDeploymentMode().String()
	health := "healthy"

	// Check if HA manager is healthy
	healthStatus := haManager.GetHealth()
	if healthStatus != nil && healthStatus.Overall != ha.NodeStateHealthy {
		health = healthStatus.Overall.String()
	}

	response := HAStatusResponse{
		NodeID:   nodeID,
		IsLeader: isLeader,
		Mode:     mode,
		Health:   health,
	}

	s.respondJSON(w, http.StatusOK, response)
}

// handleHACluster handles GET /api/v1/ha/cluster
func (s *Server) handleHACluster(w http.ResponseWriter, r *http.Request) {
	// Get HA manager from the server
	haManager := s.getHAManager()
	if haManager == nil {
		s.respondError(w, http.StatusServiceUnavailable, "HA manager not available")
		return
	}

	// Get cluster information
	nodes, err := haManager.GetClusterNodes()
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get cluster nodes: %v", err))
		return
	}

	// Convert []*NodeInfo to []NodeInfo for JSON response
	var nodeList []ha.NodeInfo
	for _, node := range nodes {
		if node != nil {
			nodeList = append(nodeList, *node)
		}
	}

	leaderNode, err := haManager.GetLeader()
	leader := ""
	if err == nil && leaderNode != nil {
		leader = leaderNode.ID
	}

	health := "healthy"
	// Check overall cluster health
	healthStatus := haManager.GetHealth()
	if healthStatus != nil && healthStatus.Overall != ha.NodeStateHealthy {
		health = healthStatus.Overall.String()
	}

	response := HAClusterResponse{
		Leader: leader,
		Nodes:  nodeList,
		Health: health,
	}

	s.respondJSON(w, http.StatusOK, response)
}

// handleHALeader handles GET /api/v1/ha/leader
func (s *Server) handleHALeader(w http.ResponseWriter, r *http.Request) {
	// Get HA manager from the server
	haManager := s.getHAManager()
	if haManager == nil {
		s.respondError(w, http.StatusServiceUnavailable, "HA manager not available")
		return
	}

	// Get leader information
	leaderNode, err := haManager.GetLeader()
	leaderID := ""
	leaderName := ""
	health := "healthy"

	if err != nil || leaderNode == nil {
		health = "no_leader"
	} else {
		leaderID = leaderNode.ID
		leaderName = leaderNode.ID // NodeInfo doesn't have Name field, using ID
	}

	response := HALeaderResponse{
		NodeID: leaderID,
		Name:   leaderName,
		Health: health,
	}

	s.respondJSON(w, http.StatusOK, response)
}

// handleHANodes handles GET /api/v1/ha/nodes
func (s *Server) handleHANodes(w http.ResponseWriter, r *http.Request) {
	// Get HA manager from the server
	haManager := s.getHAManager()
	if haManager == nil {
		s.respondError(w, http.StatusServiceUnavailable, "HA manager not available")
		return
	}

	// Get all nodes
	nodes, err := haManager.GetClusterNodes()
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get cluster nodes: %v", err))
		return
	}

	// Convert []*NodeInfo to []NodeInfo for JSON response
	var nodeList []ha.NodeInfo
	for _, node := range nodes {
		if node != nil {
			nodeList = append(nodeList, *node)
		}
	}

	response := HANodesResponse{
		Nodes: nodeList,
		Count: len(nodeList),
	}

	s.respondJSON(w, http.StatusOK, response)
}

// getHAManager gets the HA manager from the server
func (s *Server) getHAManager() *ha.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.haManager
}

// respondJSON is a helper method to send JSON responses
func (s *Server) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// respondError is a helper method to send error responses
func (s *Server) respondError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	response := map[string]string{"error": message}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("Failed to encode error response", "error", err)
	}
}