package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// NewEnrollClient returns an HTTP client suitable for enrollment and, if reused,
// config polling. When cpIP is set the control plane is dialed at that fixed IP
// (DNS bypassed) while TLS still verifies the URL host — the same behavior the
// replication agent uses.
func NewEnrollClient(cpIP string) *http.Client {
	return &http.Client{Timeout: 15 * time.Second, Transport: masterTransport(cpIP)}
}

// EnrollResult is the control plane's reply to a self-enrollment request.
type EnrollResult struct {
	ID       string `json:"id"` // the node's immutable server-generated identity
	Name     string `json:"name"`
	Key      string `json:"key"`
	Approved bool   `json:"approved"`
	// CPAddress is the control plane's own advertised address (if it set one). The
	// agent pins it so it keeps reaching the CP by a fixed IP even if DNS breaks.
	CPAddress string `json:"cp_address"`
}

// Enroll self-registers an agent with the control plane using the shared join
// token, returning the node's immutable id and per-node API key. The agent
// persists both and authenticates all later config pulls with the key.
//
// nodeID and nodeKey are the agent's currently-persisted identity, sent so a
// re-enrollment (after a hostname change or a rejected key) re-attaches to the
// SAME node: the control plane rotates the existing node's key only when the
// presented nodeKey proves ownership of nodeID. They are empty on first
// enrollment, which creates a new node. See the control plane's clusterEnroll for
// the full security model.
func Enroll(ctx context.Context, client *http.Client, cpURL, name, joinToken, nodeID, nodeKey string) (EnrollResult, error) {
	var res EnrollResult
	body, err := json.Marshal(map[string]string{
		"name": name, "token": joinToken, "node_id": nodeID, "node_key": nodeKey,
	})
	if err != nil {
		return res, err
	}
	url := strings.TrimRight(cpURL, "/") + "/api/cluster/enroll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return res, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return res, statusError(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return res, err
	}
	if res.Key == "" {
		return res, fmt.Errorf("control plane returned an empty node key")
	}
	return res, nil
}
