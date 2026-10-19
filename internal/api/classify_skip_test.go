package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A query a local record answered is the network's own name: ingesting it
// never hands it to the classifier; every other query does.
func TestClusterLogSkipsLocalAnswers(t *testing.T) {
	s, st := newEnrollServer(t, "", false)
	if _, err := st.CreateNode("agent-a", hashKey("node-key"), "node"); err != nil {
		t.Fatal(err)
	}
	var queued []string
	s.SetClassifierEnqueue(func(name string) { queued = append(queued, name) })
	body := `[{"ts":1,"name":"nas.amaze-labs.com.","action":"rewrite"},
	          {"ts":1,"name":"ns.amaze-labs.com.","action":"authoritative"},
	          {"ts":1,"name":"www.google.com.","action":"forward"},
	          {"ts":1,"name":"ads.example-tracker.com.","action":"blocked"}]`
	r := httptest.NewRequest(http.MethodPost, "/api/cluster/log", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer node-key")
	rr := httptest.NewRecorder()
	s.clusterLog(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Join(queued, ",") != "www.google.com.,ads.example-tracker.com." {
		t.Errorf("queued %v, want only the forwarded and blocked names", queued)
	}
}
