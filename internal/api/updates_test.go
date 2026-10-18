package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/updates"
)

// Without a checker (an agent) there is nothing to report; with checks
// turned off the control plane says so instead of calling out.
func TestUpdateStatus(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.updateStatus(rec, httptest.NewRequest("GET", "/api/updates", nil))
	if rec.Code != 404 {
		t.Errorf("no checker: status %d, want 404", rec.Code)
	}
	s.SetUpdates(updates.New("0.129.0", true))
	rec = httptest.NewRecorder()
	s.updateStatus(rec, httptest.NewRequest("GET", "/api/updates?refresh=1", nil))
	var st updates.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || rec.Code != 200 || !st.Disabled || st.Current != "0.129.0" || st.Releases == nil {
		t.Errorf("disabled: %d %s", rec.Code, rec.Body.String())
	}
}
