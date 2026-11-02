package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

func TestLivePagingSearchAndBounds(t *testing.T) {
	items := make([]circuitView, 55)
	for i := range items {
		items[i] = circuitView{ID: fmt.Sprintf("circuit-%02d", i), SourceRouterName: "other", OpenedAt: int64(i)}
	}
	items[0].SourceRouterName = "Needle"
	filtered := activeCircuitPage(httptest.NewRequest("GET", "/admin/circuits?active_q=needle&active_size=25", nil), items)
	if filtered.Total != 1 || len(filtered.Items) != 1 || filtered.Items[0].ID != "circuit-00" || filtered.NextURL != "" {
		t.Fatalf("filtered active circuits: %+v", filtered)
	}
	page := activeCircuitPage(httptest.NewRequest("GET", "/admin/circuits?active_size=25", nil), items)
	if page.Total != 55 || page.Pages != 3 || len(page.Items) != 25 || page.Items[0].ID != "circuit-54" || !strings.Contains(page.NextURL, "active_page=2") {
		t.Fatalf("first active page: %+v", page)
	}
	last := activeCircuitPage(httptest.NewRequest("GET", "/admin/circuits?active_size=25&active_page=999", nil), items)
	if last.Number != 3 || len(last.Items) != 5 || last.NextURL != "" || !strings.Contains(last.PrevURL, "active_page=2") {
		t.Fatalf("clamped active page: %+v", last)
	}
	request := httptest.NewRequest("GET", "/admin/router-sessions?q=alpha&page_size=50&page=2", nil)
	sessions := make([]adminRouterSession, 75)
	sessionPage := paginateLive(request, sessions, liveSearch(request, "q"), "page", "page_size")
	if sessionPage.Number != 2 || len(sessionPage.Items) != 25 || sessionPage.NextURL != "" || !strings.Contains(sessionPage.PrevURL, "q=alpha") {
		t.Fatalf("router session page: %+v", sessionPage)
	}
}

func TestAdminRouterSessionsSearchAndPages(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	adminID := store.RandomUUID()
	if _, err := a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at) VALUES(?,?,?,'admin',?)", adminID, "sessions@example.com", "unused", store.Now()); err != nil {
		t.Fatal(err)
	}
	token, _, err := a.DB.NewSession(ctx, adminID, "full")
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: "snusnu_session", Value: token}
	for i := 0; i < 30; i++ {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		session := cachedTestSession(id, adminID, "test-token", store.RandomUUID())
		session.router.DisplayName = fmt.Sprintf("Router %02d", i)
		session.connectedAt = time.Unix(100, 0)
		a.hub.clients.Store(id, session)
	}
	first := uiGet(t, a, "/admin/router-sessions?page_size=25", cookie)
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), "30 matching router session(s)") || strings.Count(first.Body.String(), "high-water") != 25 || !strings.Contains(first.Body.String(), "page=2") {
		t.Fatalf("first session page: %d %s", first.Code, first.Body.String())
	}
	second := uiGet(t, a, "/admin/router-sessions?page_size=25&page=2", cookie)
	if second.Code != http.StatusOK || strings.Count(second.Body.String(), "high-water") != 5 {
		t.Fatalf("second session page: %d %s", second.Code, second.Body.String())
	}
	filtered := uiGet(t, a, "/admin/router-sessions?q=Router+03", cookie)
	if filtered.Code != http.StatusOK || !strings.Contains(filtered.Body.String(), "1 matching router session(s)") || !strings.Contains(filtered.Body.String(), "Router 03</a>") || strings.Contains(filtered.Body.String(), "Router 04</a>") {
		t.Fatalf("filtered session page: %d %s", filtered.Code, filtered.Body.String())
	}
}
