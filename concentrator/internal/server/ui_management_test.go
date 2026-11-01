package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func uiUser(t *testing.T, a *App, email, role, password string) (string, *http.Cookie, store.Session) {
	t.Helper()
	ctx := context.Background()
	id := store.RandomUUID()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at,remind_after) VALUES(?,?,?,?,?,?)", id, email, string(hash), role, store.Now(), store.Now()+86400); err != nil {
		t.Fatal(err)
	}
	token, session, err := a.DB.NewSession(ctx, id, "full")
	if err != nil {
		t.Fatal(err)
	}
	return id, &http.Cookie{Name: "snusnu_session", Value: token}, session
}
func uiGet(t *testing.T, a *App, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", path, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}
func TestRememberLoginAndCard(t *testing.T) {
	a := testApp(t)
	_, _, _ = uiUser(t, a, "remember@example.com", "user", "remember-password-123")
	w := uiGet(t, a, "/login", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Remember me for 30 days") || !strings.Contains(w.Body.String(), "card-body p-4 p-md-5") {
		t.Fatalf("login layout: %d %s", w.Code, w.Body.String())
	}
	w = postForm(a, "/login", url.Values{"email": {"remember@example.com"}, "password": {"remember-password-123"}, "remember": {"1"}}, nil)
	if w.Code != 303 {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	if cookie.MaxAge != 30*24*3600 {
		t.Fatalf("remembered cookie max age %d", cookie.MaxAge)
	}
	session, err := a.DB.Session(context.Background(), cookie.Value)
	if err != nil || !session.Remember || session.Expires-store.Now() < 29*24*3600 {
		t.Fatalf("remembered session: %+v %v", session, err)
	}
	w = uiGet(t, a, "/dashboard", cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), ">Flows</a>") || !strings.Contains(w.Body.String(), "dropdown-menu-end") || !strings.Contains(w.Body.String(), "/profiles/"+session.UserID) {
		t.Fatalf("user card: %d %s", w.Code, w.Body.String())
	}
	w = postForm(a, "/login", url.Values{"email": {"remember@example.com"}, "password": {"remember-password-123"}}, nil)
	if w.Code != 303 || w.Result().Cookies()[0].MaxAge != 0 {
		t.Fatalf("nonremembered cookie: %d %+v", w.Code, w.Result().Cookies())
	}
}
func TestFlowsAndBlocklistsAreScoped(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	_, adminCookie, _ := uiUser(t, a, "flow-admin@example.com", "admin", "admin-password-123")
	alice, aliceCookie, aliceSession := uiUser(t, a, "flow-alice@example.com", "user", "alice-password-123")
	bob, bobCookie, bobSession := uiUser(t, a, "flow-bob@example.com", "user", "bob-password-123")
	ra, _, err := a.DB.CreateRouter(ctx, alice, "Alice router")
	if err != nil {
		t.Fatal(err)
	}
	rb, _, err := a.DB.CreateRouter(ctx, bob, "Bob router")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []store.LogEntry{{RouterID: ra.ID, PeerUserID: bob, Direction: "inbound", Level: "info", EventType: "PIU", SourceIP: "192.0.2.10", Summary: "ALICE_FLOW"}, {RouterID: rb.ID, PeerUserID: alice, Direction: "outbound", Level: "info", EventType: "PIU", SourceIP: "192.0.2.11", Summary: "BOB_FLOW"}} {
		if err := a.DB.AppendRouterLog(ctx, entry); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		cookie     *http.Cookie
		alice, bob bool
	}{{adminCookie, true, true}, {aliceCookie, true, false}, {bobCookie, false, true}} {
		w := uiGet(t, a, "/flows", tc.cookie)
		if w.Code != 200 || strings.Contains(w.Body.String(), "ALICE_FLOW") != tc.alice || strings.Contains(w.Body.String(), "BOB_FLOW") != tc.bob {
			t.Fatalf("flows scope: %d %s", w.Code, w.Body.String())
		}
	}
	if err := a.DB.SetBlock(ctx, alice, bob, true); err != nil {
		t.Fatal(err)
	}
	if w := uiGet(t, a, "/blocks", aliceCookie); w.Code != 200 || !strings.Contains(w.Body.String(), "flow-bob@example.com") {
		t.Fatalf("own blocklist: %d %s", w.Code, w.Body.String())
	}
	if w := uiGet(t, a, "/blocks", bobCookie); w.Code != 200 || strings.Contains(w.Body.String(), "flow-alice@example.com") {
		t.Fatalf("foreign blocklist: %d %s", w.Code, w.Body.String())
	}
	if w := uiGet(t, a, "/admin/blocks", adminCookie); w.Code != 200 || !strings.Contains(w.Body.String(), "flow-alice@example.com") || !strings.Contains(w.Body.String(), "flow-bob@example.com") {
		t.Fatalf("admin blocklist: %d %s", w.Code, w.Body.String())
	}
	if w := uiGet(t, a, "/admin/blocks", aliceCookie); w.Code != 403 {
		t.Fatalf("nonadmin all blocks: %d", w.Code)
	}
	if w := postForm(a, "/blocks/"+alice+"/remove", url.Values{"csrf": {bobSession.CSRF}}, bobCookie); w.Code != 303 {
		t.Fatalf("other user's unblock: %d", w.Code)
	}
	if blocked, _ := a.DB.IsBlocked(ctx, alice, bob); !blocked {
		t.Fatal("foreign unblock removed owner's block")
	}
	if w := postForm(a, "/blocks/"+bob+"/remove", url.Values{"csrf": {aliceSession.CSRF}}, aliceCookie); w.Code != 303 {
		t.Fatalf("own unblock: %d", w.Code)
	}
	if blocked, _ := a.DB.IsBlocked(ctx, alice, bob); blocked {
		t.Fatal("own unblock failed")
	}
}
func TestAdminUserSearchPaginationAndDeletion(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	admin, adminCookie, adminSession := uiUser(t, a, "admin-page@example.com", "admin", "admin-password-123")
	user, userCookie, userSession := uiUser(t, a, "delete-me@example.com", "user", "user-password-123")
	for i := 0; i < 26; i++ {
		email := "paged-" + string(rune('a'+i)) + "@example.com"
		uiUser(t, a, email, "user", "paged-password-123")
	}
	w := uiGet(t, a, "/admin/users", adminCookie)
	if w.Code != 200 || strings.Count(w.Body.String(), "/admin/users/role") != 25 || !strings.Contains(w.Body.String(), "page=2") {
		t.Fatalf("page 1: %d count %d", w.Code, strings.Count(w.Body.String(), "/admin/users/role"))
	}
	w = uiGet(t, a, "/admin/users?page=2", adminCookie)
	if w.Code != 200 || strings.Count(w.Body.String(), "/admin/users/role") != 3 {
		t.Fatalf("page 2: %d count %d", w.Code, strings.Count(w.Body.String(), "/admin/users/role"))
	}
	w = uiGet(t, a, "/admin/users?q=delete-me", adminCookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "delete-me@example.com") || strings.Contains(w.Body.String(), "paged-a@example.com") {
		t.Fatalf("search: %d %s", w.Code, w.Body.String())
	}
	w = uiGet(t, a, "/admin/users", userCookie)
	if w.Code != 403 {
		t.Fatalf("nonadmin users: %d", w.Code)
	}
	cp, err := a.DB.AllocateManagedCP(ctx, user, "SOLNET", "DELCP")
	if err != nil {
		t.Fatal(err)
	}
	router, token, err := a.DB.CreateRouter(ctx, user, "Delete router")
	if err != nil {
		t.Fatal(err)
	}
	w = postForm(a, "/settings/delete", url.Values{"csrf": {userSession.CSRF}, "password": {"wrong-password"}, "confirm": {"DELETE"}}, userCookie)
	if w.Code != 403 {
		t.Fatalf("wrong password deleted user: %d", w.Code)
	}
	w = postForm(a, "/admin/users/"+user+"/delete", url.Values{"csrf": {adminSession.CSRF}, "password": {"admin-password-123"}, "confirm": {"DELETE"}}, adminCookie)
	if w.Code != 303 {
		t.Fatalf("admin delete: %d %s", w.Code, w.Body.String())
	}
	if _, err := a.DB.UserByID(ctx, user); err == nil {
		t.Fatal("deleted user remains")
	}
	if _, err := a.DB.RouterByToken(ctx, token); err == nil {
		t.Fatal("deleted router credential remains")
	}
	if _, err := a.DB.RouterByID(ctx, router.ID); err == nil {
		t.Fatal("deleted router remains")
	}
	retired, err := a.DB.ManagedCPByID(ctx, cp.ID)
	if err != nil || retired.RetiredAt == 0 || retired.Enabled {
		t.Fatalf("managed CP not retired: %+v %v", retired, err)
	}
	if _, err := a.DB.Session(ctx, userCookie.Value); err == nil {
		t.Fatal("deleted session remains")
	}
	w = postForm(a, "/settings/delete", url.Values{"csrf": {adminSession.CSRF}, "password": {"admin-password-123"}, "confirm": {"DELETE"}}, adminCookie)
	if w.Code != 409 {
		t.Fatalf("last admin deletion: %d", w.Code)
	}
	if _, err := a.DB.UserByID(ctx, admin); err != nil {
		t.Fatalf("last admin lost: %v", err)
	}
	self, selfCookie, selfSession := uiUser(t, a, "self-delete@example.com", "user", "self-password-123")
	w = postForm(a, "/settings/delete", url.Values{"csrf": {selfSession.CSRF}, "password": {"self-password-123"}, "confirm": {"DELETE"}}, selfCookie)
	if w.Code != 303 || w.Header().Get("Location") != "/login" {
		t.Fatalf("self delete: %d %s", w.Code, w.Body.String())
	}
	if _, err := a.DB.UserByID(ctx, self); err == nil {
		t.Fatal("self-deleted user remains")
	}
}
