package server

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func TestPasswordRecoveryAndAdminReset(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	oldHash, err := bcrypt.GenerateFromPassword([]byte("original-password-123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	adminID, userID, peerID := store.RandomUUID(), store.RandomUUID(), store.RandomUUID()
	for _, x := range []struct{ id, email, role, hash string }{
		{adminID, "admin@example.com", "admin", "unused"},
		{userID, "recover@example.com", "user", string(oldHash)},
		{peerID, "peer@example.com", "user", "unused"},
	} {
		if _, err := a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at) VALUES(?,?,?,?,?)", x.id, x.email, x.hash, x.role, store.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.DB.Exec(ctx, "UPDATE users SET totp_secret='enrolled' WHERE id=?", userID); err != nil {
		t.Fatal(err)
	}
	userToken, _, err := a.DB.NewSession(ctx, userID, "full")
	if err != nil {
		t.Fatal(err)
	}
	adminToken, adminSession, err := a.DB.NewSession(ctx, adminID, "full")
	if err != nil {
		t.Fatal(err)
	}
	peerToken, peerSession, err := a.DB.NewSession(ctx, peerID, "full")
	if err != nil {
		t.Fatal(err)
	}
	userCookie := &http.Cookie{Name: "snusnu_session", Value: userToken}
	adminCookie := &http.Cookie{Name: "snusnu_session", Value: adminToken}
	peerCookie := &http.Cookie{Name: "snusnu_session", Value: peerToken}
	profile := func(cookie *http.Cookie) string {
		t.Helper()
		r := httptest.NewRequest("GET", "/profiles/"+userID, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("profile: %d %s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	if strings.Contains(profile(peerCookie), "recover@example.com") {
		t.Fatal("private email visible to another user")
	}
	if !strings.Contains(profile(adminCookie), "recover@example.com") || !strings.Contains(profile(adminCookie), "Reset this user's password") {
		t.Fatal("admin cannot see private email or password reset action")
	}
	if !strings.Contains(profile(userCookie), "recover@example.com") {
		t.Fatal("owner cannot see own email")
	}
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)
	w := postForm(a, "/password-reset/request", url.Values{"email": {"recover@example.com"}}, nil)
	if w.Code != 303 {
		t.Fatalf("request reset: %d %s", w.Code, w.Body.String())
	}
	match := regexp.MustCompile(`password reset code for recover@example.com: ([0-9]{6})`).FindStringSubmatch(logs.String())
	if len(match) != 2 {
		t.Fatalf("reset code missing from development log: %q", logs.String())
	}
	w = postForm(a, "/password-reset", url.Values{"email": {"recover@example.com"}, "code": {"000000"}, "new_password": {"replacement-password-456"}}, nil)
	if w.Code != 400 {
		t.Fatalf("wrong reset code: %d", w.Code)
	}
	w = postForm(a, "/password-reset", url.Values{"email": {"recover@example.com"}, "code": {match[1]}, "new_password": {"replacement-password-456"}}, nil)
	if w.Code != 303 {
		t.Fatalf("complete reset: %d %s", w.Code, w.Body.String())
	}
	if _, err := a.DB.Session(ctx, userToken); err == nil {
		t.Fatal("old session survived password reset")
	}
	updated, err := a.DB.UserByID(ctx, userID)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte("replacement-password-456")) != nil || updated.TOTPSecret != "enrolled" {
		t.Fatalf("password or MFA after reset: %+v %v", updated, err)
	}
	w = postForm(a, "/password-reset", url.Values{"email": {"recover@example.com"}, "code": {match[1]}, "new_password": {"another-password-789"}}, nil)
	if w.Code != 400 {
		t.Fatalf("reused code: %d", w.Code)
	}
	w = postForm(a, "/admin/users/reset-password", url.Values{"csrf": {peerSession.CSRF}, "id": {userID}}, peerCookie)
	if w.Code != 403 {
		t.Fatalf("non-admin reset: %d", w.Code)
	}
	activeUserToken, _, err := a.DB.NewSession(ctx, userID, "full")
	if err != nil {
		t.Fatal(err)
	}
	w = postForm(a, "/admin/users/reset-password", url.Values{"csrf": {adminSession.CSRF}, "id": {userID}}, adminCookie)
	if w.Code != 200 {
		t.Fatalf("admin reset: %d %s", w.Code, w.Body.String())
	}
	temporary := regexp.MustCompile(`<code>([0-9a-f]{24})</code>`).FindStringSubmatch(w.Body.String())
	if len(temporary) != 2 {
		t.Fatalf("temporary password not shown once: %s", w.Body.String())
	}
	updated, err = a.DB.UserByID(ctx, userID)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte(temporary[1])) != nil || updated.TOTPSecret != "enrolled" {
		t.Fatalf("admin password or MFA: %+v %v", updated, err)
	}
	if _, err := a.DB.Session(ctx, adminToken); err != nil {
		t.Fatalf("admin session revoked by another user's reset: %v", err)
	}
	if _, err := a.DB.Session(ctx, activeUserToken); err == nil {
		t.Fatal("admin reset left user session active")
	}
}
