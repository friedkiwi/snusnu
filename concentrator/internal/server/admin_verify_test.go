package server

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

func TestAdminManuallyVerifiesUser(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	adminID, adminCookie, adminSession := uiUser(t, a, "verify-admin@example.com", "admin", "admin-password-123")
	targetID, targetCookie, targetSession := uiUser(t, a, "verify-target@example.com", "user", "target-password-123")
	if _, err := a.DB.Exec(ctx, "UPDATE users SET verified_at=0 WHERE id=?", targetID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB.Exec(ctx, "INSERT INTO email_tokens(user_id,code_hash,expires_at,attempts) VALUES(?,?,?,0)", targetID, store.Hash(targetID+"123456"), store.Now()+600); err != nil {
		t.Fatal(err)
	}
	if w := uiGet(t, a, "/admin/users?q=verify-target", adminCookie); w.Code != 200 || !strings.Contains(w.Body.String(), `action="/admin/users/verify"`) || !strings.Contains(w.Body.String(), `Verify verify-target@example.com`) {
		t.Fatalf("verify action absent: %d %s", w.Code, w.Body.String())
	}
	path := "/admin/users/verify"
	form := url.Values{"csrf": {adminSession.CSRF}, "id": {targetID}}
	if w := postForm(a, path, url.Values{"csrf": {targetSession.CSRF}, "id": {targetID}}, targetCookie); w.Code != 403 {
		t.Fatalf("nonadmin verified user: %d", w.Code)
	}
	if w := postForm(a, path, url.Values{"id": {targetID}}, adminCookie); w.Code != 403 {
		t.Fatalf("missing CSRF accepted: %d", w.Code)
	}
	if w := postForm(a, path, form, adminCookie); w.Code != 303 {
		t.Fatalf("admin verify: %d %s", w.Code, w.Body.String())
	}
	target, err := a.DB.UserByID(ctx, targetID)
	if err != nil || target.VerifiedAt == 0 {
		t.Fatalf("user still unverified: %+v %v", target, err)
	}
	var remaining int
	if err := a.DB.Row(ctx, "SELECT COUNT(*) FROM email_tokens WHERE user_id=?", targetID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("verification token retained: %d %v", remaining, err)
	}
	if w := uiGet(t, a, "/admin/users?q=verify-target", adminCookie); w.Code != 200 || strings.Contains(w.Body.String(), `action="/admin/users/verify"`) {
		t.Fatalf("verify button remains: %d %s", w.Code, w.Body.String())
	}
	if w := postForm(a, path, form, adminCookie); w.Code != 303 {
		t.Fatalf("idempotent verification: %d", w.Code)
	}
	if err := a.DB.AdminVerifyUser(ctx, targetID, adminID); !errors.Is(err, store.ErrNotAdmin) {
		t.Fatalf("store accepted nonadmin actor: %v", err)
	}
	if err := a.DB.AdminVerifyUser(ctx, adminID, store.RandomUUID()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("store accepted missing target: %v", err)
	}
}
