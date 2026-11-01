package server

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func testApp(t *testing.T) *App {
	t.Helper()
	db, err := store.Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.DB.Close() })
	a, err := NewApp(db, Config{Origin: "http://localhost:8080", Development: true, MFAKey: bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func postForm(a *App, path string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}
func TestRegistrationVerificationAndMFAEnrollmentReminder(t *testing.T) {
	a := testApp(t)
	var logs bytes.Buffer
	original := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(original)
	w := postForm(a, "/register", url.Values{"email": {"alice@example.com"}, "password": {"a-long-test-password"}}, nil)
	if w.Code != 303 {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	code := regexp.MustCompile(`code for alice@example.com: ([0-9]{6})`).FindStringSubmatch(logs.String())
	if len(code) != 2 {
		t.Fatalf("verification code missing from development log: %q", logs.String())
	}
	w = postForm(a, "/login", url.Values{"email": {"alice@example.com"}, "password": {"a-long-test-password"}}, nil)
	if w.Code != 403 {
		t.Fatalf("unverified login: %d", w.Code)
	}
	w = postForm(a, "/verify", url.Values{"email": {"alice@example.com"}, "code": {code[1]}}, nil)
	if w.Code != 303 {
		t.Fatalf("verify: %d %s", w.Code, w.Body.String())
	}
	w = postForm(a, "/login", url.Values{"email": {"alice@example.com"}, "password": {"a-long-test-password"}}, nil)
	if w.Code != 303 || w.Header().Get("Location") != "/mfa" {
		t.Fatalf("login: %d %s", w.Code, w.Header().Get("Location"))
	}
	cookie := w.Result().Cookies()[0]
	s, err := a.DB.Session(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	w = postForm(a, "/mfa/remind", url.Values{"csrf": {s.CSRF}, "remind": {"1"}}, cookie)
	if w.Code != 303 {
		t.Fatalf("remind: %d %s", w.Code, w.Body.String())
	}
	w = postForm(a, "/logout", url.Values{"csrf": {s.CSRF}}, cookie)
	if w.Code != 303 {
		t.Fatalf("logout: %d", w.Code)
	}
	w = postForm(a, "/login", url.Values{"email": {"alice@example.com"}, "password": {"a-long-test-password"}}, nil)
	if w.Code != 303 || w.Header().Get("Location") != "/dashboard" {
		t.Fatalf("remembered login: %d %s", w.Code, w.Header().Get("Location"))
	}
}
func TestAssetsAreEmbedded(t *testing.T) {
	a := testApp(t)
	for _, path := range []string{"/assets/bootstrap.min.css", "/assets/bootstrap.bundle.min.js", "/assets/passkeys.js"} {
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 || w.Body.Len() < 100 {
			t.Fatalf("asset %s: %d %d bytes", path, w.Code, w.Body.Len())
		}
	}
}

func TestPagesRender(t *testing.T) {
	a := testApp(t)
	for _, path := range []string{"/register", "/verify", "/login"} {
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), "/assets/bootstrap.min.css") {
			t.Fatalf("page %s: %d %s", path, w.Code, w.Body.String())
		}
	}
}

func TestRoleAndClientVisibility(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	adminID, _ := store.Random()
	userID, _ := store.Random()
	otherID, _ := store.Random()
	for _, x := range []struct{ id, email, role string }{{adminID, "admin@example.com", "admin"}, {userID, "user@example.com", "user"}, {otherID, "other@example.com", "user"}} {
		if _, err := a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at) VALUES(?,?,?,?,?)", x.id, x.email, "unused", x.role, store.Now()); err != nil {
			t.Fatal(err)
		}
	}
	adminToken, adminSession, err := a.DB.NewSession(ctx, adminID, "full")
	if err != nil {
		t.Fatal(err)
	}
	userToken, userSession, err := a.DB.NewSession(ctx, userID, "full")
	if err != nil {
		t.Fatal(err)
	}
	otherConn, _ := store.Random()
	a.DB.Exec(ctx, "INSERT INTO connections(id,owner_id,name,remote_site,created_at) VALUES(?,?,?,?,?)", otherConn, otherID, "other connection", "remote", store.Now())
	myConn, _ := store.Random()
	a.DB.Exec(ctx, "INSERT INTO connections(id,owner_id,name,remote_site,created_at) VALUES(?,?,?,?,?)", myConn, userID, "my connection", "remote", store.Now())
	userCookie := &http.Cookie{Name: "snusnu_session", Value: userToken}
	adminCookie := &http.Cookie{Name: "snusnu_session", Value: adminToken}
	for _, tc := range []struct {
		cookie       *http.Cookie
		want, absent string
	}{{userCookie, "my connection", "other connection"}, {adminCookie, "other connection", ""}} {
		r := httptest.NewRequest("GET", "/connections", nil)
		r.AddCookie(tc.cookie)
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), tc.want) || tc.absent != "" && strings.Contains(w.Body.String(), tc.absent) {
			t.Fatalf("visibility: %d %s", w.Code, w.Body.String())
		}
	}
	w := postForm(a, "/admin/directory", url.Values{"csrf": {userSession.CSRF}, "site": {"s"}, "mac": {"a"}, "sap": {"4"}}, userCookie)
	if w.Code != 403 {
		t.Fatalf("normal user admin write: %d", w.Code)
	}
	w = postForm(a, "/admin/directory", url.Values{"csrf": {adminSession.CSRF}, "site": {"s"}, "mac": {"a"}, "sap": {"4"}}, adminCookie)
	if w.Code != 303 {
		t.Fatalf("admin write: %d %s", w.Code, w.Body.String())
	}
	otherRouter, _, err := a.DB.CreateRouter(ctx, otherID, "Other user's router")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path   string
		cookie *http.Cookie
		status int
	}{{"/admin/routers", userCookie, 403}, {"/routers/" + otherRouter.ID, userCookie, 403}, {"/admin/routers", adminCookie, 200}, {"/routers/" + otherRouter.ID, adminCookie, 200}} {
		r := httptest.NewRequest("GET", tc.path, nil)
		r.AddCookie(tc.cookie)
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("router access %s: got %d want %d", tc.path, w.Code, tc.status)
		}
	}
	w = postForm(a, "/clients", url.Values{"csrf": {userSession.CSRF}, "name": {"test client"}}, userCookie)
	if w.Code != 200 {
		t.Fatalf("create client: %d %s", w.Code, w.Body.String())
	}
	token := regexp.MustCompile(`<code>([0-9a-f]{64})</code>`).FindStringSubmatch(w.Body.String())
	if len(token) != 2 {
		t.Fatalf("client token missing: %s", w.Body.String())
	}
	r := httptest.NewRequest("GET", "/api/v1/connections", nil)
	r.Header.Set("Authorization", "Bearer "+token[1])
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "my connection") || strings.Contains(w.Body.String(), "other connection") {
		t.Fatalf("API visibility: %d %s", w.Code, w.Body.String())
	}
}

func TestTOTPEnrollmentAndLogin(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	id, _ := store.Random()
	password := "a-long-test-password"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at) VALUES(?,?,?,'user',?)", id, "totp@example.com", string(hash), store.Now()); err != nil {
		t.Fatal(err)
	}
	token, s, err := a.DB.NewSession(ctx, id, "full")
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: "snusnu_session", Value: token}
	w := postForm(a, "/settings/totp/begin", url.Values{"csrf": {s.CSRF}}, cookie)
	if w.Code != 200 {
		t.Fatalf("start TOTP: %d %s", w.Code, w.Body.String())
	}
	secret := regexp.MustCompile(`<code>([A-Z2-7]+)</code>`).FindStringSubmatch(w.Body.String())
	if len(secret) != 2 {
		t.Fatalf("secret missing: %s", w.Body.String())
	}
	code, err := totp.GenerateCode(secret[1], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	w = postForm(a, "/settings/totp/finish", url.Values{"csrf": {s.CSRF}, "code": {code}}, cookie)
	if w.Code != 303 {
		t.Fatalf("finish TOTP: %d %s", w.Code, w.Body.String())
	}
	w = postForm(a, "/login", url.Values{"email": {"totp@example.com"}, "password": {password}}, nil)
	if w.Code != 303 || w.Header().Get("Location") != "/mfa" {
		t.Fatalf("TOTP login: %d %s", w.Code, w.Header().Get("Location"))
	}
	mfaCookie := w.Result().Cookies()[0]
	mfaSession, err := a.DB.Session(ctx, mfaCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	w = postForm(a, "/mfa/totp", url.Values{"csrf": {mfaSession.CSRF}, "code": {code}}, mfaCookie)
	if w.Code != 303 {
		t.Fatalf("TOTP auth: %d %s", w.Code, w.Body.String())
	}
}

func TestPasskeyCeremonyIsBoundToSession(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	id, _ := store.Random()
	if _, err := a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at) VALUES(?,?,?,'user',?)", id, "passkey@example.com", "unused", store.Now()); err != nil {
		t.Fatal(err)
	}
	token, s, err := a.DB.NewSession(ctx, id, "full")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/settings/passkey/begin", nil)
	r.AddCookie(&http.Cookie{Name: "snusnu_session", Value: token})
	r.Header.Set("X-CSRF-Token", s.CSRF)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "publicKey") {
		t.Fatalf("begin passkey: %d %s", w.Code, w.Body.String())
	}
	var count int
	if err = a.DB.Row(ctx, "SELECT COUNT(*) FROM ceremonies WHERE session_id=?", s.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("ceremony storage: %d %v", count, err)
	}
	r = httptest.NewRequest("POST", "/settings/passkey/finish", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", s.CSRF)
	r.AddCookie(&http.Cookie{Name: "snusnu_session", Value: token})
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("invalid finish: %d", w.Code)
	}
	if err = a.DB.Row(ctx, "SELECT COUNT(*) FROM ceremonies WHERE session_id=?", s.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("ceremony not consumed: %d %v", count, err)
	}
}

func TestRouterOnboardingProfileAndDirectory(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	owner := store.RandomUUID()
	viewer := store.RandomUUID()
	for _, x := range []struct{ id, email string }{{owner, "owner@example.com"}, {viewer, "viewer@example.com"}} {
		if _, err := a.DB.Exec(ctx, "INSERT INTO users(id,email,password_hash,role,verified_at) VALUES(?,?,?,'user',?)", x.id, x.email, "unused", store.Now()); err != nil {
			t.Fatal(err)
		}
	}
	token, s, err := a.DB.NewSession(ctx, owner, "full")
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: "snusnu_session", Value: token}
	w := postForm(a, "/routers", url.Values{"csrf": {s.CSRF}, "name": {"Basement gateway"}}, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "/router/v1/ws") {
		t.Fatalf("onboard: %d %s", w.Code, w.Body.String())
	}
	var routerID string
	if err = a.DB.Row(ctx, "SELECT id FROM routers WHERE owner_id=?", owner).Scan(&routerID); err != nil {
		t.Fatal(err)
	}
	var secret string
	if parts := regexp.MustCompile(`<code>([0-9a-f]{64})</code>`).FindStringSubmatch(w.Body.String()); len(parts) == 2 {
		secret = parts[1]
	} else {
		t.Fatal("router token missing")
	}
	if _, err = a.DB.RouterByToken(ctx, secret); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/dashboard", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Basement gateway") || !strings.Contains(w.Body.String(), "Offline") {
		t.Fatalf("dashboard: %d %s", w.Code, w.Body.String())
	}
	w = postForm(a, "/routers/"+routerID+"/pause", url.Values{"csrf": {s.CSRF}, "paused": {"1"}}, cookie)
	if w.Code != 303 {
		t.Fatalf("pause: %d", w.Code)
	}
	if _, err = a.DB.RouterByToken(ctx, secret); !errors.Is(err, store.ErrPaused) {
		t.Fatalf("paused credential accepted: %v", err)
	}
	w = postForm(a, "/routers/"+routerID+"/rotate", url.Values{"csrf": {s.CSRF}}, cookie)
	if w.Code != 200 {
		t.Fatalf("rotate: %d %s", w.Code, w.Body.String())
	}
	if _, err = a.DB.RouterByToken(ctx, secret); err == nil {
		t.Fatal("old router token accepted")
	}
	w = postForm(a, "/profile/edit", url.Values{"csrf": {s.CSRF}, "username": {"basement-user"}, "first_name": {"Alice"}}, cookie)
	if w.Code != 303 {
		t.Fatalf("profile edit: %d %s", w.Code, w.Body.String())
	}
	viewerToken, viewerSession, err := a.DB.NewSession(ctx, viewer, "full")
	if err != nil {
		t.Fatal(err)
	}
	viewerCookie := &http.Cookie{Name: "snusnu_session", Value: viewerToken}
	r = httptest.NewRequest("GET", "/profiles/"+owner, nil)
	r.AddCookie(viewerCookie)
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "basement-user") || strings.Contains(w.Body.String(), "owner@example.com") {
		t.Fatalf("private profile: %d %s", w.Code, w.Body.String())
	}
	w = postForm(a, "/profiles/"+owner+"/block", url.Values{"csrf": {viewerSession.CSRF}, "blocked": {"1"}}, viewerCookie)
	if w.Code != 303 {
		t.Fatalf("block: %d", w.Code)
	}
	blocked, err := a.DB.IsBlocked(ctx, viewer, owner)
	if err != nil || !blocked {
		t.Fatalf("block state: %t %v", blocked, err)
	}
	w = postForm(a, "/routers/"+routerID+"/pause", url.Values{"csrf": {s.CSRF}, "paused": {"0"}}, cookie)
	if w.Code != 303 {
		t.Fatalf("resume: %d", w.Code)
	}
	epoch, err := a.DB.BeginRouterEpoch(ctx, routerID, "192.0.2.20")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.DB.ReplaceRouterSnapshot(ctx, routerID, epoch, 1, []store.RouteExport{{ID: 1, Generation: 1, Kind: "CP", NetID: "SOLNET", Name: "SNAB"}}); err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest("GET", "/directory", nil)
	r.AddCookie(viewerCookie)
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "SOLNET.SNAB") || !strings.Contains(w.Body.String(), "basement-user") {
		t.Fatalf("directory: %d %s", w.Code, w.Body.String())
	}
	w = postForm(a, "/profile/edit", url.Values{"csrf": {s.CSRF}, "username": {"basement-user"}, "public_email": {"1"}}, cookie)
	if w.Code != 303 {
		t.Fatalf("public email edit: %d", w.Code)
	}
	r = httptest.NewRequest("GET", "/profiles/"+owner, nil)
	r.AddCookie(viewerCookie)
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "owner@example.com") {
		t.Fatalf("public email absent: %d %s", w.Code, w.Body.String())
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mw.WriteField("csrf", s.CSRF)
	part, err := mw.CreateFormFile("picture", "avatar.png")
	if err != nil {
		t.Fatal(err)
	}
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	if err = png.Encode(part, img); err != nil {
		t.Fatal(err)
	}
	if err = mw.Close(); err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest("POST", "/profile/picture", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("picture upload: %d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest("GET", "/profiles/"+owner+"/picture", nil)
	r.AddCookie(viewerCookie)
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("picture view: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
}
