package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Origin, SMTPAddr, SMTPFrom, SMTPUser, SMTPPassword string
	MetricsKey                                         string
	CaptchaSiteKey, CaptchaSecret                      string
	MFAKey                                             []byte
	Development                                        bool
}
type App struct {
	DB                *store.Store
	Config            Config
	webauthn          *webauthn.WebAuthn
	client            *http.Client
	hub               *routerHub
	maintenance       *maintenanceManager
	circuitHistory    *dynamicQueue[circuitHistoryRecord]
	routerLogs        *dynamicQueue[store.LogEntry]
	workersOnce       sync.Once
	workersWG         sync.WaitGroup
	workerCancel      context.CancelFunc
	workersRunning    atomic.Bool
	writeFailures     atomic.Uint64
	leaseHealthy      atomic.Bool
	heartbeatFailures atomic.Uint64
	lastHeartbeat     atomic.Int64
	fatal             chan error
	historyMu         sync.Mutex
	historyPending    map[string]pendingCircuitHistory
	historyArchived   atomic.Uint64
	historyPersisted  atomic.Uint64
	historyRetries    atomic.Uint64
	historyFailed     atomic.Uint64
}

func NewApp(db *store.Store, cfg Config) (*App, error) {
	u, err := url.Parse(cfg.Origin)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && !(cfg.Development && u.Scheme == "http")) {
		return nil, errors.New("origin must be an HTTPS URL (HTTP only in development)")
	}
	if !cfg.Development && (cfg.SMTPAddr == "" || cfg.SMTPFrom == "") {
		return nil, errors.New("SMTP address and sender are required outside development mode")
	}
	if (cfg.CaptchaSiteKey == "") != (cfg.CaptchaSecret == "") {
		return nil, errors.New("both reCAPTCHA keys must be supplied")
	}
	if len(cfg.MFAKey) != 32 {
		return nil, errors.New("MFA encryption key must be 32 bytes")
	}
	w, err := webauthn.New(&webauthn.Config{RPID: u.Hostname(), RPDisplayName: "snusnu", RPOrigins: []string{cfg.Origin}})
	if err != nil {
		return nil, err
	}
	a := &App{DB: db, Config: cfg, webauthn: w, client: &http.Client{Timeout: 5 * time.Second}, circuitHistory: newDynamicQueue[circuitHistoryRecord](4096, 0, nil), routerLogs: newDynamicQueue[store.LogEntry](65536, 64<<20, func(x store.LogEntry) int { return len(x.Summary) + len(x.DetailsJSON) + 256 }), fatal: make(chan error, 1), historyPending: make(map[string]pendingCircuitHistory)}
	a.hub = newRouterHub(a)
	a.maintenance = newMaintenanceManager(a)
	return a, nil
}

func (a *App) Handler() http.Handler {
	m := http.NewServeMux()
	m.Handle("GET /assets/", http.StripPrefix("/", assetHandler()))
	m.HandleFunc("GET /livez", a.liveness)
	m.HandleFunc("GET /readyz", a.readiness)
	m.HandleFunc("GET /healthz", a.readiness)
	if a.Config.MetricsKey != "" {
		m.HandleFunc("GET /metrics", a.metricsAuthenticated)
	} else {
		m.HandleFunc("GET /metrics", http.NotFound)
	}
	m.HandleFunc("GET /openapi.json", a.openAPISpec)
	m.HandleFunc("GET /router/v1/ws", a.routerWebSocket)
	m.HandleFunc("GET /", a.home)
	m.HandleFunc("GET /register", a.registerPage)
	m.HandleFunc("POST /register", a.register)
	m.HandleFunc("GET /verify", a.verifyPage)
	m.HandleFunc("POST /verify", a.verify)
	m.HandleFunc("POST /verify/resend", a.resendVerification)
	m.HandleFunc("GET /password-reset", a.passwordResetPage)
	m.HandleFunc("POST /password-reset/request", a.passwordResetRequest)
	m.HandleFunc("POST /password-reset", a.passwordResetComplete)
	m.HandleFunc("GET /login", a.loginPage)
	m.HandleFunc("POST /login", a.login)
	m.HandleFunc("POST /logout", a.full(a.logout))
	m.HandleFunc("GET /mfa", a.pending(a.mfaPage))
	m.HandleFunc("POST /mfa/totp", a.pending(a.mfaTOTP))
	m.HandleFunc("POST /mfa/remind", a.pending(a.mfaRemind))
	m.HandleFunc("POST /mfa/passkey/begin", a.pending(a.passkeyLoginBegin))
	m.HandleFunc("POST /mfa/passkey/finish", a.pending(a.passkeyLoginFinish))
	m.HandleFunc("GET /dashboard", a.full(a.dashboard))
	m.HandleFunc("GET /routers/new", a.full(a.routerNewPage))
	m.HandleFunc("POST /routers", a.full(a.routerCreate))
	m.HandleFunc("GET /routers/{id}", a.full(a.routerDetails))
	m.HandleFunc("POST /routers/{id}/rename", a.full(a.routerRename))
	m.HandleFunc("POST /routers/{id}/pause", a.full(a.routerPause))
	m.HandleFunc("POST /routers/{id}/rotate", a.full(a.routerRotate))
	m.HandleFunc("POST /routers/{id}/delete", a.full(a.routerDelete))
	m.HandleFunc("POST /routers/{id}/llc-facing", a.full(a.routerLLCFacing))
	m.HandleFunc("GET /llc-macs", http.NotFound)
	m.HandleFunc("POST /llc-macs", http.NotFound)
	m.HandleFunc("POST /llc-macs/{id}/enabled", http.NotFound)
	m.HandleFunc("POST /llc-macs/{id}/retire", http.NotFound)
	m.HandleFunc("GET /admin/llc-macs", a.admin(a.adminManagedCPPage))
	m.HandleFunc("GET /flows", a.full(a.flows))
	m.HandleFunc("GET /circuits", a.full(a.snaCircuits))
	m.HandleFunc("POST /circuits/{id}/reset", a.full(a.resetSNACircuit))
	m.HandleFunc("GET /blocks", a.full(a.blocks))
	m.HandleFunc("POST /blocks/{id}/remove", a.full(a.removeBlock))
	m.HandleFunc("GET /admin/blocks", a.admin(a.adminBlocks))
	m.HandleFunc("GET /profile/edit", a.full(a.profileEditPage))
	m.HandleFunc("POST /profile/edit", a.full(a.profileEdit))
	m.HandleFunc("POST /profile/picture", a.full(a.profilePictureUpload))
	m.HandleFunc("POST /profile/picture/delete", a.full(a.profilePictureDelete))
	m.HandleFunc("GET /profiles/{id}", a.full(a.profileView))
	m.HandleFunc("GET /profiles/{id}/picture", a.full(a.profilePicture))
	m.HandleFunc("POST /profiles/{id}/block", a.full(a.profileBlock))
	m.HandleFunc("GET /settings", a.full(a.settings))
	m.HandleFunc("GET /settings/delete", a.full(a.deleteOwnAccountPage))
	m.HandleFunc("POST /settings/delete", a.full(a.deleteOwnAccount))
	m.HandleFunc("POST /settings/password", a.full(a.changePassword))
	m.HandleFunc("POST /settings/totp/begin", a.full(a.totpBegin))
	m.HandleFunc("POST /settings/totp/finish", a.full(a.totpFinish))
	m.HandleFunc("POST /settings/totp/remove", a.full(a.totpRemove))
	m.HandleFunc("POST /settings/passkey/begin", a.full(a.passkeyRegisterBegin))
	m.HandleFunc("POST /settings/passkey/finish", a.full(a.passkeyRegisterFinish))
	m.HandleFunc("POST /settings/passkey/remove", a.full(a.passkeyRemove))
	m.HandleFunc("GET /clients", a.full(a.clients))
	m.HandleFunc("POST /clients", a.full(a.createClient))
	m.HandleFunc("POST /clients/revoke", a.full(a.revokeClient))
	m.HandleFunc("GET /directory", a.full(a.globalDirectory))
	m.HandleFunc("GET /planning-directory", a.admin(a.directory))
	m.HandleFunc("GET /connections", a.full(a.connections))
	m.HandleFunc("GET /admin/users", a.admin(a.users))
	m.HandleFunc("GET /admin/users/{id}/delete", a.admin(a.adminDeleteUserPage))
	m.HandleFunc("POST /admin/users/{id}/delete", a.admin(a.adminDeleteUser))
	m.HandleFunc("GET /admin/routers", a.admin(a.adminRouters))
	m.HandleFunc("GET /admin/operations", a.admin(a.adminOperations))
	m.HandleFunc("GET /admin/circuits", a.admin(a.adminSNACircuits))
	m.HandleFunc("POST /admin/circuits/{id}/reset", a.admin(a.adminResetSNACircuit))
	m.HandleFunc("POST /admin/operations/{task}/run", a.admin(a.runMaintenanceTask))
	m.HandleFunc("POST /admin/users/role", a.admin(a.setRole))
	m.HandleFunc("POST /admin/users/reset-password", a.admin(a.adminResetPassword))
	m.HandleFunc("POST /admin/directory", a.admin(a.createDirectory))
	m.HandleFunc("POST /admin/directory/update", a.admin(a.updateDirectory))
	m.HandleFunc("POST /admin/directory/delete", a.admin(a.deleteDirectory))
	m.HandleFunc("POST /admin/connections", a.admin(a.createConnection))
	m.HandleFunc("POST /admin/connections/update", a.admin(a.updateConnection))
	m.HandleFunc("POST /admin/connections/delete", a.admin(a.deleteConnection))
	for _, endpoint := range a.apiEndpoints() {
		m.HandleFunc(endpoint.Method+" "+endpoint.Path, a.api(endpoint.Handler))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		m.ServeHTTP(w, r)
	})
}

type handler func(http.ResponseWriter, *http.Request, store.User, store.Session)

func (a *App) auth(w http.ResponseWriter, r *http.Request) (store.User, store.Session, bool) {
	c, err := r.Cookie("snusnu_session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return store.User{}, store.Session{}, false
	}
	s, err := a.DB.Session(r.Context(), c.Value)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return store.User{}, store.Session{}, false
	}
	u, err := a.DB.UserByID(r.Context(), s.UserID)
	if err != nil {
		http.Error(w, "session user missing", 500)
		return store.User{}, store.Session{}, false
	}
	if r.Method == http.MethodPost {
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			err = r.ParseMultipartForm(1 << 20)
		} else {
			err = r.ParseForm()
		}
		if err != nil {
			http.Error(w, "bad form", 400)
			return store.User{}, store.Session{}, false
		}
		csrf := r.FormValue("csrf")
		if csrf == "" {
			csrf = r.Header.Get("X-CSRF-Token")
		}
		if subtle.ConstantTimeCompare([]byte(csrf), []byte(s.CSRF)) != 1 {
			http.Error(w, "invalid CSRF token", 403)
			return store.User{}, store.Session{}, false
		}
	}
	return u, s, true
}
func (a *App) full(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, s, ok := a.auth(w, r)
		if !ok {
			return
		}
		if s.State != "full" {
			http.Redirect(w, r, "/mfa", 303)
			return
		}
		h(w, r, u, s)
	}
}
func (a *App) pending(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, s, ok := a.auth(w, r)
		if !ok {
			return
		}
		if s.State == "full" {
			http.Redirect(w, r, "/dashboard", 303)
			return
		}
		h(w, r, u, s)
	}
}
func (a *App) admin(h handler) http.HandlerFunc {
	return a.full(func(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
		if u.Role != "admin" {
			http.Error(w, "forbidden", 403)
			return
		}
		h(w, r, u, s)
	})
}
func (a *App) setSession(w http.ResponseWriter, token string, remember bool) {
	cookie := &http.Cookie{Name: "snusnu_session", Value: token, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(a.Config.Origin, "https://"), SameSite: http.SameSiteLaxMode}
	if remember {
		cookie.MaxAge = 30 * 24 * 3600
	}
	http.SetCookie(w, cookie)
}
func (a *App) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "snusnu_session", Path: "/", MaxAge: -1, HttpOnly: true})
}
func (a *App) home(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/dashboard", 303) }
func (a *App) logout(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	a.DB.Exec(r.Context(), "DELETE FROM sessions WHERE id=?", s.ID)
	a.clearSession(w)
	http.Redirect(w, r, "/login", 303)
}

func (a *App) registerPage(w http.ResponseWriter, r *http.Request) {
	a.render(w, "register", map[string]any{"CaptchaKey": a.Config.CaptchaSiteKey})
}
func (a *App) register(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	if !a.captcha(w, r) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if _, err := mail.ParseAddress(email); err != nil || len(email) > 254 || strings.ContainsAny(email, "<> ") {
		http.Error(w, "invalid email", 400)
		return
	}
	netid := strings.ToUpper(strings.TrimSpace(r.FormValue("netid")))
	if !store.ValidNetID(netid) {
		http.Error(w, "NETID must be 1-8 valid SNA characters", http.StatusBadRequest)
		return
	}
	password := r.FormValue("password")
	if len(password) < 12 || len(password) > 72 {
		http.Error(w, "password must be 12-72 characters", 400)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	id, err := store.Random()
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	code, err := verificationCode()
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	ctx := r.Context()
	tx, err := a.DB.DB.BeginTx(ctx, nil)
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, a.DB.Q("INSERT INTO users(id,email,password_hash,role,netid) VALUES(?,?,?,'user',?)"), id, email, string(hash), netid)
	if err != nil {
		http.Error(w, "email or NETID already registered", 409)
		return
	}
	_, err = tx.ExecContext(ctx, a.DB.Q("INSERT INTO email_tokens(user_id,code_hash,expires_at) VALUES(?,?,?)"), id, store.Hash(id+code), store.Now()+600)
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	if err = tx.Commit(); err != nil {
		http.Error(w, "server error", 500)
		return
	}
	if err = a.sendVerification(email, code); err != nil {
		log.Printf("email delivery failed for %s: %v", email, err)
		http.Error(w, "email delivery failed", 500)
		return
	}
	http.Redirect(w, r, "/verify?email="+url.QueryEscape(email), 303)
}
func verificationCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
func (a *App) sendVerification(email, code string) error {
	return a.sendEmailCode(email, code, "email verification")
}
func (a *App) sendEmailCode(email, code, purpose string) error {
	if a.Config.Development {
		log.Printf("development %s code for %s: %s", purpose, email, code)
		return nil
	}
	from := a.Config.SMTPFrom
	if from == "" {
		return errors.New("SMTP_FROM missing")
	}
	msg := []byte("From: " + from + "\r\nTo: " + email + "\r\nSubject: snusnu " + purpose + "\r\n\r\nYour " + purpose + " code is " + code + ". It expires in 10 minutes.\r\n")
	host, _, err := net.SplitHostPort(a.Config.SMTPAddr)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", a.Config.SMTPAddr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); !ok {
		return errors.New("SMTP server does not offer STARTTLS")
	}
	if err = c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
		return err
	}
	if a.Config.SMTPUser != "" {
		if err = c.Auth(smtp.PlainAuth("", a.Config.SMTPUser, a.Config.SMTPPassword, host)); err != nil {
			return err
		}
	}
	if err = c.Mail(from); err != nil {
		return err
	}
	if err = c.Rcpt(email); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err = w.Write(msg); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
func (a *App) verifyPage(w http.ResponseWriter, r *http.Request) {
	a.render(w, "verify", map[string]any{"Email": r.URL.Query().Get("email"), "CaptchaKey": a.Config.CaptchaSiteKey})
}
func (a *App) resendVerification(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	if !a.captcha(w, r) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	key := store.Hash("verify-resend:" + email)
	if !a.allowed(r, []string{key}, 3) {
		http.Error(w, "too many requests; try later", 429)
		return
	}
	u, err := a.DB.UserByEmail(r.Context(), email)
	if err != nil || u.VerifiedAt != 0 {
		http.Redirect(w, r, "/verify?email="+url.QueryEscape(email), 303)
		return
	}
	var expires int64
	err = a.DB.Row(r.Context(), "SELECT expires_at FROM email_tokens WHERE user_id=?", u.ID).Scan(&expires)
	if err != nil && err != sql.ErrNoRows {
		dbError(w, err)
		return
	}
	if expires > store.Now()+540 {
		http.Error(w, "wait a minute before requesting another code", 429)
		return
	}
	code, err := verificationCode()
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	if err = a.sendVerification(email, code); err != nil {
		http.Error(w, "email delivery failed", 503)
		return
	}
	if _, err = a.DB.Exec(r.Context(), "INSERT INTO email_tokens(user_id,code_hash,expires_at,attempts) VALUES(?,?,?,0) ON CONFLICT(user_id) DO UPDATE SET code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0", u.ID, store.Hash(u.ID+code), store.Now()+600); err != nil {
		dbError(w, err)
		return
	}
	if err = a.failed(r, []string{key}); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/verify?email="+url.QueryEscape(email), 303)
}
func (a *App) verify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	u, err := a.DB.UserByEmail(r.Context(), strings.ToLower(strings.TrimSpace(r.FormValue("email"))))
	if err != nil || len(r.FormValue("code")) != 6 {
		http.Error(w, "invalid code", 400)
		return
	}
	var hash string
	var expires int64
	var attempts int
	err = a.DB.Row(r.Context(), "SELECT code_hash,expires_at,attempts FROM email_tokens WHERE user_id=?", u.ID).Scan(&hash, &expires, &attempts)
	if err != nil || expires < store.Now() || attempts >= 5 {
		http.Error(w, "code expired or unavailable", 400)
		return
	}
	res, err := a.DB.Exec(r.Context(), "UPDATE email_tokens SET attempts=attempts+1 WHERE user_id=? AND attempts<5 AND expires_at>?", u.ID, store.Now())
	if err != nil {
		dbError(w, err)
		return
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		http.Error(w, "code expired or unavailable", 400)
		return
	}
	if subtle.ConstantTimeCompare([]byte(hash), []byte(store.Hash(u.ID+r.FormValue("code")))) != 1 {
		http.Error(w, "invalid code", 400)
		return
	}
	tx, err := a.DB.DB.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), a.DB.Q("UPDATE users SET verified_at=? WHERE id=?"), store.Now(), u.ID); err != nil {
		http.Error(w, "server error", 500)
		return
	}
	if _, err = tx.ExecContext(r.Context(), a.DB.Q("DELETE FROM email_tokens WHERE user_id=?"), u.ID); err != nil {
		http.Error(w, "server error", 500)
		return
	}
	if err = tx.Commit(); err != nil {
		http.Error(w, "server error", 500)
		return
	}
	http.Redirect(w, r, "/login", 303)
}

func (a *App) loginPage(w http.ResponseWriter, r *http.Request) {
	a.render(w, "login", map[string]any{"CaptchaKey": a.Config.CaptchaSiteKey})
}
func (a *App) loginError(w http.ResponseWriter, status int, message, email string, remember bool) {
	w.WriteHeader(status)
	a.render(w, "login", map[string]any{
		"CaptchaKey": a.Config.CaptchaSiteKey,
		"Error":      message,
		"Email":      email,
		"Remember":   remember,
	})
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	if !a.captcha(w, r) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	remember := r.FormValue("remember") == "1"
	keys := loginKeys(r, email)
	if !a.allowed(r, keys, 10) {
		a.loginError(w, http.StatusTooManyRequests, "Too many attempts; try again later.", email, remember)
		return
	}
	u, err := a.DB.UserByEmail(r.Context(), email)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(r.FormValue("password"))) != nil {
		if err = a.failed(r, keys); err != nil {
			dbError(w, err)
			return
		}
		a.loginError(w, http.StatusUnauthorized, "The email address or password is incorrect.", email, remember)
		return
	}
	a.clearFailures(r, keys)
	if u.VerifiedAt == 0 {
		a.loginError(w, http.StatusForbidden, "Verify your email address before signing in.", email, remember)
		return
	}
	var count int
	if err = a.DB.Row(r.Context(), "SELECT COUNT(*) FROM passkeys WHERE user_id=?", u.ID).Scan(&count); err != nil {
		http.Error(w, "server error", 500)
		return
	}
	state := "full"
	if u.TOTPSecret != "" || count > 0 {
		state = "mfa"
	} else if u.RemindAfter <= store.Now() {
		state = "enroll"
	}
	token, _, err := a.DB.NewSessionWithRemember(r.Context(), u.ID, state, remember)
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	a.setSession(w, token, remember)
	if state == "full" {
		http.Redirect(w, r, "/dashboard", 303)
	} else {
		http.Redirect(w, r, "/mfa", 303)
	}
}

func (a *App) captcha(w http.ResponseWriter, r *http.Request) bool {
	if a.Config.CaptchaSecret == "" {
		return true
	}
	token := r.FormValue("g-recaptcha-response")
	if token == "" {
		http.Error(w, "complete reCAPTCHA", 400)
		return false
	}
	v := url.Values{"secret": {a.Config.CaptchaSecret}, "response": {token}}
	resp, err := a.client.PostForm("https://www.google.com/recaptcha/api/siteverify", v)
	if err != nil {
		http.Error(w, "reCAPTCHA unavailable", 503)
		return false
	}
	defer resp.Body.Close()
	var result struct {
		Success  bool   `json:"success"`
		Hostname string `json:"hostname"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&result) != nil || !result.Success {
		http.Error(w, "reCAPTCHA failed", 403)
		return false
	}
	if result.Hostname != mustHost(a.Config.Origin) {
		http.Error(w, "reCAPTCHA hostname mismatch", 403)
		return false
	}
	return true
}
func mustHost(origin string) string { u, _ := url.Parse(origin); return u.Hostname() }

func (a *App) api(h func(http.ResponseWriter, *http.Request, store.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "unauthorized", 401)
			return
		}
		var id string
		err := a.DB.Row(r.Context(), "SELECT user_id FROM api_clients WHERE secret_hash=? AND revoked_at=0", store.Hash(parts[1])).Scan(&id)
		if err != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		u, err := a.DB.UserByID(r.Context(), id)
		if err != nil || u.VerifiedAt == 0 {
			http.Error(w, "unauthorized", 401)
			return
		}
		h(w, r, u)
	}
}
func jsonResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Print(err)
	}
}
func dbError(w http.ResponseWriter, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, nil)
	} else {
		log.Print(err)
		http.Error(w, "database error", 500)
	}
}
func (a *App) render(w http.ResponseWriter, name string, data map[string]any) {
	pageLayout := strings.Replace(layout, `<a class="nav-link" href="/llc-macs">LLC MACs</a>`, "", 1)
	pageLayout = strings.Replace(pageLayout, `<a class="nav-link" href="/clients">API clients</a>`, "", 1)
	pageLayout = strings.Replace(pageLayout, `<a class="nav-link" href="/flows">Flows</a>`, `<a class="nav-link" href="/flows">Flows</a><a class="nav-link" href="/circuits">SNA circuits</a>`, 1)
	pageLayout = strings.Replace(pageLayout, `>All MACs</a>`, `>LLC allocations</a>`, 1)
	pageLayout = strings.Replace(pageLayout, `<a class="dropdown-item" href="/admin/routers">All routers</a>`, `<a class="dropdown-item" href="/admin/routers">All routers</a><a class="dropdown-item" href="/admin/circuits">All SNA circuits</a><a class="dropdown-item" href="/admin/operations">Operations</a>`, 1)
	pageLayout = strings.Replace(pageLayout, `<a class="dropdown-item" href="/settings">Settings</a>`, `<a class="dropdown-item" href="/settings">Settings</a><a class="dropdown-item" href="/clients">API keys</a>`, 1)
	t, err := template.New("page").Funcs(template.FuncMap{"date": func(unix int64) string {
		if unix == 0 {
			return "Never"
		}
		return time.Unix(unix, 0).UTC().Format(time.RFC3339)
	}, "prettyJSON": prettyJSON}).Parse(pageLayout + nodeAddressTemplate + pages[name])
	if err != nil {
		log.Print(err)
		http.Error(w, "template error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err = t.Execute(w, data); err != nil {
		log.Print(err)
	}
}

func prettyJSON(raw string) string {
	var out bytes.Buffer
	if err := json.Indent(&out, []byte(raw), "", "  "); err != nil {
		return raw
	}
	return out.String()
}
