package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func (a *App) mfaPage(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	var count int
	a.DB.Row(r.Context(), "SELECT COUNT(*) FROM passkeys WHERE user_id=?", u.ID).Scan(&count)
	a.render(w, "mfa", map[string]any{"User": u, "CSRF": s.CSRF, "Enroll": s.State == "enroll", "TOTP": u.TOTPSecret != "", "Passkeys": count > 0})
}
func (a *App) mfaTOTP(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	if s.State != "mfa" || u.TOTPSecret == "" {
		http.Error(w, "TOTP unavailable", 400)
		return
	}
	key := store.Hash("mfa:" + s.ID)
	if !a.allowed(r, []string{key}, 10) {
		http.Error(w, "too many attempts; try later", 429)
		return
	}
	secret, err := a.decrypt(u.TOTPSecret)
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	if !totp.Validate(strings.TrimSpace(r.FormValue("code")), secret) {
		if err = a.failed(r, []string{key}); err != nil {
			dbError(w, err)
			return
		}
		http.Error(w, "invalid code", 401)
		return
	}
	a.clearFailures(r, []string{key})
	a.finishMFA(w, r, s)
}
func (a *App) mfaRemind(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	if s.State != "enroll" {
		http.Error(w, "MFA required", 403)
		return
	}
	var passkeys int
	if err := a.DB.Row(r.Context(), "SELECT COUNT(*) FROM passkeys WHERE user_id=?", u.ID).Scan(&passkeys); err != nil {
		dbError(w, err)
		return
	}
	if u.TOTPSecret != "" || passkeys > 0 {
		http.Error(w, "MFA is now required; sign in again", 403)
		return
	}
	remind := int64(0)
	if r.FormValue("remind") != "" {
		remind = store.Now() + 30*24*3600
	}
	if _, err := a.DB.Exec(r.Context(), "UPDATE users SET remind_after=? WHERE id=?", remind, u.ID); err != nil {
		dbError(w, err)
		return
	}
	a.finishMFA(w, r, s)
}
func (a *App) finishMFA(w http.ResponseWriter, r *http.Request, s store.Session) {
	if _, err := a.DB.Exec(r.Context(), "UPDATE sessions SET state='full' WHERE id=?", s.ID); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/dashboard", 303)
}
func (a *App) settings(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	rows, err := a.DB.Query(r.Context(), "SELECT id FROM passkeys WHERE user_id=?", u.ID)
	if err != nil {
		dbError(w, err)
		return
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			keys = append(keys, id)
		}
	}
	a.render(w, "settings", map[string]any{"User": u, "CSRF": s.CSRF, "TOTP": u.TOTPSecret != "", "Pending": u.PendingTOTP != "", "Keys": keys})
}
func (a *App) changePassword(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(r.FormValue("current_password"))) != nil {
		http.Error(w, "current password is incorrect", 403)
		return
	}
	password := r.FormValue("new_password")
	if len(password) < 12 || len(password) > 72 {
		http.Error(w, "password must be 12-72 characters", 400)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	if _, err = a.DB.Exec(r.Context(), "UPDATE users SET password_hash=? WHERE id=?", string(hash), u.ID); err != nil {
		dbError(w, err)
		return
	}
	if _, err = a.DB.Exec(r.Context(), "DELETE FROM sessions WHERE user_id=? AND id<>?", u.ID, s.ID); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/settings", 303)
}
func (a *App) totpBegin(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	if u.TOTPSecret != "" {
		http.Error(w, "TOTP already enabled", 409)
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "snusnu", AccountName: u.Email})
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	enc, err := a.encrypt(key.Secret())
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	if _, err = a.DB.Exec(r.Context(), "UPDATE users SET pending_totp=? WHERE id=?", enc, u.ID); err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "totp", map[string]any{"User": u, "CSRF": s.CSRF, "Secret": key.Secret(), "URL": key.URL()})
}
func (a *App) totpFinish(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	if u.PendingTOTP == "" {
		http.Error(w, "start enrollment first", 400)
		return
	}
	secret, err := a.decrypt(u.PendingTOTP)
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	if !totp.Validate(strings.TrimSpace(r.FormValue("code")), secret) {
		http.Error(w, "invalid code", 400)
		return
	}
	if _, err = a.DB.Exec(r.Context(), "UPDATE users SET totp_secret=pending_totp,pending_totp='',remind_after=0 WHERE id=?", u.ID); err != nil {
		dbError(w, err)
		return
	}
	a.DB.Exec(r.Context(), "DELETE FROM sessions WHERE user_id=? AND id<>?", u.ID, s.ID)
	http.Redirect(w, r, "/settings", 303)
}
func (a *App) totpRemove(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	if u.TOTPSecret == "" {
		http.Error(w, "TOTP not enabled", 400)
		return
	}
	secret, err := a.decrypt(u.TOTPSecret)
	if err != nil || !totp.Validate(strings.TrimSpace(r.FormValue("code")), secret) {
		http.Error(w, "invalid code", 401)
		return
	}
	if _, err = a.DB.Exec(r.Context(), "UPDATE users SET totp_secret='' WHERE id=?", u.ID); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/settings", 303)
}

type webUser struct {
	store.User
	credentials []webauthn.Credential
}

func (u webUser) WebAuthnID() []byte                         { b, _ := hex.DecodeString(u.ID); return b }
func (u webUser) WebAuthnName() string                       { return u.Email }
func (u webUser) WebAuthnDisplayName() string                { return u.Email }
func (u webUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }
func (a *App) webUser(r *http.Request, u store.User) (webUser, error) {
	w := webUser{User: u}
	rows, err := a.DB.Query(r.Context(), "SELECT credential FROM passkeys WHERE user_id=?", u.ID)
	if err != nil {
		return w, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		var c webauthn.Credential
		if err = rows.Scan(&raw); err != nil {
			return w, err
		}
		if err = json.Unmarshal([]byte(raw), &c); err != nil {
			return w, err
		}
		w.credentials = append(w.credentials, c)
	}
	return w, rows.Err()
}
func (a *App) saveCeremony(r *http.Request, s store.Session, kind string, v *webauthn.SessionData) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = a.DB.Exec(r.Context(), "INSERT INTO ceremonies(session_id,kind,data,expires_at) VALUES(?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET kind=excluded.kind,data=excluded.data,expires_at=excluded.expires_at", s.ID, kind, string(b), store.Now()+300)
	return err
}
func (a *App) takeCeremony(r *http.Request, s store.Session, kind string) (webauthn.SessionData, error) {
	var raw string
	var expires int64
	var v webauthn.SessionData
	err := a.DB.Row(r.Context(), "DELETE FROM ceremonies WHERE session_id=? AND kind=? RETURNING data,expires_at", s.ID, kind).Scan(&raw, &expires)
	if err != nil {
		return v, err
	}
	if expires < store.Now() {
		return v, errors.New("ceremony expired")
	}
	err = json.Unmarshal([]byte(raw), &v)
	return v, err
}
func (a *App) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	wu, err := a.webUser(r, u)
	if err != nil {
		dbError(w, err)
		return
	}
	creation, session, err := a.webauthn.BeginRegistration(wu, webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred))
	if err != nil {
		http.Error(w, "passkey unavailable", 500)
		return
	}
	if err = a.saveCeremony(r, s, "register", session); err != nil {
		dbError(w, err)
		return
	}
	jsonResponse(w, creation)
}
func (a *App) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	wu, err := a.webUser(r, u)
	if err != nil {
		dbError(w, err)
		return
	}
	ceremony, err := a.takeCeremony(r, s, "register")
	if err != nil {
		http.Error(w, "ceremony expired", 400)
		return
	}
	c, err := a.webauthn.FinishRegistration(wu, ceremony, r)
	if err != nil {
		http.Error(w, "passkey registration failed", 400)
		return
	}
	b, err := json.Marshal(c)
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	id := hex.EncodeToString(c.ID)
	if _, err = a.DB.Exec(r.Context(), "INSERT INTO passkeys(id,user_id,credential) VALUES(?,?,?)", id, u.ID, string(b)); err != nil {
		dbError(w, err)
		return
	}
	a.DB.Exec(r.Context(), "DELETE FROM sessions WHERE user_id=? AND id<>?", u.ID, s.ID)
	w.WriteHeader(204)
}
func (a *App) passkeyLoginBegin(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	if s.State != "mfa" {
		http.Error(w, "MFA unavailable", 400)
		return
	}
	wu, err := a.webUser(r, u)
	if err != nil {
		dbError(w, err)
		return
	}
	if len(wu.credentials) == 0 {
		http.Error(w, "no passkey enrolled", 400)
		return
	}
	assertion, session, err := a.webauthn.BeginLogin(wu, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		http.Error(w, "passkey unavailable", 500)
		return
	}
	if err = a.saveCeremony(r, s, "login", session); err != nil {
		dbError(w, err)
		return
	}
	jsonResponse(w, assertion)
}
func (a *App) passkeyLoginFinish(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	if s.State != "mfa" {
		http.Error(w, "MFA unavailable", 400)
		return
	}
	wu, err := a.webUser(r, u)
	if err != nil {
		dbError(w, err)
		return
	}
	ceremony, err := a.takeCeremony(r, s, "login")
	if err != nil {
		http.Error(w, "ceremony expired", 400)
		return
	}
	c, err := a.webauthn.FinishLogin(wu, ceremony, r)
	if err != nil {
		http.Error(w, "passkey authentication failed", 401)
		return
	}
	b, err := json.Marshal(c)
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	if _, err = a.DB.Exec(r.Context(), "UPDATE passkeys SET credential=? WHERE id=? AND user_id=?", string(b), hex.EncodeToString(c.ID), u.ID); err != nil {
		dbError(w, err)
		return
	}
	if _, err = a.DB.Exec(r.Context(), "UPDATE sessions SET state='full' WHERE id=?", s.ID); err != nil {
		dbError(w, err)
		return
	}
	w.WriteHeader(204)
}
func (a *App) passkeyRemove(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	res, err := a.DB.Exec(r.Context(), "DELETE FROM passkeys WHERE id=? AND user_id=?", r.FormValue("id"), u.ID)
	if err != nil {
		dbError(w, err)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/settings", 303)
}

func (a *App) encrypt(secret string) (string, error) {
	block, err := aes.NewCipher(a.Config.MFAKey)
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(g.Seal(nonce, nonce, []byte(secret), nil)), nil
}
func (a *App) decrypt(encoded string) (string, error) {
	b, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(a.Config.MFAKey)
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(b) < g.NonceSize() {
		return "", errors.New("invalid encrypted secret")
	}
	plain, err := g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], nil)
	return string(plain), err
}
