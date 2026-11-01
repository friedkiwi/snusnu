package server

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func (a *App) passwordResetPage(w http.ResponseWriter, r *http.Request) {
	a.render(w, "password_reset", map[string]any{"Email": r.URL.Query().Get("email"), "Requested": r.URL.Query().Get("requested") == "1", "CaptchaKey": a.Config.CaptchaSiteKey})
}

func (a *App) passwordResetRequest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	if !a.captcha(w, r) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if len(email) > 254 || !strings.Contains(email, "@") {
		http.Error(w, "invalid email", 400)
		return
	}
	keys := []string{store.Hash("password-reset-email:" + email), store.Hash("password-reset-ip:" + loginKeys(r, "")[0])}
	if !a.allowed(r, keys, 3) {
		http.Error(w, "too many requests; try later", 429)
		return
	}
	if err := a.failed(r, keys); err != nil {
		dbError(w, err)
		return
	}
	u, err := a.DB.UserByEmail(r.Context(), email)
	if err == nil && u.VerifiedAt != 0 {
		code, err := verificationCode()
		if err != nil {
			dbError(w, err)
			return
		}
		if err = a.DB.IssuePasswordReset(r.Context(), u.ID, code); err != nil {
			dbError(w, err)
			return
		}
		if err = a.sendEmailCode(email, code, "password reset"); err != nil {
			log.Printf("password reset delivery failed for %s: %v", email, err)
		}
	}
	http.Redirect(w, r, "/password-reset?requested=1&email="+url.QueryEscape(email), 303)
}

func (a *App) passwordResetComplete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	code := r.FormValue("code")
	password := r.FormValue("new_password")
	if len(code) != 6 || len(password) < 12 || len(password) > 72 {
		http.Error(w, "invalid code or password", 400)
		return
	}
	u, err := a.DB.UserByEmail(r.Context(), email)
	if err != nil || u.VerifiedAt == 0 {
		http.Error(w, "invalid or expired code", 400)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		dbError(w, err)
		return
	}
	if err = a.DB.CompletePasswordReset(r.Context(), u.ID, code, string(hash)); err != nil {
		if errors.Is(err, store.ErrInvalidResetCode) {
			http.Error(w, "invalid or expired code", 400)
		} else {
			dbError(w, err)
		}
		return
	}
	a.clearSession(w)
	http.Redirect(w, r, "/login", 303)
}

func (a *App) adminResetPassword(w http.ResponseWriter, r *http.Request, admin store.User, session store.Session) {
	id := r.FormValue("id")
	if _, err := a.DB.UserByID(r.Context(), id); err != nil {
		http.Error(w, "unknown user", 404)
		return
	}
	random, err := store.Random()
	if err != nil {
		dbError(w, err)
		return
	}
	temporary := random[:24]
	hash, err := bcrypt.GenerateFromPassword([]byte(temporary), bcrypt.DefaultCost)
	if err != nil {
		dbError(w, err)
		return
	}
	if err = a.DB.AdminResetPassword(r.Context(), id, string(hash)); err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "admin_password_reset", map[string]any{"User": admin, "CSRF": session.CSRF, "Temporary": temporary, "TargetID": id})
}
