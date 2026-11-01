package server

import (
	"database/sql"
	"net"
	"net/http"
	"strings"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

func loginKeys(r *http.Request, email string) []string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	host = strings.TrimSpace(host)
	return []string{store.Hash("login-ip:" + host), store.Hash("login-email:" + email)}
}
func (a *App) allowed(r *http.Request, keys []string, limit int) bool {
	for _, key := range keys {
		var count int
		var reset int64
		err := a.DB.Row(r.Context(), "SELECT count,reset_at FROM auth_attempts WHERE id=?", key).Scan(&count, &reset)
		if err != nil && err != sql.ErrNoRows {
			return false
		}
		if err == nil && reset > store.Now() && count >= limit {
			return false
		}
	}
	return true
}
func (a *App) failed(r *http.Request, keys []string) error {
	now := store.Now()
	for _, key := range keys {
		if _, err := a.DB.Exec(r.Context(), "INSERT INTO auth_attempts(id,count,reset_at) VALUES(?,1,?) ON CONFLICT(id) DO UPDATE SET count=CASE WHEN auth_attempts.reset_at<? THEN 1 ELSE auth_attempts.count+1 END,reset_at=CASE WHEN auth_attempts.reset_at<? THEN ? ELSE auth_attempts.reset_at END", key, now+900, now, now, now+900); err != nil {
			return err
		}
	}
	return nil
}
func (a *App) clearFailures(r *http.Request, keys []string) {
	for _, key := range keys {
		a.DB.Exec(r.Context(), "DELETE FROM auth_attempts WHERE id=?", key)
	}
}
