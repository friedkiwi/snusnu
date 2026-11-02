package server

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func (a *App) deleteOwnAccountPage(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	a.render(w, "delete_account", map[string]any{"User": u, "CSRF": s.CSRF})
}
func (a *App) deleteOwnAccount(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	if r.FormValue("confirm") != "DELETE" || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(r.FormValue("password"))) != nil {
		http.Error(w, "confirmation or password is incorrect", 403)
		return
	}
	if err := a.DB.DeleteUser(r.Context(), u.ID); err != nil {
		accountDeleteError(w, err)
		return
	}
	a.closeDeletedUserRouters()
	a.clearSession(w)
	http.Redirect(w, r, "/login", 303)
}
func (a *App) adminDeleteUserPage(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	target, err := a.DB.UserByID(r.Context(), r.PathValue("id"))
	if err != nil {
		dbError(w, err)
		return
	}
	if target.ID == u.ID {
		http.Redirect(w, r, "/settings/delete", 303)
		return
	}
	a.render(w, "admin_delete_user", map[string]any{"User": u, "CSRF": s.CSRF, "Target": target})
}
func (a *App) adminDeleteUser(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	id := r.PathValue("id")
	if id == u.ID {
		http.Error(w, "delete your own account from Settings", 400)
		return
	}
	if r.FormValue("confirm") != "DELETE" || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(r.FormValue("password"))) != nil {
		http.Error(w, "confirmation or password is incorrect", 403)
		return
	}
	if err := a.DB.DeleteUser(r.Context(), id); err != nil {
		accountDeleteError(w, err)
		return
	}
	a.closeDeletedUserRouters()
	http.Redirect(w, r, "/admin/users", 303)
}
func (a *App) closeDeletedUserRouters() {
	if err := a.hub.refreshPolicyAndRoutes(context.Background()); err != nil {
		log.Printf("refresh router policy after account deletion: %v", err)
	}
}
func accountDeleteError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrLastAdmin) {
		http.Error(w, "cannot delete the last admin account", 409)
		return
	}
	dbError(w, err)
}
