package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

type Client struct {
	ID, Name             string
	CreatedAt, RevokedAt int64
}
type Entry struct{ ID, Site, MAC, SAP, Description, OwnerID string }
type Connection struct {
	ID, OwnerID, OwnerEmail, Name, RemoteSite, Status, Notes string
	CreatedAt                                                int64
}
type Account struct {
	ID, Email, Username, Role string
	VerifiedAt                int64
}

func (a *App) dashboard(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	routers, err := a.DB.ListRouters(r.Context(), u.ID)
	if err != nil {
		dbError(w, err)
		return
	}
	exports, err := a.DB.ListExports(r.Context(), u.ID)
	if err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "portal_dashboard", map[string]any{"User": u, "CSRF": s.CSRF, "Routers": routers, "Exports": exports})
}
func (a *App) clients(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	rows, err := a.DB.Query(r.Context(), "SELECT id,name,created_at,revoked_at FROM api_clients WHERE user_id=? ORDER BY created_at DESC", u.ID)
	if err != nil {
		dbError(w, err)
		return
	}
	defer rows.Close()
	var items []Client
	for rows.Next() {
		var c Client
		if err = rows.Scan(&c.ID, &c.Name, &c.CreatedAt, &c.RevokedAt); err != nil {
			dbError(w, err)
			return
		}
		items = append(items, c)
	}
	if err = rows.Err(); err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "clients", map[string]any{"User": u, "CSRF": s.CSRF, "Items": items})
}
func (a *App) createClient(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || len(name) > 80 {
		http.Error(w, "name must be 1-80 characters", 400)
		return
	}
	id, err := store.Random()
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	secret, err := store.Random()
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	if _, err = a.DB.Exec(r.Context(), "INSERT INTO api_clients(id,user_id,name,secret_hash,created_at) VALUES(?,?,?,?,?)", id, u.ID, name, store.Hash(secret), store.Now()); err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "client_created", map[string]any{"User": u, "CSRF": s.CSRF, "Name": name, "Secret": secret})
}
func (a *App) revokeClient(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	if _, err := a.DB.Exec(r.Context(), "UPDATE api_clients SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at=0", store.Now(), r.FormValue("id"), u.ID); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/clients", 303)
}
func (a *App) directoryItems(r *http.Request) ([]Entry, error) {
	rows, err := a.DB.Query(r.Context(), "SELECT id,site,mac,sap,description,COALESCE(owner_id,'') FROM directory ORDER BY site,mac,sap")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Entry
	for rows.Next() {
		var x Entry
		if err = rows.Scan(&x.ID, &x.Site, &x.MAC, &x.SAP, &x.Description, &x.OwnerID); err != nil {
			return nil, err
		}
		items = append(items, x)
	}
	return items, rows.Err()
}
func (a *App) directory(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	items, err := a.directoryItems(r)
	if err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "directory", map[string]any{"User": u, "CSRF": s.CSRF, "Items": items})
}
func (a *App) createDirectory(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	site := strings.TrimSpace(r.FormValue("site"))
	mac := strings.ToUpper(strings.TrimSpace(r.FormValue("mac")))
	sap := strings.ToUpper(strings.TrimSpace(r.FormValue("sap")))
	description := strings.TrimSpace(r.FormValue("description"))
	if site == "" || len(site) > 64 || mac == "" || len(mac) > 32 || sap == "" || len(sap) > 8 || len(description) > 250 {
		http.Error(w, "invalid directory entry", 400)
		return
	}
	id, err := store.Random()
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	if _, err = a.DB.Exec(r.Context(), "INSERT INTO directory(id,site,mac,sap,description) VALUES(?,?,?,?,?)", id, site, mac, sap, description); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/planning-directory", 303)
}
func (a *App) deleteDirectory(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	if _, err := a.DB.Exec(r.Context(), "DELETE FROM directory WHERE id=?", r.FormValue("id")); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/planning-directory", 303)
}
func (a *App) updateDirectory(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	site := strings.TrimSpace(r.FormValue("site"))
	mac := strings.ToUpper(strings.TrimSpace(r.FormValue("mac")))
	sap := strings.ToUpper(strings.TrimSpace(r.FormValue("sap")))
	description := strings.TrimSpace(r.FormValue("description"))
	if site == "" || len(site) > 64 || mac == "" || len(mac) > 32 || sap == "" || len(sap) > 8 || len(description) > 250 {
		http.Error(w, "invalid directory entry", 400)
		return
	}
	if _, err := a.DB.Exec(r.Context(), "UPDATE directory SET site=?,mac=?,sap=?,description=? WHERE id=?", site, mac, sap, description, r.FormValue("id")); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/planning-directory", 303)
}
func (a *App) connectionItems(r *http.Request, u store.User) ([]Connection, error) {
	query := "SELECT c.id,c.owner_id,u.email,c.name,c.remote_site,c.status,c.notes,c.created_at FROM connections c JOIN users u ON u.id=c.owner_id"
	args := []any{}
	if u.Role != "admin" {
		query += " WHERE c.owner_id=?"
		args = append(args, u.ID)
	}
	query += " ORDER BY c.created_at DESC"
	rows, err := a.DB.Query(r.Context(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Connection
	for rows.Next() {
		var x Connection
		if err = rows.Scan(&x.ID, &x.OwnerID, &x.OwnerEmail, &x.Name, &x.RemoteSite, &x.Status, &x.Notes, &x.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, x)
	}
	return items, rows.Err()
}
func (a *App) connections(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	items, err := a.connectionItems(r, u)
	if err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "connections", map[string]any{"User": u, "CSRF": s.CSRF, "Items": items})
}
func (a *App) createConnection(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	owner := r.FormValue("owner_id")
	name := strings.TrimSpace(r.FormValue("name"))
	remote := strings.TrimSpace(r.FormValue("remote_site"))
	notes := strings.TrimSpace(r.FormValue("notes"))
	if name == "" || len(name) > 100 || remote == "" || len(remote) > 64 || len(notes) > 500 {
		http.Error(w, "invalid connection", 400)
		return
	}
	if _, err := a.DB.UserByID(r.Context(), owner); err != nil {
		http.Error(w, "unknown owner", 400)
		return
	}
	id, err := store.Random()
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	if _, err = a.DB.Exec(r.Context(), "INSERT INTO connections(id,owner_id,name,remote_site,notes,created_at) VALUES(?,?,?,?,?,?)", id, owner, name, remote, notes, store.Now()); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/connections", 303)
}
func (a *App) deleteConnection(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	if _, err := a.DB.Exec(r.Context(), "DELETE FROM connections WHERE id=?", r.FormValue("id")); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/connections", 303)
}
func (a *App) updateConnection(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	owner := r.FormValue("owner_id")
	name := strings.TrimSpace(r.FormValue("name"))
	remote := strings.TrimSpace(r.FormValue("remote_site"))
	notes := strings.TrimSpace(r.FormValue("notes"))
	if name == "" || len(name) > 100 || remote == "" || len(remote) > 64 || len(notes) > 500 {
		http.Error(w, "invalid connection", 400)
		return
	}
	if _, err := a.DB.UserByID(r.Context(), owner); err != nil {
		http.Error(w, "unknown owner", 400)
		return
	}
	if _, err := a.DB.Exec(r.Context(), "UPDATE connections SET owner_id=?,name=?,remote_site=?,notes=? WHERE id=?", owner, name, remote, notes, r.FormValue("id")); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/connections", 303)
}
func (a *App) users(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > 100 {
		q = q[:100]
	}
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}
	if page > 10000 {
		page = 10000
	}
	filter := "%" + strings.ToLower(q) + "%"
	rows, err := a.DB.Query(r.Context(), "SELECT id,email,username,role,verified_at FROM users WHERE LOWER(email) LIKE ? OR LOWER(username) LIKE ? ORDER BY email,id LIMIT 26 OFFSET ?", filter, filter, (page-1)*25)
	if err != nil {
		dbError(w, err)
		return
	}
	defer rows.Close()
	var items []Account
	for rows.Next() {
		var x Account
		if err = rows.Scan(&x.ID, &x.Email, &x.Username, &x.Role, &x.VerifiedAt); err != nil {
			dbError(w, err)
			return
		}
		items = append(items, x)
	}
	if err = rows.Err(); err != nil {
		dbError(w, err)
		return
	}
	hasNext := len(items) > 25
	if hasNext {
		items = items[:25]
	}
	a.render(w, "users", map[string]any{"User": u, "CSRF": s.CSRF, "Items": items, "Search": q, "Page": page, "PrevPage": page - 1, "NextPage": page + 1, "HasPrev": page > 1, "HasNext": hasNext})
}
func (a *App) setRole(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	id := r.FormValue("id")
	role := r.FormValue("role")
	if role != "admin" && role != "user" {
		http.Error(w, "invalid role", 400)
		return
	}
	if id == u.ID && role != "admin" {
		http.Error(w, "cannot demote yourself", 400)
		return
	}
	if _, err := a.DB.Exec(r.Context(), "UPDATE users SET role=? WHERE id=?", role, id); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/admin/users", 303)
}
func (a *App) apiDirectory(w http.ResponseWriter, r *http.Request, u store.User) {
	items, err := a.DB.ListExports(r.Context(), "")
	if err != nil {
		dbError(w, err)
		return
	}
	jsonResponse(w, items)
}
func (a *App) apiConnections(w http.ResponseWriter, r *http.Request, u store.User) {
	items, err := a.connectionItems(r, u)
	if err != nil {
		dbError(w, err)
		return
	}
	jsonResponse(w, items)
}
