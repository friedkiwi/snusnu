package server

import (
	"net/http"
	"strings"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

func (a *App) managedCPPage(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	items, err := a.DB.ListManagedCP(r.Context(), u.ID)
	if err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "managed_cp", map[string]any{"User": u, "CSRF": s.CSRF, "Items": items})
}
func (a *App) adminManagedCPPage(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	items, err := a.DB.ListManagedCP(r.Context(), "")
	if err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "managed_cp", map[string]any{"User": u, "CSRF": s.CSRF, "Items": items, "All": true})
}
func (a *App) managedCPCreate(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	owner := u.ID
	netid := u.NetID
	if u.Role == "admin" && r.FormValue("owner_id") != "" {
		owner = r.FormValue("owner_id")
		target, err := a.DB.UserByID(r.Context(), owner)
		if err != nil {
			dbError(w, err)
			return
		}
		netid = target.NetID
	}
	if !store.ValidNetID(netid) {
		http.Error(w, "set a valid NETID in the owner profile first", http.StatusConflict)
		return
	}
	name := strings.ToUpper(strings.TrimSpace(r.FormValue("cp_name")))
	_, err := a.DB.AllocateManagedCP(r.Context(), owner, netid, name)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	http.Redirect(w, r, "/llc-macs", 303)
}
func (a *App) managedCPForUser(w http.ResponseWriter, r *http.Request, u store.User) (store.ManagedCP, bool) {
	cp, err := a.DB.ManagedCPByID(r.Context(), r.PathValue("id"))
	if err != nil {
		dbError(w, err)
		return cp, false
	}
	if cp.OwnerID != u.ID && u.Role != "admin" {
		http.Error(w, "forbidden", 403)
		return cp, false
	}
	return cp, true
}
func (a *App) managedCPEnabled(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	cp, ok := a.managedCPForUser(w, r, u)
	if !ok {
		return
	}
	if err := a.DB.SetManagedCPEnabled(r.Context(), cp.ID, cp.OwnerID, r.FormValue("enabled") == "1"); err != nil {
		dbError(w, err)
		return
	}
	if u.Role == "admin" && cp.OwnerID != u.ID {
		http.Redirect(w, r, "/admin/llc-macs", 303)
	} else {
		http.Redirect(w, r, "/llc-macs", 303)
	}
}
func (a *App) managedCPRetire(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	cp, ok := a.managedCPForUser(w, r, u)
	if !ok {
		return
	}
	if err := a.DB.RetireManagedCP(r.Context(), cp.ID, cp.OwnerID); err != nil {
		dbError(w, err)
		return
	}
	if u.Role == "admin" && cp.OwnerID != u.ID {
		http.Redirect(w, r, "/admin/llc-macs", 303)
	} else {
		http.Redirect(w, r, "/llc-macs", 303)
	}
}
func (a *App) routerLLCFacing(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	item, ok := a.routerForUser(w, r, u)
	if !ok {
		return
	}
	if err := a.DB.SetRouterLLCFacing(r.Context(), item.ID, r.FormValue("enabled") == "1"); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/routers/"+item.ID, 303)
}
