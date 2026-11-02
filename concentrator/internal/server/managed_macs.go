package server

import (
	"net/http"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

func (a *App) adminManagedCPPage(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	items, err := a.DB.ListManagedCP(r.Context(), "")
	if err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "managed_cp", map[string]any{"User": u, "CSRF": s.CSRF, "Items": items})
}
func (a *App) routerLLCFacing(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	item, ok := a.routerForUser(w, r, u)
	if !ok {
		return
	}
	enabled := r.FormValue("enabled") == "1"
	update := func() error { return a.DB.SetRouterLLCFacing(r.Context(), item.ID, enabled) }
	var err error
	if !enabled && item.LLCFacing {
		err = a.revokeRouter(item.ID, update)
	} else {
		err = update()
	}
	if err != nil {
		dbError(w, err)
		return
	}
	if enabled || !item.LLCFacing {
		a.routerPolicyChanged(r.Context())
	}
	http.Redirect(w, r, "/routers/"+item.ID, 303)
}
