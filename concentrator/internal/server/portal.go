package server

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	wire "github.com/friedkiwi/snusnu/concentrator/internal/wire/routesv1"
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9_][a-z0-9_-]{2,31}$`)

func validRouterName(name string) bool {
	if name == "" || utf8.RuneCountInString(name) > 80 {
		return false
	}
	for _, c := range name {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func (a *App) routerForUser(w http.ResponseWriter, r *http.Request, u store.User) (store.Router, bool) {
	item, err := a.DB.RouterByID(r.Context(), r.PathValue("id"))
	if err != nil {
		dbError(w, err)
		return item, false
	}
	if item.OwnerID != u.ID && u.Role != "admin" {
		http.Error(w, "forbidden", 403)
		return item, false
	}
	return item, true
}
func (a *App) websocketURL() string {
	u, _ := url.Parse(a.Config.Origin)
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	u.Path = "/router/v1/ws"
	u.RawQuery = ""
	return u.String()
}
func (a *App) routerNewPage(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	a.render(w, "router_new", map[string]any{"User": u, "CSRF": s.CSRF})
}
func (a *App) routerCreate(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	if u.NetID == "" {
		http.Error(w, "set your user NETID in your profile before onboarding a router", http.StatusConflict)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if !validRouterName(name) {
		http.Error(w, "name must be 1-80 printable characters", 400)
		return
	}
	item, token, err := a.DB.CreateRouter(r.Context(), u.ID, name)
	if err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "router_token", map[string]any{"User": u, "CSRF": s.CSRF, "Router": item, "Token": token, "WebSocketURL": a.websocketURL(), "NetID": u.NetID})
}
func (a *App) routerDetails(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	item, ok := a.routerForUser(w, r, u)
	if !ok {
		return
	}
	exports, err := a.DB.ListRouterExports(r.Context(), item.ID)
	if err != nil {
		dbError(w, err)
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	logs, err := a.DB.SearchRouterLogs(r.Context(), item.ID, q)
	if err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "router_details", map[string]any{"User": u, "CSRF": s.CSRF, "Router": item, "Exports": exports, "Logs": logs, "Search": q, "WebSocketURL": a.websocketURL()})
}
func (a *App) routerRename(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	item, ok := a.routerForUser(w, r, u)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if !validRouterName(name) {
		http.Error(w, "invalid name", 400)
		return
	}
	if _, err := a.DB.Exec(r.Context(), "UPDATE routers SET display_name=? WHERE id=?", name, item.ID); err != nil {
		dbError(w, err)
		return
	}
	a.routerPolicyChanged(r.Context())
	http.Redirect(w, r, "/routers/"+item.ID, 303)
}
func (a *App) routerPause(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	item, ok := a.routerForUser(w, r, u)
	if !ok {
		return
	}
	paused := r.FormValue("paused") == "1"
	var err error
	if paused {
		err = a.revokeRouter(item.ID, func() error { return a.DB.SetRouterPaused(r.Context(), item.ID, true) })
	} else {
		err = a.DB.SetRouterPaused(r.Context(), item.ID, false)
	}
	if err != nil {
		dbError(w, err)
		return
	}
	if !paused {
		a.routerPolicyChanged(r.Context())
	}
	http.Redirect(w, r, "/routers/"+item.ID, 303)
}
func (a *App) routerRotate(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	item, ok := a.routerForUser(w, r, u)
	if !ok {
		return
	}
	var token string
	err := a.revokeRouter(item.ID, func() (err error) {
		token, err = a.DB.RotateRouterToken(r.Context(), item.ID)
		return err
	})
	if err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "router_token", map[string]any{"User": u, "CSRF": s.CSRF, "Router": item, "Token": token, "WebSocketURL": a.websocketURL(), "Rotated": true, "NetID": u.NetID})
}
func (a *App) routerDelete(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	item, ok := a.routerForUser(w, r, u)
	if !ok {
		return
	}
	if err := a.revokeRouter(item.ID, func() error { return a.DB.DeleteRouter(r.Context(), item.ID) }); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/dashboard", 303)
}
func (a *App) globalDirectory(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	exports, err := a.liveDirectoryExports(r.Context())
	if err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "global_directory", map[string]any{"User": u, "CSRF": s.CSRF, "Exports": exports})
}

func (a *App) liveDirectoryExports(ctx context.Context) ([]store.Export, error) {
	exports, err := a.DB.ListExports(ctx, "")
	if err != nil {
		return nil, err
	}
	if a.hub.local != nil {
		service := store.Export{RouterID: serviceRouterID, RouterName: "SNUSNU services", OwnerID: serviceOwnerID,
			OwnerUsername: "snusnu", NetID: "SNUSNU", Revision: 1, Generation: 1}
		for _, route := range a.hub.local.snapshot.Routes {
			entry := service
			entry.RouteID = int64(route.Id)
			switch resource := route.Resource.(type) {
			case *wire.RouteExport_ControlPoint:
				entry.Kind, entry.Name = "CP", resource.ControlPoint.Name
				if entry.Name == "SVC" {
					entry.ManagedMAC = (store.ManagedCP{Suffix: serviceMACSuffix}).MACColon()
					entry.ADPTADR = (store.ManagedCP{Suffix: serviceMACSuffix}).ADPTADR()
				}
			case *wire.RouteExport_LogicalUnit:
				entry.Kind, entry.Name = "LU", resource.LogicalUnit.Lu.Name
				entry.HostingCPNetID, entry.HostingCPName = resource.LogicalUnit.HostingCp.Netid, resource.LogicalUnit.HostingCp.Name
				for _, kind := range resource.LogicalUnit.SupportedTypes {
					entry.LUTypes = append(entry.LUTypes, localLUTypeLabel(kind))
				}
			default:
				continue
			}
			exports = append(exports, entry)
		}
	}
	return exports, nil
}
func (a *App) adminRouters(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	items, err := a.DB.ListRouters(r.Context(), "")
	if err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "admin_routers", map[string]any{"User": u, "CSRF": s.CSRF, "Routers": items})
}
func (a *App) flows(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	ownerID := u.ID
	if u.Role == "admin" {
		ownerID = ""
	}
	logs, err := a.DB.SearchFlows(r.Context(), ownerID, q)
	if err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "flows", map[string]any{"User": u, "CSRF": s.CSRF, "Logs": logs, "Search": q, "All": u.Role == "admin"})
}
func (a *App) blocks(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	items, err := a.DB.ListBlocks(r.Context(), u.ID)
	if err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "blocks", map[string]any{"User": u, "CSRF": s.CSRF, "Items": items})
}
func (a *App) adminBlocks(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	items, err := a.DB.ListBlocks(r.Context(), "")
	if err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "admin_blocks", map[string]any{"User": u, "CSRF": s.CSRF, "Items": items})
}
func (a *App) removeBlock(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	id := r.PathValue("id")
	if id == u.ID {
		http.Error(w, "cannot block yourself", 400)
		return
	}
	if err := a.setBlock(r.Context(), u.ID, id, false); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/blocks", 303)
}
func (a *App) profileEditPage(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	a.render(w, "profile_edit", map[string]any{"User": u, "CSRF": s.CSRF})
}
func (a *App) profileEdit(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	username := strings.ToLower(strings.TrimSpace(r.FormValue("username")))
	first := strings.TrimSpace(r.FormValue("first_name"))
	last := strings.TrimSpace(r.FormValue("last_name"))
	netid := strings.ToUpper(strings.TrimSpace(r.FormValue("netid")))
	if !usernamePattern.MatchString(username) || !store.ValidNetID(netid) || utf8.RuneCountInString(first) > 80 || utf8.RuneCountInString(last) > 80 {
		http.Error(w, "invalid profile fields", 400)
		return
	}
	for _, value := range []string{first, last} {
		for _, c := range value {
			if unicode.IsControl(c) {
				http.Error(w, "invalid name", 400)
				return
			}
		}
	}
	public := r.FormValue("public_email") == "1"
	update := func() error { return a.DB.UpdateProfile(r.Context(), u.ID, username, first, last, netid, public) }
	var err error
	if netid != u.NetID {
		err = a.revokeOwnerRouters(u.ID, update)
	} else {
		err = update()
	}
	if err != nil {
		http.Error(w, "username or NETID already taken, or profile is invalid", 409)
		return
	}
	if netid == u.NetID {
		a.routerPolicyChanged(r.Context())
	}
	http.Redirect(w, r, "/profiles/"+u.ID, 303)
}
func (a *App) profilePictureUpload(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	file, _, err := r.FormFile("picture")
	if err != nil {
		http.Error(w, "select an image", 400)
		return
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, 256*1024+1))
	if err != nil || len(b) > 256*1024 {
		http.Error(w, "image must be at most 256 KiB", 400)
		return
	}
	mime := http.DetectContentType(b)
	if mime != "image/png" && mime != "image/jpeg" {
		http.Error(w, "PNG or JPEG required", 400)
		return
	}
	config, _, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil || config.Width < 1 || config.Height < 1 || config.Width > 2048 || config.Height > 2048 {
		http.Error(w, "invalid image dimensions", 400)
		return
	}
	if _, err = a.DB.Exec(r.Context(), "UPDATE users SET picture=?,picture_type=? WHERE id=?", b, mime, u.ID); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/profile/edit", 303)
}
func (a *App) profilePictureDelete(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	if _, err := a.DB.Exec(r.Context(), "UPDATE users SET picture=NULL,picture_type='' WHERE id=?", u.ID); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/profile/edit", 303)
}
func (a *App) profileView(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	target, err := a.DB.UserByID(r.Context(), r.PathValue("id"))
	if err != nil {
		dbError(w, err)
		return
	}
	blocked, err := a.DB.IsBlocked(r.Context(), u.ID, target.ID)
	if err != nil {
		dbError(w, err)
		return
	}
	exports, err := a.DB.ListExports(r.Context(), target.ID)
	if err != nil {
		dbError(w, err)
		return
	}
	var picture int
	if err = a.DB.Row(r.Context(), "SELECT CASE WHEN picture IS NULL THEN 0 ELSE 1 END FROM users WHERE id=?", target.ID).Scan(&picture); err != nil {
		dbError(w, err)
		return
	}
	a.render(w, "profile_view", map[string]any{"User": u, "CSRF": s.CSRF, "Profile": target, "ShowEmail": target.PublicEmail || target.ID == u.ID || u.Role == "admin", "Own": target.ID == u.ID, "Blocked": blocked, "Exports": exports, "HasPicture": picture != 0})
}
func (a *App) profilePicture(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	var picture []byte
	var mime string
	err := a.DB.Row(r.Context(), "SELECT picture,picture_type FROM users WHERE id=?", r.PathValue("id")).Scan(&picture, &mime)
	if errors.Is(err, sql.ErrNoRows) || len(picture) == 0 {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		dbError(w, err)
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Write(picture)
}
func (a *App) profileBlock(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	id := r.PathValue("id")
	if id == u.ID {
		http.Error(w, "cannot block yourself", 400)
		return
	}
	if _, err := a.DB.UserByID(r.Context(), id); err != nil {
		dbError(w, err)
		return
	}
	if err := a.setBlock(r.Context(), u.ID, id, r.FormValue("blocked") == "1"); err != nil {
		dbError(w, err)
		return
	}
	http.Redirect(w, r, "/profiles/"+id, 303)
}
