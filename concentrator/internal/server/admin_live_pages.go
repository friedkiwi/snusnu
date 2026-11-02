package server

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

type livePage[T any] struct {
	Items            []T
	Search           string
	Number, Pages    int
	PageSize, Total  int
	PrevURL, NextURL string
}

func liveSearch(r *http.Request, key string) string {
	q := strings.TrimSpace(r.URL.Query().Get(key))
	if len(q) > 128 {
		q = q[:128]
	}
	return q
}

func paginateLive[T any](r *http.Request, items []T, search, pageKey, sizeKey string) livePage[T] {
	size, _ := strconv.Atoi(r.URL.Query().Get(sizeKey))
	if size != 25 && size != 50 && size != 100 && size != 200 {
		size = 25
	}
	pages := (len(items) + size - 1) / size
	if pages == 0 {
		pages = 1
	}
	number, _ := strconv.Atoi(r.URL.Query().Get(pageKey))
	if number < 1 {
		number = 1
	}
	if number > pages {
		number = pages
	}
	start := (number - 1) * size
	end := start + size
	if end > len(items) {
		end = len(items)
	}
	page := livePage[T]{Items: items[start:end], Search: search, Number: number, Pages: pages, PageSize: size, Total: len(items)}
	pageURL := func(n int) string {
		values := r.URL.Query()
		values.Set(pageKey, strconv.Itoa(n))
		values.Set(sizeKey, strconv.Itoa(size))
		return "?" + values.Encode()
	}
	if number > 1 {
		page.PrevURL = pageURL(number - 1)
	}
	if number < pages {
		page.NextURL = pageURL(number + 1)
	}
	return page
}

func (a *App) adminRouterSessionsPage(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	search := liveSearch(r, "q")
	items := a.hub.adminRouterSessions()
	if search != "" {
		filtered := items[:0]
		needle := strings.ToLower(search)
		for _, item := range items {
			if strings.Contains(strings.ToLower(strings.Join([]string{item.ID, item.Name, item.IP, item.Protocol, item.Epoch}, " ")), needle) {
				filtered = append(filtered, item)
			}
		}
		items = filtered
	}
	page := paginateLive(r, items, search, "page", "page_size")
	a.render(w, "admin_router_sessions", map[string]any{"User": u, "CSRF": s.CSRF, "Page": page})
}

func activeCircuitPage(r *http.Request, items []circuitView) livePage[circuitView] {
	search := liveSearch(r, "active_q")
	if search != "" {
		filtered := items[:0]
		needle := strings.ToLower(search)
		for _, item := range items {
			if strings.Contains(strings.ToLower(strings.Join([]string{item.ID, item.SourceRouterID, item.SourceRouterName, item.SourceOwnerID, item.TargetRouterID, item.TargetRouterName, item.TargetOwnerID, item.State, item.Profile}, " ")), needle) {
				filtered = append(filtered, item)
			}
		}
		items = filtered
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].OpenedAt == items[j].OpenedAt {
			return items[i].ID > items[j].ID
		}
		return items[i].OpenedAt > items[j].OpenedAt
	})
	return paginateLive(r, items, search, "active_page", "active_size")
}
