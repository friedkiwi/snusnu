package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	"github.com/friedkiwi/snusnu/sna/services/printer"
)

func (a *App) printJobs(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > 80 {
		http.Error(w, "search is too long", http.StatusBadRequest)
		return
	}
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}
	if page > 40000 {
		http.Error(w, "page is too large", http.StatusBadRequest)
		return
	}
	items, err := a.DB.ListPrintJobs(r.Context(), u.ID, q, 26, (page-1)*25)
	if err != nil {
		dbError(w, err)
		return
	}
	hasNext := len(items) > 25
	if hasNext {
		items = items[:25]
	}
	a.render(w, "print_jobs", map[string]any{"User": u, "CSRF": s.CSRF, "Items": items, "Search": q, "Page": page, "HasPrev": page > 1, "PrevPage": page - 1, "HasNext": hasNext, "NextPage": page + 1})
}

func (a *App) printJob(w http.ResponseWriter, r *http.Request, u store.User, s store.Session) {
	job, raw, err := a.readPrintJob(r.Context(), u.ID, r.PathValue("id"))
	if err != nil {
		printReadError(w, err)
		return
	}
	pages, err := printer.RenderSCS(raw)
	if err != nil {
		http.Error(w, "print data cannot be rendered", http.StatusInternalServerError)
		return
	}
	lines := make([][]string, len(pages))
	for i, page := range pages {
		lines[i] = page.Lines()
	}
	a.render(w, "print_job", map[string]any{"User": u, "CSRF": s.CSRF, "Job": job, "Pages": lines})
}

func (a *App) printJobPDF(w http.ResponseWriter, r *http.Request, u store.User, _ store.Session) {
	job, raw, err := a.readPrintJob(r.Context(), u.ID, r.PathValue("id"))
	if err != nil {
		printReadError(w, err)
		return
	}
	pages, err := printer.RenderSCS(raw)
	if err != nil {
		http.Error(w, "print data cannot be rendered", http.StatusInternalServerError)
		return
	}
	pdf, err := renderGreenbarPDF(pages)
	if err != nil {
		http.Error(w, "print data cannot be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+job.ID+".pdf\"")
	w.Write(pdf)
}

func printReadError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, nil)
		return
	}
	http.Error(w, "print data unavailable", http.StatusInternalServerError)
}
