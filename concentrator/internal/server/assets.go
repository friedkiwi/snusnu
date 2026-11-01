package server

import (
	"embed"
	"net/http"
)

//go:embed assets/*
var assets embed.FS

func assetHandler() http.Handler {
	return http.FileServer(http.FS(assets))
}
