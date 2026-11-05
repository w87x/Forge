package main

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var frontendFiles embed.FS

func frontend() http.Handler {
	assets, err := fs.Sub(frontendFiles, "dist")
	if err != nil {
		panic(err)
	}
	server := http.FileServer(http.FS(assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "." {
			name = "index.html"
		}
		if _, err := fs.Stat(assets, name); err != nil && !strings.Contains(path.Base(name), ".") {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			server.ServeHTTP(w, r2)
			return
		}
		server.ServeHTTP(w, r)
	})
}
