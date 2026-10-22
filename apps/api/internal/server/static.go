package server

import "net/http"

// demoHandler serves NAZR_DEMO_DIR under /demo/.
func demoHandler(dir string) http.Handler {
	return http.StripPrefix("/demo", http.FileServer(http.Dir(dir)))
}
