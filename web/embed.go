// Package web embeds the admin UI (plain HTML, CSS, JS; no build step).
package web

import "embed"

// Files of the admin UI.
//
//go:embed index.html app.js style.css
var Files embed.FS
