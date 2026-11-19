// Package iam embeds the self-service console.
package iam

import "embed"

//go:embed web
var Web embed.FS
