package main

import "embed"

//go:embed webui/dist/*
var webuiFS embed.FS
