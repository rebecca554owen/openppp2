package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	apiURL := flag.String("api", "http://127.0.0.1:18080", "guardian api base url")
	token := flag.String("token", "", "guardian jwt token")
	flag.Parse()

	client := &Client{
		BaseURL: *apiURL,
		Token:   *token,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}

	p := tea.NewProgram(newModel(client), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "guardian tui failed: %v\n", err)
		os.Exit(1)
	}
}
