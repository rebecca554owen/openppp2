package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg, err := LoadConfigFromArgs(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	daemon, err := NewDaemon(cfg)
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           daemon.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		_ = server.Close()
		daemon.Shutdown()
	}()

	log.Printf("daemon listening on %s", cfg.Listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
