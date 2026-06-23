package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/VardrSec/vardrgate/internal/api"
	"github.com/VardrSec/vardrgate/internal/client"
	"github.com/VardrSec/vardrgate/internal/engine"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	port, err := resolvePort()
	if err != nil {
		log.Error("invalid PORT", "error", err)
		os.Exit(1)
	}

	allowPrivate, err := resolveAllowPrivateTargets()
	if err != nil {
		log.Error("invalid ALLOW_PRIVATE_TARGETS", "error", err)
		os.Exit(1)
	}
	if allowPrivate {
		log.Warn("ALLOW_PRIVATE_TARGETS is enabled; loopback and private-network targets are permitted")
	}

	c := client.NewWithConfig(nil, client.Config{AllowPrivateTargets: allowPrivate})
	eng := engine.New(c)
	handler := api.New(log, eng)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Info("server starting", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	stop()
	log.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown error", "error", err)
		os.Exit(1)
	}

	log.Info("server stopped")
}

func resolvePort() (int, error) {
	raw := os.Getenv("PORT")
	if raw == "" {
		return 8080, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("PORT must be an integer between 1 and 65535, got %q", raw)
	}
	return n, nil
}

func resolveAllowPrivateTargets() (bool, error) {
	raw := os.Getenv("ALLOW_PRIVATE_TARGETS")
	if raw == "" {
		return false, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("ALLOW_PRIVATE_TARGETS must be true or false, got %q", raw)
	}
	return v, nil
}
