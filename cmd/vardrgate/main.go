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
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	port, err := resolvePort()
	if err != nil {
		log.Error("invalid PORT", "error", err)
		os.Exit(1)
	}

	handler := api.New(log)
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: handler,
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
