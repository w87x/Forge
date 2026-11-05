package main

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"forge/internal/auth"
	"forge/internal/httpapi"
	"forge/internal/inspection"
	"forge/internal/inventory"
	"forge/internal/jobs"
	"forge/internal/netbox"
	"forge/internal/profiles"
	"forge/internal/redfish"
	"forge/internal/secrets"
	"forge/internal/simulation"
	"forge/internal/store/sqlite"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	addr := os.Getenv("FORGE_LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		logger.Error("invalid listen address", "error", err)
		os.Exit(1)
	}
	databasePath := os.Getenv("FORGE_DATABASE_PATH")
	simulated := os.Getenv("FORGE_SIMULATION") == "true"
	if databasePath == "" {
		databasePath = "data/forge.db"
		if simulated {
			databasePath = "data/simulation/forge.db"
		}
	}
	if err := os.MkdirAll(filepath.Dir(databasePath), 0700); err != nil {
		logger.Error("create database directory", "error", err)
		os.Exit(1)
	}
	lock, err := jobs.LockExecutor(databasePath + ".executor.lock")
	if err != nil {
		logger.Error("acquire executor lock", "error", err)
		os.Exit(1)
	}
	defer lock.Close()
	store, err := sqlite.Open(context.Background(), databasePath)
	if err != nil {
		logger.Error("open database", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	if err := simulation.EnsureMode(context.Background(), store.DB, simulated); err != nil {
		logger.Error("database mode", "error", err)
		os.Exit(1)
	}
	vault, err := secrets.New(store.DB, os.Getenv("FORGE_ENCRYPTION_KEY"))
	if err != nil {
		logger.Error("invalid encryption key", "error", err)
		os.Exit(1)
	}
	bootstrapToken := os.Getenv("FORGE_BOOTSTRAP_TOKEN")
	if bootstrapToken != "" && len(bootstrapToken) < 32 {
		logger.Error("FORGE_BOOTSTRAP_TOKEN must be at least 32 characters")
		os.Exit(1)
	}
	authentication := &auth.Service{DB: store.DB, BootstrapToken: bootstrapToken}
	secureCookies := os.Getenv("FORGE_DEV_INSECURE_HTTP") != "true"
	if !secureCookies {
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			logger.Error("insecure development cookies require a loopback listen address")
			os.Exit(1)
		}
		logger.Warn("insecure HTTP cookies enabled for local development")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	jobStore := &jobs.Store{DB: store.DB}
	netboxService := &netbox.Service{DB: store.DB, Auth: authentication, Vault: vault, AllowHTTP: os.Getenv("FORGE_ALLOW_NETBOX_HTTP") == "true", AllowedHosts: strings.Split(os.Getenv("FORGE_NETBOX_ALLOWED_HOSTS"), ","), ConnectionsEnabled: !simulated}
	inventoryService := &inventory.Service{DB: store.DB, NetBox: netboxService}
	profileService := &profiles.Service{DB: store.DB, Auth: authentication, Vault: vault}
	var allowedBMC []netip.Prefix
	for _, value := range strings.Split(os.Getenv("FORGE_BMC_ALLOWED_CIDRS"), ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			logger.Error("invalid BMC allowed network")
			os.Exit(1)
		}
		allowedBMC = append(allowedBMC, prefix.Masked())
	}
	var roots *x509.CertPool
	if caPath := os.Getenv("FORGE_BMC_CA_FILE"); caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			logger.Error("read BMC CA file", "error", err)
			os.Exit(1)
		}
		roots, err = x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			logger.Error("BMC CA file contains no certificates")
			os.Exit(1)
		}
	}
	redfishClient := &redfish.Client{Allowed: allowedBMC, Roots: roots}
	inspectionService := &inspection.Service{DB: store.DB, Auth: authentication, Inventory: inventoryService, NetBox: netboxService, Profiles: profileService, Vault: vault, Jobs: jobStore, Redfish: redfishClient, Enabled: !simulated}
	var workers sync.WaitGroup
	if simulated {
		workers.Add(1)
		go func() { defer workers.Done(); simulation.Run(ctx, jobStore, logger) }()
	}
	if !simulated {
		workers.Add(1)
		go func() { defer workers.Done(); inspectionService.Run(ctx, logger) }()
	}
	srv := &http.Server{Addr: addr, Handler: httpapi.Handler(logger, frontend(), authentication, vault, jobStore, netboxService, inventoryService, profileService, inspectionService, simulated, secureCookies), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("server shutdown", "error", err)
		}
	}()
	logger.Info("starting Forge", "address", addr)
	err = srv.ListenAndServe()
	stop()
	workers.Wait()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}
