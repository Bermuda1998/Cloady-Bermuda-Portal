package main

import (
	"context"
	"errors"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultPort               = "8080"
	compatCloadyDefaultPort   = "3000"
	compatHttpPort            = "80"
	fallbackSelfMemMB         = 128
	fallbackWorkerMemMB       = 550
	defaultGOMAXPROCS         = 2
	gatewayMemPercent         = 14
	workerMemPercent          = 54
	httpDrainTimeout          = 8 * time.Second
	edgeKeepAlivePeriod       = 15 * time.Second
	drainPropagationWindow    = 450 * time.Millisecond
	startupOrchestrationDelay = 3 * time.Second
	dnsPropagationSettleDelay = 4 * time.Second
	tcpUserTimeoutOpt         = 18
)

func cgroupMemoryLimit() (uint64, bool) {
	candidates := []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(data))
		if s == "" || s == "max" {
			continue
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil || n == 0 || n >= 1<<50 {
			continue
		}
		return n, true
	}
	return 0, false
}

func deriveMemoryBudget() (gwMB, workerMB int) {
	gwMB, workerMB = fallbackSelfMemMB, fallbackWorkerMemMB
	limit, limited := cgroupMemoryLimit()
	if limited {
		totalMB := int(limit >> 20)
		gwMB = totalMB * gatewayMemPercent / 100
		workerMB = totalMB * workerMemPercent / 100

		allowedMB := totalMB * 68 / 100
		if gwMB < 48 {
			gwMB = 48
		}
		if workerMB < 64 {
			workerMB = 64
		}
		if total := gwMB + workerMB; total > allowedMB && allowedMB >= 112 {
			gwMB = allowedMB * gatewayMemPercent / 68
			workerMB = allowedMB * workerMemPercent / 68
		}
	}

	gwMB = getEnvInt("BERMUDA_SELF_MEM_MB", gwMB)
	workerMB = getEnvInt("BERMUDA_WORKER_MEM_MB", getEnvInt("BERMUDA_XRAY_MEM_MB", workerMB))
	return gwMB, workerMB
}

func applyMemoryCeiling(selfMB int) {
	if selfMB < 48 {
		selfMB = 48
	}
	debug.SetMemoryLimit(int64(selfMB) << 20)
	debug.SetGCPercent(100)
}

func cgroupCPUQuota() (float64, bool) {
	if data, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		f := strings.Fields(string(data))
		if len(f) == 2 && f[0] != "max" {
			q, e1 := strconv.ParseFloat(f[0], 64)
			p, e2 := strconv.ParseFloat(f[1], 64)
			if e1 == nil && e2 == nil && q > 0 && p > 0 {
				return q / p, true
			}
		}
	}
	qb, e1 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	pb, e2 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if e1 == nil && e2 == nil {
		q, e3 := strconv.ParseFloat(strings.TrimSpace(string(qb)), 64)
		p, e4 := strconv.ParseFloat(strings.TrimSpace(string(pb)), 64)
		if e3 == nil && e4 == nil && q > 0 && p > 0 {
			return q / p, true
		}
	}
	return 0, false
}

func applyGOMAXPROCS() (gwProcs, workerProcs int) {
	explicitGW := getEnvInt("BERMUDA_GOMAXPROCS", 0)
	explicitWorker := getEnvInt("BERMUDA_WORKER_GOMAXPROCS", getEnvInt("BERMUDA_XRAY_GOMAXPROCS", 0))

	if explicitGW > 0 {
		gwProcs = explicitGW
	} else if q, ok := cgroupCPUQuota(); ok {
		if q <= 0.55 {
			gwProcs = 1
		} else {
			gwProcs = int(math.Ceil(q))
		}
	} else {
		gwProcs = defaultGOMAXPROCS
	}

	if explicitWorker > 0 {
		workerProcs = explicitWorker
	} else if explicitGW > 0 {
		workerProcs = explicitGW
	} else if q, ok := cgroupCPUQuota(); ok {
		workerProcs = int(math.Ceil(q))
		if workerProcs < defaultGOMAXPROCS {
			workerProcs = defaultGOMAXPROCS
		}
	} else {
		workerProcs = defaultGOMAXPROCS
	}

	if gwProcs < 1 {
		gwProcs = 1
	}
	if workerProcs < 1 {
		workerProcs = 1
	}

	if cpus := runtime.NumCPU(); cpus > 0 {
		if gwProcs > cpus {
			gwProcs = cpus
		}
		if workerProcs > cpus {
			workerProcs = cpus
		}
	}

	runtime.GOMAXPROCS(gwProcs)
	return gwProcs, workerProcs
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func cleanHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" || strings.Contains(h, "${") || strings.HasPrefix(h, "$") || strings.Contains(h, "}") {
		return ""
	}
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	if slashIdx := strings.IndexByte(h, '/'); slashIdx != -1 {
		h = h[:slashIdx]
	}
	h = strings.TrimRight(h, "/.")
	if idx := strings.Index(h, ":"); idx != -1 && !strings.Contains(h, "]") {
		h = h[:idx]
	}
	return strings.ToLower(strings.TrimSpace(h))
}

func isCloadyCnameAlias(h string) bool {
	h = cleanHost(h)
	if h == "" {
		return false
	}
	switch h {
	case "cloady.io", "cloady.com", "cloady.internal",
		"ssh.cloady.io", "api.cloady.io", "api.cloady.com",
		"app.cloady.com", "docs.cloady.com", "www.cloady.com", "www.cloady.io",
		"ns1.cloady.io", "ns2.cloady.io":
		return true
	}
	return strings.HasSuffix(h, ".cloady.internal") ||
		strings.Contains(h, ".ingress.cloady.")
}

func isCloadyManagedDomain(h string) bool {
	h = cleanHost(h)
	if h == "" {
		return false
	}
	return isCloadyCnameAlias(h) ||
		strings.HasSuffix(h, ".cloady.io") ||
		strings.HasSuffix(h, ".cloady.com") ||
		strings.HasSuffix(h, "-service") ||
		strings.HasSuffix(h, ".cluster.local") ||
		strings.HasSuffix(h, ".svc") ||
		strings.HasSuffix(h, ".internal") ||
		strings.HasSuffix(h, ".local")
}

func isCloadyPublicDomain(h string) bool {
	h = cleanHost(h)
	if h == "" || isCloadyCnameAlias(h) {
		return false
	}
	return strings.HasSuffix(h, ".cloady.io") &&
		!strings.HasSuffix(h, ".internal") &&
		!strings.HasSuffix(h, ".local") &&
		!strings.HasSuffix(h, ".cluster.local") &&
		!strings.HasSuffix(h, ".svc") &&
		!strings.HasSuffix(h, "-service")
}

func isFullCloadyServiceDomain(h string) bool {
	h = cleanHost(h)
	if !isCloadyPublicDomain(h) {
		return false
	}
	sub := strings.TrimSuffix(h, ".cloady.io")
	if sub == "" || strings.Contains(sub, ".") {
		return false
	}
	// Cloady canonical app hostname format: <appSlug>-<hash8>-<workspaceSlug>.cloady.io
	return strings.Count(sub, "-") >= 2
}

func normalizeOptionalRegion(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" || strings.Contains(s, "${") || strings.HasPrefix(s, "$") {
		return ""
	}
	switch {
	case s == "eu1" || strings.Contains(s, "de-fra") || strings.Contains(s, "frankfurt") || strings.Contains(s, "germany") || strings.Contains(s, "eu-central") || strings.Contains(s, "europe"):
		return "eu1"
	case s == "uk1" || strings.Contains(s, "uk-lon") || strings.Contains(s, "london") || strings.Contains(s, "united kingdom") || s == "uk" || s == "gb":
		return "uk1"
	case s == "use1" || strings.Contains(s, "us-east") || strings.Contains(s, "virginia") || strings.Contains(s, "nyc") || strings.Contains(s, "ashburn"):
		return "use1"
	case s == "usc1" || strings.Contains(s, "us-central") || strings.Contains(s, "dallas") || strings.Contains(s, "chicago") || strings.Contains(s, "iowa"):
		return "usc1"
	case s == "usw1" || strings.Contains(s, "us-west") || strings.Contains(s, "california") || strings.Contains(s, "oregon") || strings.Contains(s, "sjc") || strings.Contains(s, "lax"):
		return "usw1"
	case s == "sin1" || strings.Contains(s, "singapore") || strings.Contains(s, "asia-southeast") || strings.Contains(s, "sg-sin") || s == "sg":
		return "sin1"
	case s == "jpn1" || strings.Contains(s, "japan") || strings.Contains(s, "tokyo") || s == "jp":
		return "jpn1"
	case s == "aus1" || strings.Contains(s, "australia") || strings.Contains(s, "sydney") || s == "au":
		return "aus1"
	case s == "ind1" || strings.Contains(s, "india") || strings.Contains(s, "mumbai") || strings.Contains(s, "bangalore") || s == "in":
		return "ind1"
	default:
		return ""
	}
}

func normalizeRegion(raw string) string {
	if reg := normalizeOptionalRegion(raw); reg != "" {
		return reg
	}
	return "eu1"
}

func resolveInfrastructureDomains() (cloadyDomain, customDomain string) {
	explicitCloady := cleanHost(getEnv("BERMUDA_CLOADY_DOMAIN", ""))
	primaryHost := cleanHost(getEnv("CLOADY_PRIMARY_HOST", ""))
	primaryURL := cleanHost(getEnv("CLOADY_PRIMARY_URL", getEnv("CLOADY_URL", "")))
	publicDomain := cleanHost(getEnv("CLOADY_DOMAIN", ""))
	customEnv := cleanHost(getEnv("CUSTOM_DOMAIN", getEnv("BERMUDA_CUSTOM_DOMAIN", "")))

	clCandidates := []string{explicitCloady, primaryHost, primaryURL, publicDomain}
	for _, candidate := range clCandidates {
		if isFullCloadyServiceDomain(candidate) {
			cloadyDomain = candidate
			break
		}
	}
	if cloadyDomain == "" {
		for _, candidate := range clCandidates {
			if isCloadyPublicDomain(candidate) {
				cloadyDomain = candidate
				break
			}
		}
	}

	for _, candidate := range []string{customEnv, publicDomain, primaryHost, primaryURL, explicitCloady} {
		if candidate != "" && !isCloadyManagedDomain(candidate) {
			customDomain = candidate
			break
		}
	}

	return cloadyDomain, customDomain
}

func resolveCloadyAPIToken() string {
	if tok := sanitizeCloadyToken(getEnv("CLOADY_API_TOKEN", "")); tok != "" {
		return tok
	}
	if tok := sanitizeCloadyToken(getEnv("BERMUDA_CLOADY_TOKEN", "")); tok != "" {
		return tok
	}
	if tok := sanitizeCloadyToken(getEnv("CLOADY_TOKEN", "")); isValidCloadyTokenFormat(tok) {
		return tok
	}
	return ""
}

func orchestrateCloudInfrastructure(
	ctx context.Context,
	sup *Supervisor,
	gw *Gateway,
	cl *CloadyClient,
	cf *CloudflareClient,
	initialCL string,
	initialCF string,
	initialRegion string,
) {
	for i := 0; i < 120 && !sup.IsReady(); i++ {
		if !sleepContext(ctx, 250*time.Millisecond) {
			return
		}
	}

	if !sleepContext(ctx, startupOrchestrationDelay) {
		return
	}

	startCL := cleanHost(initialCL)
	startCF := cleanHost(initialCF)
	cloadyDomain := startCL
	customDomain := startCF
	region := normalizeOptionalRegion(initialRegion)

	if curCL, curCF, curReg := sup.GetInfrastructureDomains(); cloadyDomain == "" || customDomain == "" || region == "" {
		if cloadyDomain == "" && isCloadyPublicDomain(curCL) {
			cloadyDomain = curCL
		}
		if customDomain == "" && curCF != "" && !isCloadyManagedDomain(curCF) {
			customDomain = curCF
		}
		if region == "" {
			region = normalizeOptionalRegion(curReg)
		}
	}

	domainDiscovered := false

	syncDomains := func(newCL, newCF string) {
		cleanCL := cleanHost(newCL)
		cleanCF := cleanHost(newCF)
		if isCloadyPublicDomain(cleanCL) {
			if cloadyDomain == "" || (!isFullCloadyServiceDomain(cloadyDomain) && isFullCloadyServiceDomain(cleanCL)) {
				if cloadyDomain != cleanCL {
					cloadyDomain = cleanCL
					domainDiscovered = true
				}
			}
		}
		if cleanCF != "" && !isCloadyManagedDomain(cleanCF) {
			if customDomain == "" || strings.HasSuffix(cleanCF, "."+customDomain) {
				if customDomain != cleanCF {
					customDomain = cleanCF
					domainDiscovered = true
				}
			}
		}
		sup.SetInfrastructureDomains(cloadyDomain, customDomain, region)
		gw.SetInfrastructureDomains(cloadyDomain, customDomain, region)
		if cf != nil {
			if cloadyDomain != "" {
				cf.SetCloadyOrigin(cloadyDomain)
			}
			if customDomain != "" {
				cf.SetPreferredDomain(customDomain)
			}
		}
		if cl != nil {
			if cloadyDomain != "" {
				cl.SetServiceDomain(cloadyDomain)
			}
			if customDomain != "" {
				cl.SetCustomDomain(customDomain)
			}
		}
	}

	if cl != nil && cl.IsConfigured() {
		if (sup.IsMasterKeyAutoGenerated() || sanitizeMasterKey(getEnv("BERMUDA_MASTER_KEY", getEnv("MASTER_KEY", ""))) == "") &&
			!strings.EqualFold(getEnv("BERMUDA_PERSIST_KEY", "true"), "false") {
			cl.PersistMasterKey(ctx, sup.MasterKey())
		}

		if srvDom, err := cl.EnsureServiceDomain(ctx); err == nil && srvDom != "" {
			syncDomains(srvDom, "")
		} else if err != nil {
			log.Printf("[Cloady] Notice: Service domain lookup: %v", err)
		}

		if reg := normalizeOptionalRegion(cl.GetDiscoveredRegion()); reg != "" && reg != region {
			region = reg
			sup.SetInfrastructureDomains(cloadyDomain, customDomain, region)
			gw.SetInfrastructureDomains(cloadyDomain, customDomain, region)
		}
	}

	if cf != nil && cf.Token != "" {
		probeCtx, probeCancel := context.WithTimeout(ctx, 12*time.Second)
		if cfDom, err := cf.FetchZoneDomain(probeCtx); err == nil && cfDom != "" {
			syncDomains(cf.GetCloadyOrigin(), cfDom)
		} else if err != nil {
			log.Printf("[Cloudflare] Notice: Zone domain discovery: %v", err)
		}
		probeCancel()
	}

	if region == "" {
		region = "eu1"
		sup.SetInfrastructureDomains(cloadyDomain, customDomain, region)
		gw.SetInfrastructureDomains(cloadyDomain, customDomain, region)
	}

	autoOrange := !strings.EqualFold(getEnv("BERMUDA_CF_AUTO_ORANGE", "true"), "false")
	if cf != nil && !autoOrange {
		cf.SetHoldGreyCloud(true)
	}

	var customDomInfo *CloadyCustomDomainInfo
	var cnameRecordID string
	var cfDNSProvisioned bool

	if customDomain != "" && (cl != nil || cloadyDomain != "") {
		if cl != nil && cl.IsConfigured() {
			info, err := cl.EnsureCustomDomain(ctx, customDomain)
			if err != nil {
				log.Printf("[Cloady] Notice: Custom domain registration (%s): %v", customDomain, err)
			} else if info != nil {
				customDomInfo = info
				syncDomains(cl.GetServiceDomain(), info.Domain)
			}
		}
		if customDomInfo == nil && cloadyDomain != "" {
			certState := "pending"
			isValid := probeCustomDomainTLS(ctx, customDomain, cloadyDomain)
			if isValid {
				certState = "issued"
			}
			customDomInfo = &CloadyCustomDomainInfo{
				Domain:            customDomain,
				CNAMETarget:       cloadyDomain,
				CertificateStatus: certState,
				RecordsVerified:   isValid,
			}
		}

		if cf != nil && (customDomInfo == nil || !customDomInfo.IsCertificateValid() || !autoOrange) {
			cf.SetHoldGreyCloud(true)
		}

		if customDomInfo != nil && cf != nil && cf.Token != "" {
			recID, dnsErr := cf.ProvisionCloadyDNS(ctx, customDomInfo)
			if dnsErr != nil {
				log.Printf("[Cloudflare] Warning: Automated Cloady DNS provisioning: %v", dnsErr)
			} else {
				cnameRecordID = recID
				cfDNSProvisioned = true
				_ = sleepContext(ctx, dnsPropagationSettleDelay)
				if cl != nil && cl.IsConfigured() && !customDomInfo.IsCertificateValid() {
					cl.TriggerDomainVerification(ctx, customDomInfo.ID)
				}
			}
		}
	}

	if cf != nil && cf.Token != "" && ctx.Err() == nil {
		cf.Tune(ctx)
		syncDomains(cf.GetCloadyOrigin(), cf.CachedZoneDomain())
	}

	if cf != nil && customDomInfo != nil && !customDomInfo.IsCertificateValid() && autoOrange && ctx.Err() == nil {
		if cfDNSProvisioned || customDomInfo.RecordsVerified {
			log.Printf("[Cloady] Waiting for Cloady TLS issuance on %s before enabling Cloudflare Orange Cloud...", customDomInfo.Domain)
			if cl != nil && cl.IsConfigured() {
				updatedInfo, valid := cl.WaitCustomDomainCertificate(ctx, customDomInfo.ID, customDomInfo.Domain, defaultCLCertPollWait)
				if valid && updatedInfo != nil {
					cf.PromoteCustomDomainToOrangeCloud(ctx, updatedInfo.Domain, updatedInfo.CNAMETarget, cnameRecordID)
				} else if ctx.Err() == nil {
					go watchAndPromoteCustomDomain(ctx, sup, cl, cf, customDomInfo, cnameRecordID)
				}
			} else {
				go watchAndPromoteCustomDomain(ctx, sup, nil, cf, customDomInfo, cnameRecordID)
			}
		} else if cf.GetZoneID() != "" {
			go watchAndPromoteCustomDomain(ctx, sup, cl, cf, customDomInfo, cnameRecordID)
		}
	}

	if ctx.Err() == nil {
		cl.TuneComputeAndNetwork(ctx)
	}

	// Re-sync in case proxy.go learned the live *.cloady.io domain from an incoming request during orchestration
	if curCL, curCF, _ := sup.GetInfrastructureDomains(); (cloadyDomain == "" && curCL != "") || (customDomain == "" && curCF != "") {
		if cloadyDomain == "" && isCloadyPublicDomain(curCL) {
			cloadyDomain = curCL
		}
		if customDomain == "" && curCF != "" && !isCloadyManagedDomain(curCF) {
			customDomain = curCF
		}
	}

	if ctx.Err() == nil {
		log.Printf("[Runtime] Synchronized Topology: CloadyDomain=%q | CloudflareDomain=%q | Region=%q",
			cloadyDomain, customDomain, region)
		if domainDiscovered && (cloadyDomain != startCL || customDomain != startCF) {
			sup.LogProvisioningLink("")
		} else if cloadyDomain == "" && customDomain == "" {
			log.Printf("[Runtime] Direct Mode Ready: Open https://<your-app>.cloady.io/?bmk=%s in your browser (or paste your *.cloady.io subdomain alongside the BMB1 token in index.html).",
				sup.MasterKey())
		}
	}
}

func watchAndPromoteCustomDomain(
	parent context.Context,
	sup *Supervisor,
	cl *CloadyClient,
	cf *CloudflareClient,
	info *CloadyCustomDomainInfo,
	cnameRecordID string,
) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
	defer cancel()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if parent.Err() == nil && info != nil {
				log.Printf("[Cloady] Notice: Deferred TLS watcher for %s timed out after 15m; verify CNAME propagation and Cloady TLS status.", info.Domain)
			}
			return
		case <-ticker.C:
			if cl != nil && cl.IsConfigured() {
				cl.TriggerDomainVerification(ctx, info.ID)
				latest, err := cl.FetchCustomDomainStatus(ctx, info.ID, info.Domain)
				if err == nil && latest != nil && latest.IsCertificateValid() {
					log.Printf("[Cloady] ✓ Deferred TLS issuance completed for %s (%s)",
						latest.Domain, latest.CertificateStatus)
					cf.PromoteCustomDomainToOrangeCloud(ctx, latest.Domain, latest.CNAMETarget, cnameRecordID)
					if sup != nil {
						sup.LogProvisioningLink("")
					}
					return
				}
			} else if probeCustomDomainTLS(ctx, info.Domain, info.CNAMETarget) {
				log.Printf("[Cloady] ✓ Direct Origin TLS + Route Identity verified for %s", info.Domain)
				cf.PromoteCustomDomainToOrangeCloud(ctx, info.Domain, info.CNAMETarget, cnameRecordID)
				if sup != nil {
					sup.LogProvisioningLink("")
				}
				return
			}
		}
	}
}

func bindDualListeners(listenCfg *net.ListenConfig, primaryPort string) ([]net.Listener, []string, error) {
	strictMode := strings.EqualFold(getEnv("BERMUDA_STRICT_PORT", "false"), "true")

	seenPorts := make(map[string]struct{}, 5)
	var portsToTry []string
	addPort := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, exists := seenPorts[p]; !exists {
			seenPorts[p] = struct{}{}
			portsToTry = append(portsToTry, p)
		}
	}

	addPort(primaryPort)
	if !strictMode {
		addPort(getEnv("PORT", ""))
		addPort(defaultPort)
		addPort(compatCloadyDefaultPort)
		addPort(compatHttpPort)
	}

	var listeners []net.Listener
	var boundAddrs []string
	var firstErr error

	for i, p := range portsToTry {
		addr := "0.0.0.0:" + p
		ln, err := listenCfg.Listen(context.Background(), "tcp", addr)
		if err != nil {
			if i == 0 {
				firstErr = err
				if strictMode {
					return nil, nil, err
				}
				log.Printf("[Gateway] Notice: Primary port :%s unavailable (%v); binding compatibility ports...", p, err)
			}
			continue
		}
		listeners = append(listeners, ln)
		boundAddrs = append(boundAddrs, ":"+p)
	}

	if len(listeners) == 0 {
		return nil, nil, firstErr
	}
	return listeners, boundAddrs, nil
}

func teardown(
	srv *http.Server,
	gw *Gateway,
	sup *Supervisor,
	supCancel context.CancelFunc,
	cloudCancel context.CancelFunc,
	graceful bool,
) {
	hardDeadline := time.Now().Add(22 * time.Second)

	if cloudCancel != nil {
		cloudCancel()
	}

	gw.SetDraining()
	if graceful {
		log.Println("[Gateway] Stage 1/5: Health status set to 503 (traffic shedding)...")
		time.Sleep(drainPropagationWindow)
	}

	if graceful {
		log.Println("[Gateway] Stage 2/5: Draining HTTP listeners and active XHTTP streams...")
		httpDeadline := minTime(hardDeadline.Add(-7*time.Second), time.Now().Add(11*time.Second))
		httpCtx, cancelHTTP := context.WithDeadline(context.Background(), httpDeadline)
		if err := srv.Shutdown(httpCtx); err != nil {
			log.Printf("[Gateway] HTTP drain timeout (%v); closing listeners", err)
			_ = srv.Close()
		} else {
			log.Println("[Gateway] HTTP listeners drained cleanly")
		}
		cancelHTTP()

		log.Println("[Gateway] Stage 3/5: Waiting for active upgraded WebSocket tunnels...")
		tunnelDeadline := minTime(hardDeadline.Add(-5*time.Second), time.Now().Add(httpDrainTimeout))
		if tunnelDeadline.After(time.Now()) {
			tunnelCtx, cancelTunnel := context.WithDeadline(context.Background(), tunnelDeadline)
			gw.WaitTunnels(tunnelCtx)
			cancelTunnel()
		}
	} else {
		_ = srv.Close()
	}

	log.Println("[Gateway] Stage 4/5: Closing remaining sockets and idle pools...")
	gw.CloseTunnels()
	gw.CloseIdleBackendConns()

	log.Println("[Gateway] Stage 5/5: Stopping worker process group...")
	supCancel()
	remainingSupTime := time.Until(hardDeadline)
	if remainingSupTime <= 0 {
		remainingSupTime = 2 * time.Second
	}
	sup.Stop(remainingSupTime)
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.Println("[Gateway] Initializing BERMUDA PORTAL Edge Router (Cloady Cloud + Cloudflare Edition)...")

	gwMB, workerMB := deriveMemoryBudget()
	gwProcs, workerProcs := applyGOMAXPROCS()

	_ = syscall.Setenv("BERMUDA_WORKER_MEM_MB", strconv.Itoa(workerMB))
	_ = syscall.Setenv("BERMUDA_XRAY_MEM_MB", strconv.Itoa(workerMB))
	_ = syscall.Setenv("BERMUDA_WORKER_GOMAXPROCS", strconv.Itoa(workerProcs))
	_ = syscall.Setenv("BERMUDA_XRAY_GOMAXPROCS", strconv.Itoa(workerProcs))
	log.Printf("[Runtime] Resource budget calibrated: Gateway=%dMiB (P=%d), Worker=%dMiB (P=%d) | GOGC=100",
		gwMB, gwProcs, workerMB, workerProcs)

	sigCtx, stopSig := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopSig()

	port := getEnv("PORT", getEnv("BERMUDA_LISTEN_PORT", defaultPort))
	cloadyDomain, customDomain := resolveInfrastructureDomains()

	rawRegion := getEnv("CLOADY_REGION", getEnv("BERMUDA_REGION", getEnv("REGION", "")))
	explicitRegion := normalizeOptionalRegion(rawRegion)

	sup := NewSupervisor()

	cfToken := sanitizeCloudflareToken(getEnv("CLOUDFLARE_API_TOKEN", getEnv("BERMUDA_CF_API_TOKEN", "")))
	cfZoneID := sanitizeExplicitCredential(getEnv("CLOUDFLARE_ZONE_ID", getEnv("BERMUDA_CF_ZONE_ID", "")))
	var cf *CloudflareClient
	if cfToken != "" {
		cf = NewCloudflareClient(cfToken, cfZoneID)
		if cloadyDomain != "" {
			cf.SetCloadyOrigin(cloadyDomain)
		}
		if customDomain != "" {
			cf.SetPreferredDomain(customDomain)
		}
	} else {
		log.Println("[Cloudflare] Notice: CLOUDFLARE_API_TOKEN unset. Edge auto-tuning bypassed.")
	}

	clToken := resolveCloadyAPIToken()
	var cl *CloadyClient
	if clToken != "" {
		cl = NewCloadyClient(clToken)
		if cl != nil {
			if cloadyDomain != "" {
				cl.SetServiceDomain(cloadyDomain)
			}
			if customDomain != "" {
				cl.SetCustomDomain(customDomain)
			}
		}
	} else {
		log.Println("[Cloady] Notice: CLOADY_API_TOKEN unset. Running in Zero-Token Direct Mode (auto-discovers *.cloady.io on first request).")
	}

	initialRegion := explicitRegion
	if initialRegion == "" && cl == nil {
		initialRegion = normalizeRegion(rawRegion)
	}

	sup.SetInfrastructureDomains(cloadyDomain, customDomain, initialRegion)
	primaryLogDomain := customDomain
	if primaryLogDomain == "" {
		primaryLogDomain = cloadyDomain
	}
	if primaryLogDomain != "" {
		sup.SetPublicDomain(primaryLogDomain)
	}

	displayRegion := initialRegion
	if displayRegion == "" {
		displayRegion = "auto-discover"
	}
	log.Printf("[Runtime] Initial Topology: CloadyDomain=%q | CloudflareDomain=%q | Region=%q",
		cloadyDomain, customDomain, displayRegion)

	gw := NewGateway(sup, cf, cloadyDomain, customDomain, initialRegion)
	gw.SetCloadyClient(cl)

	topologyUpdater := func(clDom, cfDom string) {
		_, _, curReg := sup.GetInfrastructureDomains()
		sup.SetInfrastructureDomains(clDom, cfDom, curReg)
		gw.SetInfrastructureDomains(clDom, cfDom, curReg)
	}
	if cf != nil {
		cf.SetTopologyCallback(topologyUpdater)
	}
	if cl != nil {
		cl.SetTopologyCallback(topologyUpdater)
	}

	srv := &http.Server{
		Addr:              "0.0.0.0:" + port,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       16 * time.Minute,
		MaxHeaderBytes:    32 << 10,
		ConnState:         gw.TrackConnState,
	}

	listenCfg := net.ListenConfig{
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     edgeKeepAlivePeriod,
			Interval: edgeKeepAlivePeriod,
			Count:    4,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			_ = c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeoutOpt, 90000)
			})
			return nil
		},
	}

	listeners, boundAddrs, err := bindDualListeners(&listenCfg, port)
	if err != nil {
		log.Fatalf("[Gateway] Fatal: Cannot bind HTTP listener on :%s: %v", port, err)
	}

	serverErrCh := make(chan error, len(listeners))
	log.Printf("[Gateway] Edge listeners active on %s (PID %d, GatewayP=%d, WorkerP=%d)",
		strings.Join(boundAddrs, " & "), os.Getpid(), gwProcs, workerProcs)

	for _, ln := range listeners {
		activeLn := ln
		go func() {
			if err := srv.Serve(activeLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				select {
				case serverErrCh <- err:
				default:
				}
			}
		}()
	}

	supCtx, supCancel := context.WithCancel(context.Background())
	supErrCh := make(chan error, 1)
	go func() {
		supErrCh <- sup.Run(supCtx)
	}()

	go func() {
		select {
		case <-sup.BootstrapDone():
		case <-sigCtx.Done():
			return
		}
		runtime.GC()
		debug.FreeOSMemory()
		applyMemoryCeiling(gwMB)
	}()

	cloudCtx, cloudCancel := context.WithCancel(sigCtx)
	defer cloudCancel()
	go orchestrateCloudInfrastructure(cloudCtx, sup, gw, cl, cf, cloadyDomain, customDomain, initialRegion)

	select {
	case err := <-serverErrCh:
		log.Printf("[Gateway] Fatal: HTTP server error: %v", err)
		teardown(srv, gw, sup, supCancel, cloudCancel, false)
		os.Exit(1)
	case err := <-supErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("[Gateway] Fatal: Worker supervisor halted: %v", err)
		}
		teardown(srv, gw, sup, supCancel, cloudCancel, false)
		os.Exit(1)
	case <-sigCtx.Done():
		log.Println("[Gateway] Termination signal received. Initiating graceful teardown...")
	}

	teardown(srv, gw, sup, supCancel, cloudCancel, true)
	log.Println("[Gateway] BERMUDA PORTAL Edge Router shutdown complete. Exit 0.")
}
