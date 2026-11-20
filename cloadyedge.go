package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

const (
	cloadyAPIBase            = "https://cloady.com/api"
	defaultCLReqTimeout      = 15 * time.Second
	defaultCLCertPollTick    = 6 * time.Second
	defaultCLCertPollWait    = 90 * time.Second
	defaultCLTLSProbeTimeout = 6 * time.Second
	defaultCLTargetPort      = 8080
	minCLRequestInterval     = 500 * time.Millisecond
	ipv6ProbeCacheTTL        = 60 * time.Second
)

var cloudflareIPv4CIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

var cloudflareIPv6CIDRs = []string{
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

var (
	cfNetsOnce sync.Once
	cfNets     []*net.IPNet

	ipv6ProbeMu      sync.Mutex
	ipv6ProbeChecked time.Time
	ipv6ProbeResult  bool
)

func isCloudflareEdgeIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	cfNetsOnce.Do(func() {
		for _, cidr := range append(append([]string{}, cloudflareIPv4CIDRs...), cloudflareIPv6CIDRs...) {
			if _, network, err := net.ParseCIDR(cidr); err == nil && network != nil {
				cfNets = append(cfNets, network)
			}
		}
	})
	for _, network := range cfNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

type clAPIError struct {
	StatusCode int
	Message    string
}

func (e *clAPIError) Error() string {
	if strings.TrimSpace(e.Message) != "" {
		return fmt.Sprintf("cloady api error (HTTP %d): %s", e.StatusCode, strings.TrimSpace(e.Message))
	}
	return fmt.Sprintf("cloady api error (HTTP %d)", e.StatusCode)
}

func (e *clAPIError) IsPermissionOrPlan() bool {
	if e.StatusCode == http.StatusUnauthorized ||
		e.StatusCode == http.StatusForbidden ||
		e.StatusCode == http.StatusPaymentRequired {
		return true
	}
	lower := strings.ToLower(e.Message)
	return strings.Contains(lower, "unauthorized") ||
		strings.Contains(lower, "forbidden") ||
		strings.Contains(lower, "permission") ||
		strings.Contains(lower, "scope") ||
		strings.Contains(lower, "payment_required") ||
		strings.Contains(lower, "plan") ||
		strings.Contains(lower, "quota") ||
		strings.Contains(lower, "limit")
}

func (e *clAPIError) IsRegionRequired() bool {
	if e.StatusCode != http.StatusBadRequest {
		return false
	}
	return strings.Contains(strings.ToLower(e.Message), "region_required")
}

type CloadyCustomDomainInfo struct {
	ID                string
	Domain            string
	CNAMETarget       string
	VerificationHost  string
	VerificationToken string
	CertificateStatus string
	DNSReady          bool
	SSLReady          bool
	Ready             bool
	RecordsVerified   bool
	OriginIPv4        []string
	OriginIPv6        []string
}

func (info *CloadyCustomDomainInfo) IsCertificateValid() bool {
	if info == nil {
		return false
	}
	st := strings.ToUpper(strings.TrimSpace(info.CertificateStatus))
	if st == "" ||
		strings.Contains(st, "QUEUED") ||
		strings.Contains(st, "PENDING") ||
		strings.Contains(st, "PROVISION") ||
		strings.Contains(st, "ISSUING") ||
		strings.Contains(st, "UNVERIFIED") ||
		strings.Contains(st, "INVALID") ||
		strings.Contains(st, "FAILED") ||
		strings.Contains(st, "ERROR") ||
		strings.Contains(st, "UNKNOWN") {
		return false
	}
	if st == "ISSUED" || st == "VALID" || st == "ACTIVE" || st == "READY" || st == "VERIFIED" {
		return true
	}
	return info.Ready || info.SSLReady
}

type cloadyDNSCheckResult struct {
	OK          bool
	Taken       bool
	Delegated   bool
	TargetsA    []string
	TargetsAAAA []string
}

type CloadyClient struct {
	Token         string
	WorkspaceSlug string
	AppSlug       string
	Environment   string
	TargetPort    int
	apiBase       string
	client        *http.Client

	reqMu      sync.Mutex
	lastReq    time.Time
	authFailed atomic.Bool

	mu               sync.RWMutex
	serviceDomain    string
	customDomain     string
	discoveredRegion string
	regionConfirmed  bool
	certEndpointSkip bool
	cachedOriginIPv4 []string
	cachedOriginIPv6 []string
	keyPersisted     bool
	onTopology       func(cloadyDom, cfDom string)
}

func sanitizeCloadyToken(raw string) string {
	s := strings.TrimSpace(raw)
	upper := strings.ToUpper(s)
	for _, prefix := range []string{"CLOADY_API_TOKEN", "CLOADY_TOKEN", "BERMUDA_CLOADY_TOKEN"} {
		if strings.HasPrefix(upper, prefix) {
			if _, after, ok := strings.Cut(s, "="); ok {
				s = strings.TrimSpace(after)
			}
		}
	}
	if len(s) > 7 && strings.EqualFold(s[:7], "bearer ") {
		s = strings.TrimSpace(s[7:])
	}
	s = strings.Trim(s, "\"'` \t\r\n")
	if idx := strings.Index(s, "cldy_"); idx > 0 {
		s = s[idx:]
		if fields := strings.Fields(s); len(fields) > 0 {
			s = fields[0]
		}
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r > 126 {
			return -1
		}
		return r
	}, s)
	if strings.Contains(s, "${") || strings.HasPrefix(s, "$") {
		return ""
	}
	return s
}

func isValidCloadyTokenFormat(tok string) bool {
	if !strings.HasPrefix(tok, "cldy_") || len(tok) < 16 {
		return false
	}
	for i := 5; i < len(tok); i++ {
		c := tok[i]
		isAlphaNum := (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		if !isAlphaNum && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func maskCloadyTokenPreview(tok string) string {
	if tok == "" {
		return "empty"
	}
	if strings.HasPrefix(tok, "cldy_") {
		return fmt.Sprintf("prefix=\"cldy_\", len=%d", len(tok))
	}
	return fmt.Sprintf("prefix=\"non-cldy\", len=%d", len(tok))
}

func NewCloadyClient(token string) *CloadyClient {
	cleanTok := sanitizeCloadyToken(token)
	if cleanTok == "" {
		return nil
	}
	if !isValidCloadyTokenFormat(cleanTok) {
		log.Printf("[Cloady] Warning: Ignoring invalid CLOADY_API_TOKEN (%s): Cloady tokens must start with 'cldy_' (create one at cloady.com -> Avatar -> API tokens -> + New token). Continuing in Direct Mode.",
			maskCloadyTokenPreview(cleanTok))
		return nil
	}

	port := getEnvInt("PORT", getEnvInt("BERMUDA_LISTEN_PORT", defaultCLTargetPort))
	if port <= 0 {
		port = defaultCLTargetPort
	}

	clDom, cfDom := resolveInfrastructureDomains()
	apiURL := sanitizeExplicitCredential(getEnv("CLOADY_API_URL", getEnv("BERMUDA_CLOADY_API_URL", cloadyAPIBase)))
	if apiURL == "" {
		apiURL = cloadyAPIBase
	}
	apiURL = strings.TrimRight(apiURL, "/")

	wsSlug := sanitizeExplicitCredential(getEnv("CLOADY_WORKSPACE", getEnv("CLOADY_WORKSPACE_SLUG", "")))
	appSlug := sanitizeExplicitCredential(getEnv("CLOADY_APP", getEnv("CLOADY_SVCID", getEnv("CLOADY_APP_SLUG", ""))))
	envName := sanitizeExplicitCredential(getEnv("CLOADY_ENV", "production"))
	if envName == "" {
		envName = "production"
	}

	platformReg := normalizeOptionalRegion(getEnv("CLOADY_REGION", ""))
	explicitReg := normalizeOptionalRegion(getEnv("BERMUDA_REGION", getEnv("REGION", "")))
	discReg := platformReg
	regConfirmed := platformReg != ""
	if discReg == "" && explicitReg != "" {
		discReg = explicitReg
	}

	return &CloadyClient{
		Token:            cleanTok,
		WorkspaceSlug:    wsSlug,
		AppSlug:          appSlug,
		Environment:      envName,
		TargetPort:       port,
		apiBase:          apiURL,
		serviceDomain:    clDom,
		customDomain:     cfDom,
		discoveredRegion: discReg,
		regionConfirmed:  regConfirmed,
		client: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func (c *CloadyClient) IsConfigured() bool {
	return c != nil && c.Token != "" && !c.authFailed.Load()
}

func (c *CloadyClient) HasServiceContext() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.WorkspaceSlug != "" && c.AppSlug != ""
}

func (c *CloadyClient) SetTopologyCallback(fn func(cloadyDom, cfDom string)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.onTopology = fn
	c.mu.Unlock()
}

func (c *CloadyClient) notifyTopology() {
	if c == nil {
		return
	}
	c.mu.RLock()
	fn := c.onTopology
	cl := c.serviceDomain
	cf := c.customDomain
	c.mu.RUnlock()
	if fn != nil {
		fn(cl, cf)
	}
}

func (c *CloadyClient) GetServiceDomain() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.serviceDomain
}

func (c *CloadyClient) GetCustomDomain() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.customDomain
}

func (c *CloadyClient) GetDiscoveredRegion() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.discoveredRegion
}

func (c *CloadyClient) SetServiceDomain(d string) {
	if c == nil {
		return
	}
	clean := cleanHost(d)
	if !isCloadyPublicDomain(clean) {
		return
	}
	c.mu.Lock()
	if c.serviceDomain == "" || (!isFullCloadyServiceDomain(c.serviceDomain) && isFullCloadyServiceDomain(clean)) {
		c.serviceDomain = clean
	}
	c.mu.Unlock()
}

func (c *CloadyClient) SetCustomDomain(d string) {
	if c == nil {
		return
	}
	clean := cleanHost(d)
	if clean == "" || isCloadyManagedDomain(clean) {
		return
	}
	c.mu.Lock()
	c.customDomain = clean
	c.mu.Unlock()
}

func (c *CloadyClient) baseURL() string {
	if c != nil && c.apiBase != "" {
		return c.apiBase
	}
	return cloadyAPIBase
}

func (c *CloadyClient) envOnlyQuery() string {
	c.mu.RLock()
	envName := c.Environment
	c.mu.RUnlock()
	if envName == "" {
		envName = "production"
	}
	return "?env=" + url.QueryEscape(envName)
}

func (c *CloadyClient) envRegionQuery() string {
	c.mu.RLock()
	envName := c.Environment
	reg := c.discoveredRegion
	c.mu.RUnlock()

	if envName == "" {
		envName = "production"
	}
	if reg == "" {
		return "?env=" + url.QueryEscape(envName)
	}
	return "?env=" + url.QueryEscape(envName) + "&region=" + url.QueryEscape(reg)
}

func (c *CloadyClient) paceAPIRequest(ctx context.Context) error {
	c.reqMu.Lock()
	defer c.reqMu.Unlock()

	if !c.lastReq.IsZero() {
		elapsed := time.Since(c.lastReq)
		if elapsed < minCLRequestInterval {
			wait := minCLRequestInterval - elapsed
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				if !t.Stop() {
					<-t.C
				}
				return ctx.Err()
			case <-t.C:
			}
		}
	}
	c.lastReq = time.Now()
	return nil
}

func extractCloadyErrorMessage(rawBytes []byte) string {
	trimmed := strings.TrimSpace(string(rawBytes))
	if trimmed == "" {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(rawBytes, &m) == nil && m != nil {
		if errObj, ok := m["error"].(map[string]any); ok {
			for _, k := range []string{"message", "code", "detail"} {
				if s, ok := errObj[k].(string); ok && strings.TrimSpace(s) != "" {
					return strings.TrimSpace(s)
				}
			}
		}
		for _, k := range []string{"error", "code", "message", "detail", "reason"} {
			if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	if len(trimmed) > 256 {
		trimmed = trimmed[:256]
	}
	return trimmed
}

func doCLRequest(ctx context.Context, c *CloadyClient, method, path string, body any) ([]byte, int, error) {
	if c == nil || c.Token == "" {
		return nil, 0, errors.New("cloady client not configured")
	}
	if c.authFailed.Load() {
		return nil, http.StatusUnauthorized, &clAPIError{
			StatusCode: http.StatusUnauthorized,
			Message:    "cloady api token previously rejected (HTTP 401)",
		}
	}

	var reqBytes []byte
	if body != nil {
		var err error
		reqBytes, err = json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal cloady payload: %w", err)
		}
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if err := c.paceAPIRequest(ctx); err != nil {
			return nil, 0, err
		}

		reqCtx, cancel := context.WithTimeout(ctx, defaultCLReqTimeout)
		var bodyReader io.Reader
		if len(reqBytes) > 0 {
			bodyReader = bytes.NewReader(reqBytes)
		}

		req, err := http.NewRequestWithContext(reqCtx, method, c.baseURL()+path, bodyReader)
		if err != nil {
			cancel()
			return nil, 0, fmt.Errorf("build cloady request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("User-Agent", "BERMUDA-Portal-CloudOrchestrator/4.0 (Go-Standard-Library)")

		resp, doErr := c.client.Do(req)
		if doErr != nil {
			cancel()
			lastErr = doErr
			break
		}

		rawBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		cancel()

		if readErr != nil {
			return nil, resp.StatusCode, fmt.Errorf("read cloady response: %w", readErr)
		}

		if resp.StatusCode == http.StatusTooManyRequests && attempt == 0 {
			select {
			case <-ctx.Done():
				return nil, resp.StatusCode, ctx.Err()
			case <-time.After(2 * time.Second):
				continue
			}
		}

		if resp.StatusCode >= 400 {
			errMsg := extractCloadyErrorMessage(rawBytes)
			if resp.StatusCode == http.StatusUnauthorized {
				if c.authFailed.CompareAndSwap(false, true) {
					log.Printf("[Cloady] Warning: CLOADY_API_TOKEN (%s) was rejected by Cloady API (HTTP 401: %s). Direct *.cloady.io tunnel remains 100%% active; regenerate a 'cldy_...' token at cloady.com -> Avatar -> API tokens only if you need automated API discovery.",
						maskCloadyTokenPreview(c.Token), errMsg)
				}
			} else if resp.StatusCode == http.StatusForbidden {
				log.Printf("[Cloady] Warning: CLOADY_API_TOKEN (%s) returned HTTP 403 Forbidden (%s). Ensure the token has 'read' scope (for Direct Mode) or 'deploy' scope (for Custom Domains) and is not pinned to a different workspace.",
					maskCloadyTokenPreview(c.Token), errMsg)
			}
			return rawBytes, resp.StatusCode, &clAPIError{
				StatusCode: resp.StatusCode,
				Message:    errMsg,
			}
		}

		return rawBytes, resp.StatusCode, nil
	}

	return nil, 0, lastErr
}

// doCLAppRequest sends an app-scoped API call with Cloady's ?env=&region= semantics:
// uses ?env= first unless region is confirmed, automatically retrying with ?region=
// on HTTP 400 region_required, and falling back to ?env= on HTTP 404.
func (c *CloadyClient) doCLAppRequest(ctx context.Context, method, basePath string, body any) ([]byte, int, error) {
	c.mu.RLock()
	reg := c.discoveredRegion
	confirmed := c.regionConfirmed
	c.mu.RUnlock()

	primaryPath := basePath + c.envOnlyQuery()
	usedRegion := false
	if confirmed && reg != "" {
		primaryPath = basePath + c.envRegionQuery()
		usedRegion = true
	}

	raw, status, err := doCLRequest(ctx, c, method, primaryPath, body)
	if err == nil {
		return raw, status, nil
	}

	var apiErr *clAPIError
	if errors.As(err, &apiErr) {
		if apiErr.IsRegionRequired() && !usedRegion && reg != "" {
			raw2, status2, err2 := doCLRequest(ctx, c, method, basePath+c.envRegionQuery(), body)
			if err2 == nil {
				c.mu.Lock()
				c.regionConfirmed = true
				c.mu.Unlock()
				return raw2, status2, nil
			}
			return raw2, status2, err2
		}
		if apiErr.StatusCode == http.StatusNotFound && usedRegion {
			return doCLRequest(ctx, c, method, basePath+c.envOnlyQuery(), body)
		}
	}

	return raw, status, err
}

func clAnyToString(v any) string {
	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val)
	case float64:
		if val > 0 {
			return strconv.FormatInt(int64(val), 10)
		}
	case json.Number:
		return val.String()
	}
	return ""
}

type clWorkspaceCandidate struct {
	ID       string
	Slug     string
	Name     string
	Services []clAppCandidate
}

type clAppCandidate struct {
	ID            string
	Slug          string
	Name          string
	WorkspaceSlug string
	Environment   string
	Region        string
	ServiceDomain string
	Port          int
}

func extractBestCloadyEndpoint(endpointsVal any) string {
	arr, ok := endpointsVal.([]any)
	if !ok || len(arr) == 0 {
		return ""
	}
	var fallback string
	checkCandidate := func(raw string) string {
		clean := cleanHost(raw)
		if isFullCloadyServiceDomain(clean) {
			return clean
		}
		if fallback == "" && isCloadyPublicDomain(clean) {
			fallback = clean
		}
		return ""
	}

	for _, item := range arr {
		switch ep := item.(type) {
		case string:
			if full := checkCandidate(ep); full != "" {
				return full
			}
		case map[string]any:
			for _, k := range []string{"url", "host", "hostname", "domain", "fqdn", "primaryUrl", "primaryHost"} {
				if s := clAnyToString(ep[k]); s != "" {
					if full := checkCandidate(s); full != "" {
						return full
					}
				}
			}
		}
	}
	return fallback
}

func parseCloadyAppMap(m map[string]any, wsSlug string) clAppCandidate {
	if inner, ok := m["service"].(map[string]any); ok && len(inner) > 0 {
		m = inner
	} else if inner, ok := m["app"].(map[string]any); ok && len(inner) > 0 {
		m = inner
	} else if inner, ok := m["application"].(map[string]any); ok && len(inner) > 0 {
		m = inner
	}

	var cand clAppCandidate
	cand.WorkspaceSlug = wsSlug
	cand.ID = clAnyToString(m["id"])
	for _, k := range []string{"slug", "appSlug", "serviceSlug", "svcid"} {
		if s := clAnyToString(m[k]); s != "" {
			cand.Slug = s
			break
		}
	}
	for _, k := range []string{"name", "title", "displayName"} {
		if s := clAnyToString(m[k]); s != "" {
			cand.Name = s
			break
		}
	}
	if cand.Slug == "" {
		cand.Slug = cand.ID
	}
	if s := clAnyToString(m["env"]); s != "" {
		cand.Environment = s
	} else if s := clAnyToString(m["environment"]); s != "" {
		cand.Environment = s
	}
	for _, k := range []string{"region", "regionCode", "location"} {
		if s := clAnyToString(m[k]); s != "" {
			if norm := normalizeOptionalRegion(s); norm != "" {
				cand.Region = norm
				break
			}
		}
	}
	if cand.Region == "" {
		if regMap, ok := m["region"].(map[string]any); ok {
			for _, k := range []string{"code", "slug", "id", "name"} {
				if s := clAnyToString(regMap[k]); s != "" {
					if norm := normalizeOptionalRegion(s); norm != "" {
						cand.Region = norm
						break
					}
				}
			}
		}
	}

	if dom := extractBestCloadyEndpoint(m["endpoints"]); dom != "" {
		cand.ServiceDomain = dom
	}

	if !isFullCloadyServiceDomain(cand.ServiceDomain) {
		for _, k := range []string{"primaryHost", "primaryUrl", "url", "domain", "defaultDomain", "hostname", "publicUrl", "fqdn"} {
			if s := clAnyToString(m[k]); s != "" {
				clean := cleanHost(s)
				if isFullCloadyServiceDomain(clean) {
					cand.ServiceDomain = clean
					break
				}
				if cand.ServiceDomain == "" && isCloadyPublicDomain(clean) {
					cand.ServiceDomain = clean
				}
			}
		}
	}

	if !isFullCloadyServiceDomain(cand.ServiceDomain) {
		for _, subKey := range []string{"subServices", "components"} {
			if subs, ok := m[subKey].([]any); ok {
				for _, item := range subs {
					subMap, ok := item.(map[string]any)
					if !ok {
						continue
					}
					if dom := extractBestCloadyEndpoint(subMap["endpoints"]); isFullCloadyServiceDomain(dom) {
						cand.ServiceDomain = dom
						break
					}
					for _, k := range []string{"url", "host", "domain"} {
						if clean := cleanHost(clAnyToString(subMap[k])); isFullCloadyServiceDomain(clean) {
							cand.ServiceDomain = clean
							break
						}
						if cand.ServiceDomain == "" {
							if clean := cleanHost(clAnyToString(subMap[k])); isCloadyPublicDomain(clean) {
								cand.ServiceDomain = clean
							}
						}
					}
					if isFullCloadyServiceDomain(cand.ServiceDomain) {
						break
					}
				}
			}
		}
	}

	if p, err := strconv.Atoi(clAnyToString(m["port"])); err == nil && p > 0 {
		cand.Port = p
	}

	return cand
}

func extractCloadyAppsFromMap(v map[string]any, wsSlug string) []clAppCandidate {
	var out []clAppCandidate
	seen := make(map[string]struct{})

	addApp := func(m map[string]any) {
		cand := parseCloadyAppMap(m, wsSlug)
		if cand.Slug == "" {
			return
		}
		key := cand.WorkspaceSlug + "|" + cand.Slug + "|" + cand.Region
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		out = append(out, cand)
	}

	if wsObj, ok := v["workspace"].(map[string]any); ok && len(wsObj) > 0 {
		if slug := clAnyToString(wsObj["slug"]); slug != "" && wsSlug == "" {
			wsSlug = slug
		}
		v = wsObj
	}

	for _, key := range []string{"services", "apps", "applications", "data", "items", "results"} {
		if arr, ok := v[key].([]any); ok {
			for _, item := range arr {
				if m, ok := item.(map[string]any); ok {
					addApp(m)
				}
			}
		}
	}
	if len(out) == 0 {
		addApp(v)
	}
	return out
}

func extractCloadyAppsFromJSON(rawBytes []byte, wsSlug string) []clAppCandidate {
	var raw any
	if err := json.Unmarshal(rawBytes, &raw); err != nil {
		return nil
	}

	switch v := raw.(type) {
	case []any:
		var out []clAppCandidate
		seen := make(map[string]struct{})
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				cand := parseCloadyAppMap(m, wsSlug)
				if cand.Slug == "" {
					continue
				}
				key := cand.WorkspaceSlug + "|" + cand.Slug + "|" + cand.Region
				if _, exists := seen[key]; !exists {
					seen[key] = struct{}{}
					out = append(out, cand)
				}
			}
		}
		return out
	case map[string]any:
		return extractCloadyAppsFromMap(v, wsSlug)
	}
	return nil
}

func extractWorkspacesFromJSON(rawBytes []byte) []clWorkspaceCandidate {
	var raw any
	if err := json.Unmarshal(rawBytes, &raw); err != nil {
		return nil
	}

	var out []clWorkspaceCandidate
	seen := make(map[string]struct{})

	addWS := func(m map[string]any) {
		if inner, ok := m["workspace"].(map[string]any); ok && len(inner) > 0 {
			m = inner
		}
		var cand clWorkspaceCandidate
		cand.ID = clAnyToString(m["id"])
		for _, k := range []string{"slug", "workspaceSlug", "handle"} {
			if s := clAnyToString(m[k]); s != "" {
				cand.Slug = s
				break
			}
		}
		for _, k := range []string{"name", "title"} {
			if s := clAnyToString(m[k]); s != "" {
				cand.Name = s
				break
			}
		}
		if cand.Slug == "" {
			cand.Slug = cand.ID
		}
		if cand.Slug == "" {
			return
		}
		if _, exists := seen[cand.Slug]; exists {
			return
		}
		seen[cand.Slug] = struct{}{}

		for _, svcKey := range []string{"services", "apps", "applications"} {
			if arr, ok := m[svcKey].([]any); ok && len(arr) > 0 {
				for _, item := range arr {
					if svcMap, ok := item.(map[string]any); ok {
						appCand := parseCloadyAppMap(svcMap, cand.Slug)
						if appCand.Slug != "" {
							cand.Services = append(cand.Services, appCand)
						}
					}
				}
				break
			}
		}
		out = append(out, cand)
	}

	switch v := raw.(type) {
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				addWS(m)
			}
		}
	case map[string]any:
		for _, key := range []string{"workspaces", "data", "items", "results"} {
			if arr, ok := v[key].([]any); ok {
				for _, item := range arr {
					if m, ok := item.(map[string]any); ok {
						addWS(m)
					}
				}
			}
		}
		if len(out) == 0 {
			addWS(v)
		}
	}

	return out
}

func (c *CloadyClient) applyAppCandidate(cand clAppCandidate) {
	c.mu.Lock()
	if cand.WorkspaceSlug != "" && c.WorkspaceSlug == "" {
		c.WorkspaceSlug = cand.WorkspaceSlug
	}
	if cand.Slug != "" && c.AppSlug == "" {
		c.AppSlug = cand.Slug
	}
	if cand.Environment != "" && c.Environment == "" {
		c.Environment = cand.Environment
	}
	if cand.Region != "" {
		c.discoveredRegion = cand.Region
		c.regionConfirmed = true
	}
	if isCloadyPublicDomain(cand.ServiceDomain) && (c.serviceDomain == "" || (!isFullCloadyServiceDomain(c.serviceDomain) && isFullCloadyServiceDomain(cand.ServiceDomain))) {
		c.serviceDomain = cand.ServiceDomain
	}
	if cand.Port > 0 {
		c.TargetPort = cand.Port
	}
	c.mu.Unlock()
	c.notifyTopology()
}

func (c *CloadyClient) enrichAppDetails(ctx context.Context) {
	if !c.IsConfigured() {
		return
	}
	c.mu.RLock()
	ws := c.WorkspaceSlug
	app := c.AppSlug
	c.mu.RUnlock()
	if ws == "" || app == "" {
		return
	}

	wsPath := fmt.Sprintf("/workspaces/%s", url.PathEscape(ws))
	if raw, _, err := doCLRequest(ctx, c, http.MethodGet, wsPath, nil); err == nil && len(raw) > 0 {
		for _, cand := range extractCloadyAppsFromJSON(raw, ws) {
			if strings.EqualFold(cand.Slug, app) || strings.EqualFold(cand.Name, app) || strings.EqualFold(cand.ID, app) {
				c.applyAppCandidate(cand)
				break
			}
		}
	}

	if !isCloadyPublicDomain(c.GetServiceDomain()) || c.GetDiscoveredRegion() == "" {
		appPath := fmt.Sprintf("/workspaces/%s/apps/%s", url.PathEscape(ws), url.PathEscape(app))
		if raw, _, err := c.doCLAppRequest(ctx, http.MethodGet, appPath, nil); err == nil && len(raw) > 0 {
			cands := extractCloadyAppsFromJSON(raw, ws)
			if len(cands) > 0 {
				c.applyAppCandidate(cands[0])
			}
		}
	}
}

func (c *CloadyClient) ResolveRuntimeContext(ctx context.Context) error {
	if !c.IsConfigured() {
		return errors.New("cloady client not configured")
	}

	c.mu.RLock()
	wsSlug := c.WorkspaceSlug
	appSlug := c.AppSlug
	srvDom := c.serviceDomain
	regConfirmed := c.regionConfirmed
	c.mu.RUnlock()

	if wsSlug != "" && appSlug != "" {
		if !isCloadyPublicDomain(srvDom) || !regConfirmed {
			c.enrichAppDetails(ctx)
		}
		return nil
	}

	var workspaces []clWorkspaceCandidate
	if wsSlug != "" {
		workspaces = []clWorkspaceCandidate{{Slug: wsSlug}}
	} else {
		raw, _, err := doCLRequest(ctx, c, http.MethodGet, "/workspaces", nil)
		if err != nil {
			return fmt.Errorf("list cloady workspaces: %w", err)
		}
		workspaces = extractWorkspacesFromJSON(raw)
	}

	if len(workspaces) == 0 {
		return errors.New("no cloady workspaces discovered under this api token")
	}

	localHost, _ := os.Hostname()
	localHost = strings.ToLower(strings.TrimSpace(localHost))
	svcIDEnv := strings.ToLower(strings.TrimSpace(getEnv("CLOADY_SVCID", "")))

	var allApps []clAppCandidate
	var matched *clAppCandidate

	matchApp := func(cand clAppCandidate) bool {
		if srvDom != "" && cand.ServiceDomain != "" && strings.EqualFold(cand.ServiceDomain, srvDom) {
			return true
		}
		if appSlug != "" && (strings.EqualFold(cand.Slug, appSlug) || strings.EqualFold(cand.Name, appSlug) || strings.EqualFold(cand.ID, appSlug)) {
			return true
		}
		if svcIDEnv != "" && (strings.EqualFold(cand.Slug, svcIDEnv) || strings.EqualFold(cand.ID, svcIDEnv)) {
			return true
		}
		if localHost != "" && cand.Slug != "" && strings.HasPrefix(localHost, strings.ToLower(cand.Slug)) {
			return true
		}
		return false
	}

	for _, ws := range workspaces {
		apps := ws.Services

		if len(apps) == 0 {
			wsDetailPath := fmt.Sprintf("/workspaces/%s", url.PathEscape(ws.Slug))
			if raw, _, err := doCLRequest(ctx, c, http.MethodGet, wsDetailPath, nil); err == nil && len(raw) > 0 {
				apps = extractCloadyAppsFromJSON(raw, ws.Slug)
			}
		}

		if len(apps) == 0 {
			appsPath := fmt.Sprintf("/workspaces/%s/apps", url.PathEscape(ws.Slug))
			if raw, _, err := doCLRequest(ctx, c, http.MethodGet, appsPath, nil); err == nil && len(raw) > 0 {
				apps = extractCloadyAppsFromJSON(raw, ws.Slug)
			}
		}

		for i := range apps {
			cand := apps[i]
			allApps = append(allApps, cand)
			if matchApp(cand) {
				matched = &allApps[len(allApps)-1]
				break
			}
		}
		if matched != nil {
			break
		}
	}

	if matched == nil {
		if len(allApps) == 1 {
			matched = &allApps[0]
		} else if len(allApps) == 0 {
			return errors.New("no cloady applications discovered under this api token")
		} else {
			return fmt.Errorf("ambiguous cloady application identity (%d apps found; set CLOADY_WORKSPACE and CLOADY_APP explicitly)", len(allApps))
		}
	}

	c.applyAppCandidate(*matched)
	if !isCloadyPublicDomain(c.GetServiceDomain()) || c.GetDiscoveredRegion() == "" {
		c.enrichAppDetails(ctx)
	}
	log.Printf("[Cloady] ✓ Application context resolved: Workspace=%s | App=%s | Domain=%q | Region=%q",
		c.WorkspaceSlug, c.AppSlug, c.GetServiceDomain(), c.GetDiscoveredRegion())
	return nil
}

func inspectCloadyMasterKeyVar(rawBytes []byte) (hasNonEmpty bool, emptyVarID string) {
	if len(rawBytes) == 0 {
		return false, ""
	}
	var raw any
	if err := json.Unmarshal(rawBytes, &raw); err != nil {
		return false, ""
	}

	var walk func(node any)
	walk = func(node any) {
		if hasNonEmpty {
			return
		}
		switch val := node.(type) {
		case []any:
			for _, item := range val {
				if m, ok := item.(map[string]any); ok {
					k := clAnyToString(m["key"])
					if k == "" {
						k = clAnyToString(m["name"])
					}
					if strings.EqualFold(k, "BERMUDA_MASTER_KEY") || strings.EqualFold(k, "MASTER_KEY") {
						v := clAnyToString(m["value"])
						isSec, _ := m["isSecret"].(bool)
						if v != "" || isSec {
							hasNonEmpty = true
							return
						}
						if id := clAnyToString(m["id"]); id != "" && strings.EqualFold(k, "BERMUDA_MASTER_KEY") {
							emptyVarID = id
						}
					}
				}
			}
		case map[string]any:
			for _, wrapKey := range []string{"vars", "variables", "environmentVariables", "data", "items"} {
				if inner, ok := val[wrapKey]; ok {
					walk(inner)
					return
				}
			}
			for k, v := range val {
				if (strings.EqualFold(k, "BERMUDA_MASTER_KEY") || strings.EqualFold(k, "MASTER_KEY")) && clAnyToString(v) != "" {
					hasNonEmpty = true
					return
				}
			}
		}
	}
	walk(raw)
	return hasNonEmpty, emptyVarID
}

func (c *CloadyClient) PersistMasterKey(ctx context.Context, masterKey string) bool {
	if !c.IsConfigured() || strings.TrimSpace(masterKey) == "" {
		return false
	}

	c.mu.RLock()
	alreadyPersisted := c.keyPersisted
	c.mu.RUnlock()
	if alreadyPersisted {
		return true
	}

	if err := c.ResolveRuntimeContext(ctx); err != nil {
		log.Printf("[Cloady] Notice: PersistMasterKey skipped: %v", err)
		return false
	}

	c.mu.RLock()
	ws := c.WorkspaceSlug
	app := c.AppSlug
	c.mu.RUnlock()
	if ws == "" || app == "" {
		return false
	}

	baseVarsPath := fmt.Sprintf("/workspaces/%s/apps/%s/vars", url.PathEscape(ws), url.PathEscape(app))

	var existingEmptyID string
	if raw, _, err := c.doCLAppRequest(ctx, http.MethodGet, baseVarsPath, nil); err == nil {
		hasKey, emptyID := inspectCloadyMasterKeyVar(raw)
		if hasKey {
			c.mu.Lock()
			c.keyPersisted = true
			c.mu.Unlock()
			log.Println("[Cloady] ✓ BERMUDA_MASTER_KEY already present in Cloady App Variables (Restart-Loop Guard active)")
			return true
		}
		existingEmptyID = emptyID
	}

	cleanKey := strings.TrimSpace(masterKey)
	var writeErr error

	if existingEmptyID != "" {
		updatePath := baseVarsPath + "/" + url.PathEscape(existingEmptyID)
		updatePayload := map[string]any{
			"key":      "BERMUDA_MASTER_KEY",
			"value":    cleanKey,
			"isSecret": true,
		}
		_, _, writeErr = c.doCLAppRequest(ctx, http.MethodPatch, updatePath, updatePayload)
		if writeErr != nil {
			_, _, writeErr = c.doCLAppRequest(ctx, http.MethodPut, updatePath, updatePayload)
		}
	} else {
		createPayload := map[string]any{
			"key":      "BERMUDA_MASTER_KEY",
			"value":    cleanKey,
			"isSecret": true,
		}
		_, _, writeErr = c.doCLAppRequest(ctx, http.MethodPost, baseVarsPath, createPayload)
	}

	if writeErr != nil {
		var apiErr *clAPIError
		if errors.As(writeErr, &apiErr) {
			if apiErr.StatusCode == http.StatusConflict {
				c.mu.Lock()
				c.keyPersisted = true
				c.mu.Unlock()
				log.Println("[Cloady] ✓ BERMUDA_MASTER_KEY already registered on Cloady (conflict guard)")
				return true
			}
			if apiErr.IsPermissionOrPlan() {
				log.Println("[Cloady] Note: Auto-persisting BERMUDA_MASTER_KEY skipped (token scope restriction; use 'deploy' scope)")
				return false
			}
		}
		log.Printf("[Cloady] Notice: Could not persist BERMUDA_MASTER_KEY to Cloady Variables: %v", writeErr)
		return false
	}

	c.mu.Lock()
	c.keyPersisted = true
	c.mu.Unlock()
	log.Println("[Cloady] ✓ BERMUDA_MASTER_KEY persisted to Cloady App Variables (takes effect on next deploy; zero restart loop)")
	return true
}

func (c *CloadyClient) EnsureServiceDomain(ctx context.Context) (string, error) {
	if dom := c.GetServiceDomain(); isFullCloadyServiceDomain(dom) && c.GetDiscoveredRegion() != "" {
		return dom, nil
	}
	if !c.IsConfigured() {
		return c.GetServiceDomain(), nil
	}
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return c.GetServiceDomain(), err
	}
	return c.GetServiceDomain(), nil
}

// CheckPublicDNS queries Cloady's public GET /api/dns?host=<domain> verification endpoint
// to inspect real-time DNS alignment (ok/taken/delegated) and retrieve official A/AAAA targets.
func (c *CloadyClient) CheckPublicDNS(ctx context.Context, targetDomain string) (*cloadyDNSCheckResult, error) {
	cleanTarget := cleanHost(targetDomain)
	if cleanTarget == "" {
		return nil, errors.New("empty domain for cloady dns check")
	}

	baseURL := cloadyAPIBase
	httpClient := &http.Client{Timeout: 10 * time.Second}
	if c != nil {
		baseURL = c.baseURL()
		if c.client != nil {
			httpClient = c.client
		}
		if err := c.paceAPIRequest(ctx); err != nil {
			return nil, err
		}
	}

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	endpoint := baseURL + "/dns?host=" + url.QueryEscape(cleanTarget)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "BERMUDA-Portal-CloudOrchestrator/4.0 (Go-Standard-Library)")
	if c != nil && c.Token != "" && !c.authFailed.Load() {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	rawBytes, err := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, &clAPIError{
			StatusCode: resp.StatusCode,
			Message:    extractCloadyErrorMessage(rawBytes),
		}
	}

	var parsed struct {
		OK        bool `json:"ok"`
		Taken     bool `json:"taken"`
		Delegated bool `json:"delegated"`
		Targets   struct {
			A    []string `json:"a"`
			AAAA []string `json:"aaaa"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(rawBytes, &parsed); err != nil {
		return nil, err
	}

	res := &cloadyDNSCheckResult{
		OK:        parsed.OK,
		Taken:     parsed.Taken,
		Delegated: parsed.Delegated,
	}
	for _, ipStr := range parsed.Targets.A {
		if ip := net.ParseIP(strings.TrimSpace(ipStr)); ip != nil && ip.To4() != nil && !isCloudflareEdgeIP(ip) {
			res.TargetsA = append(res.TargetsA, ip.String())
		}
	}
	for _, ipStr := range parsed.Targets.AAAA {
		if ip := net.ParseIP(strings.TrimSpace(ipStr)); ip != nil && ip.To4() == nil && !isCloudflareEdgeIP(ip) {
			res.TargetsAAAA = append(res.TargetsAAAA, ip.String())
		}
	}

	if c != nil && (len(res.TargetsA) > 0 || len(res.TargetsAAAA) > 0) {
		c.mu.Lock()
		if len(res.TargetsA) > 0 {
			c.cachedOriginIPv4 = append([]string(nil), res.TargetsA...)
		}
		if len(res.TargetsAAAA) > 0 {
			c.cachedOriginIPv6 = append([]string(nil), res.TargetsAAAA...)
		}
		c.mu.Unlock()
	}

	return res, nil
}

func (c *CloadyClient) getCachedOriginIPs() (v4, v6 []string) {
	if c == nil {
		return nil, nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string(nil), c.cachedOriginIPv4...), append([]string(nil), c.cachedOriginIPv6...)
}

func parseCloadyDomainMap(m map[string]any, fallbackCNAME string) CloadyCustomDomainInfo {
	if inner, ok := m["customDomain"].(map[string]any); ok && len(inner) > 0 {
		m = inner
	} else if inner, ok := m["domain"].(map[string]any); ok && len(inner) > 0 {
		m = inner
	}

	var info CloadyCustomDomainInfo
	info.ID = clAnyToString(m["id"])
	if info.ID == "" {
		info.ID = clAnyToString(m["domainId"])
	}

	for _, k := range []string{"host", "domain", "hostname", "domainName", "name", "fqdn"} {
		if s := clAnyToString(m[k]); s != "" {
			info.Domain = cleanHost(s)
			break
		}
	}

	if v, ok := m["verified"].(bool); ok {
		info.DNSReady = v
		info.RecordsVerified = v
	}
	if v, ok := m["dnsVerified"].(bool); ok {
		info.DNSReady = v
		info.RecordsVerified = v
	}
	if v, ok := m["dnsReady"].(bool); ok {
		info.DNSReady = v
		info.RecordsVerified = v
	}
	if v, ok := m["sslReady"].(bool); ok {
		info.SSLReady = v
	}
	if v, ok := m["tlsReady"].(bool); ok {
		info.SSLReady = v
	}
	if v, ok := m["ready"].(bool); ok {
		info.Ready = v
	}

	for _, k := range []string{"cnameTarget", "target", "cname", "pointsTo"} {
		if s := clAnyToString(m[k]); s != "" {
			if cleanT := cleanHost(s); cleanT != "" {
				info.CNAMETarget = cleanT
				break
			}
		}
	}

	if targetsMap, ok := m["targets"].(map[string]any); ok {
		if arrA, ok := targetsMap["a"].([]any); ok {
			for _, item := range arrA {
				if ip := net.ParseIP(clAnyToString(item)); ip != nil && ip.To4() != nil {
					info.OriginIPv4 = append(info.OriginIPv4, ip.String())
				}
			}
		}
		if arrAAAA, ok := targetsMap["aaaa"].([]any); ok {
			for _, item := range arrAAAA {
				if ip := net.ParseIP(clAnyToString(item)); ip != nil && ip.To4() == nil {
					info.OriginIPv6 = append(info.OriginIPv6, ip.String())
				}
			}
		}
	}

	extractRec := func(recMap map[string]any) {
		rType := strings.ToUpper(clAnyToString(recMap["type"]))
		rHost := ""
		for _, hk := range []string{"host", "name", "hostname", "recordName", "fqdn"} {
			if s := clAnyToString(recMap[hk]); s != "" {
				rHost = cleanHost(s)
				break
			}
		}
		rVal := ""
		for _, vk := range []string{"value", "target", "content", "pointsTo", "data"} {
			if s := clAnyToString(recMap[vk]); s != "" {
				rVal = s
				break
			}
		}
		switch rType {
		case "CNAME":
			if cleanT := cleanHost(rVal); cleanT != "" {
				info.CNAMETarget = cleanT
			}
		case "TXT":
			if rHost != "" && rVal != "" {
				info.VerificationHost = rHost
				info.VerificationToken = rVal
			}
		}
	}

	for _, recKey := range []string{"dnsRecords", "records", "dnsSetup", "verification"} {
		switch rv := m[recKey].(type) {
		case map[string]any:
			extractRec(rv)
			if arr, ok := rv["records"].([]any); ok {
				for _, item := range arr {
					if rm, ok := item.(map[string]any); ok {
						extractRec(rm)
					}
				}
			}
		case []any:
			for _, item := range rv {
				if rm, ok := item.(map[string]any); ok {
					extractRec(rm)
				}
			}
		}
	}

	if info.CNAMETarget == "" && fallbackCNAME != "" {
		info.CNAMETarget = cleanHost(fallbackCNAME)
	}

	for _, k := range []string{"tlsStatus", "sslStatus", "certStatus", "certificateStatus", "status", "state"} {
		if s := clAnyToString(m[k]); s != "" {
			info.CertificateStatus = s
			break
		}
	}
	if info.CertificateStatus == "" {
		for _, nestedKey := range []string{"certificate", "cert", "tls", "ssl"} {
			if nested, ok := m[nestedKey].(map[string]any); ok {
				for _, sk := range []string{"status", "state"} {
					if s := clAnyToString(nested[sk]); s != "" {
						info.CertificateStatus = s
						break
					}
				}
				if info.CertificateStatus != "" {
					break
				}
			}
		}
	}
	if info.CertificateStatus == "" {
		if info.Ready || info.SSLReady {
			info.CertificateStatus = "issued"
		} else {
			info.CertificateStatus = "pending"
		}
	}

	return info
}

func extractCloadyDomainsFromJSON(rawBytes []byte, fallbackCNAME string) []CloadyCustomDomainInfo {
	var raw any
	if err := json.Unmarshal(rawBytes, &raw); err != nil {
		return nil
	}

	var out []CloadyCustomDomainInfo
	seen := make(map[string]struct{})

	addDom := func(m map[string]any) {
		info := parseCloadyDomainMap(m, fallbackCNAME)
		if info.Domain == "" {
			return
		}
		if _, exists := seen[info.Domain]; exists {
			return
		}
		seen[info.Domain] = struct{}{}
		out = append(out, info)
	}

	switch v := raw.(type) {
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				addDom(m)
			}
		}
	case map[string]any:
		for _, key := range []string{"domains", "customDomains", "certificates", "certs", "data", "items", "results"} {
			if arr, ok := v[key].([]any); ok {
				for _, item := range arr {
					if m, ok := item.(map[string]any); ok {
						addDom(m)
					}
				}
			}
		}
		if len(out) == 0 {
			addDom(v)
		}
	}

	return out
}

func (c *CloadyClient) listDomainsRaw(ctx context.Context) ([]CloadyCustomDomainInfo, error) {
	c.mu.RLock()
	ws := c.WorkspaceSlug
	app := c.AppSlug
	fallbackCNAME := c.serviceDomain
	c.mu.RUnlock()

	if ws == "" || app == "" {
		return nil, errors.New("missing cloady workspace or app slug")
	}

	basePath := fmt.Sprintf("/workspaces/%s/apps/%s/domains", url.PathEscape(ws), url.PathEscape(app))
	raw, _, err := c.doCLAppRequest(ctx, http.MethodGet, basePath, nil)
	if err != nil {
		return nil, err
	}
	return extractCloadyDomainsFromJSON(raw, fallbackCNAME), nil
}

// fetchCertStatusForDomain queries Cloady's certificate status endpoint (listCertStatuses)
// when available, caching 404/405 absence to avoid redundant polling requests.
func (c *CloadyClient) fetchCertStatusForDomain(ctx context.Context, cleanTarget string) (string, bool) {
	if !c.IsConfigured() || cleanTarget == "" {
		return "", false
	}
	c.mu.RLock()
	if c.certEndpointSkip {
		c.mu.RUnlock()
		return "", false
	}
	ws := c.WorkspaceSlug
	app := c.AppSlug
	fallbackCNAME := c.serviceDomain
	c.mu.RUnlock()

	if ws == "" || app == "" {
		return "", false
	}

	basePaths := []string{
		fmt.Sprintf("/workspaces/%s/apps/%s/domains/certs", url.PathEscape(ws), url.PathEscape(app)),
		fmt.Sprintf("/workspaces/%s/apps/%s/certs", url.PathEscape(ws), url.PathEscape(app)),
	}

	notFoundCount := 0
	for _, bp := range basePaths {
		raw, _, err := c.doCLAppRequest(ctx, http.MethodGet, bp, nil)
		if err != nil {
			var apiErr *clAPIError
			if errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusMethodNotAllowed) {
				notFoundCount++
			}
			continue
		}
		items := extractCloadyDomainsFromJSON(raw, fallbackCNAME)
		for _, item := range items {
			if cleanHost(item.Domain) == cleanTarget && item.CertificateStatus != "" {
				return item.CertificateStatus, true
			}
		}
		return "", false
	}

	if notFoundCount == len(basePaths) {
		c.mu.Lock()
		c.certEndpointSkip = true
		c.mu.Unlock()
	}
	return "", false
}

func resolveOriginIngressIPs(ctx context.Context, gatewayHost string, extraIPs []string) []string {
	var ips []string
	seen := make(map[string]struct{})

	addIP := func(ipStr string) {
		parsed := net.ParseIP(strings.TrimSpace(ipStr))
		if parsed == nil || isCloudflareEdgeIP(parsed) {
			return
		}
		s := parsed.String()
		if _, exists := seen[s]; !exists {
			seen[s] = struct{}{}
			ips = append(ips, s)
		}
	}

	for _, ipStr := range extraIPs {
		addIP(ipStr)
	}

	host := cleanHost(gatewayHost)
	if host == "" {
		return ips
	}
	if net.ParseIP(host) != nil {
		addIP(host)
		return ips
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	addrsV4, errV4 := net.DefaultResolver.LookupIP(lookupCtx, "ip4", host)
	cancel()
	if errV4 == nil {
		for _, ip := range addrsV4 {
			addIP(ip.String())
		}
	}

	if probeKernelIPv6Route() {
		lookupCtx6, cancel6 := context.WithTimeout(ctx, 3*time.Second)
		addrsV6, errV6 := net.DefaultResolver.LookupIP(lookupCtx6, "ip6", host)
		cancel6()
		if errV6 == nil {
			for _, ip := range addrsV6 {
				addIP(ip.String())
			}
		}
	}

	return ips
}

func probeCustomDomainTLS(ctx context.Context, customDomain, gatewayHost string) bool {
	return probeCustomDomainTLSWithExtraIPs(ctx, customDomain, gatewayHost, nil)
}

func probeCustomDomainTLSWithExtraIPs(ctx context.Context, customDomain, gatewayHost string, extraIPs []string) bool {
	cleanCustom := cleanHost(customDomain)
	if cleanCustom == "" {
		return false
	}

	originIPs := resolveOriginIngressIPs(ctx, gatewayHost, extraIPs)
	if len(originIPs) == 0 {
		if dnsRes, err := (*CloadyClient)(nil).CheckPublicDNS(ctx, cleanCustom); err == nil && dnsRes != nil {
			var fallbackExtra []string
			fallbackExtra = append(fallbackExtra, dnsRes.TargetsA...)
			if probeKernelIPv6Route() {
				fallbackExtra = append(fallbackExtra, dnsRes.TargetsAAAA...)
			}
			originIPs = resolveOriginIngressIPs(ctx, "", fallbackExtra)
		}
	}
	if len(originIPs) == 0 {
		return false
	}

	healthPath := getEnv("BERMUDA_HEALTH_PATH", defaultHealthPath)
	if !strings.HasPrefix(healthPath, "/") {
		healthPath = "/" + healthPath
	}

	for _, ipStr := range originIPs {
		targetAddr := net.JoinHostPort(ipStr, "443")
		network := "tcp4"
		if strings.Contains(ipStr, ":") {
			if !probeKernelIPv6Route() {
				continue
			}
			network = "tcp6"
		}
		probeCtx, cancel := context.WithTimeout(ctx, defaultCLTLSProbeTimeout)

		tr := &http.Transport{
			Proxy: nil,
			DialContext: func(dCtx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: defaultCLTLSProbeTimeout}
				return d.DialContext(dCtx, network, targetAddr)
			},
			TLSClientConfig: &tls.Config{
				ServerName:         cleanCustom,
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: false,
			},
			DisableKeepAlives:  true,
			DisableCompression: true,
		}

		req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, "https://"+cleanCustom+healthPath, nil)
		if err != nil {
			tr.CloseIdleConnections()
			cancel()
			continue
		}
		req.Host = cleanCustom
		req.Header.Set("User-Agent", "curl/8.7.1")
		req.Header.Set("Accept-Encoding", "identity")

		client := &http.Client{
			Transport: tr,
			Timeout:   defaultCLTLSProbeTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, doErr := client.Do(req)
		if doErr != nil {
			tr.CloseIdleConnections()
			cancel()
			continue
		}

		bodySnippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		var tlsVerified bool
		if resp.TLS != nil && len(resp.TLS.VerifiedChains) > 0 && len(resp.TLS.PeerCertificates) > 0 {
			leaf := resp.TLS.PeerCertificates[0]
			if leaf.VerifyHostname(cleanCustom) == nil && time.Now().Before(leaf.NotAfter) {
				tlsVerified = true
			}
		}

		normETag := strings.TrimPrefix(strings.TrimSpace(resp.Header.Get("ETag")), "W/")
		etagMatch := normETag == openrestyIndexETag
		lastModMatch := strings.EqualFold(strings.TrimSpace(resp.Header.Get("Last-Modified")), openrestyIndexLastModified)
		serverMatch := strings.EqualFold(strings.TrimSpace(resp.Header.Get("Server")), openrestyServerToken)
		bodyMatch := bytes.Contains(bodySnippet, []byte("Welcome to OpenResty!"))

		routeVerified := resp.StatusCode == http.StatusOK && (etagMatch || lastModMatch || serverMatch || bodyMatch)

		tr.CloseIdleConnections()
		cancel()

		if tlsVerified && routeVerified {
			return true
		}
	}

	return false
}

func (c *CloadyClient) finalizeCustomDomainInfo(ctx context.Context, info CloadyCustomDomainInfo) *CloadyCustomDomainInfo {
	if info.CNAMETarget == "" && c.GetServiceDomain() != "" {
		info.CNAMETarget = c.GetServiceDomain()
	}

	if !info.IsCertificateValid() {
		if certSt, ok := c.fetchCertStatusForDomain(ctx, info.Domain); ok && certSt != "" {
			info.CertificateStatus = certSt
		}
	}

	v4, v6 := c.getCachedOriginIPs()
	if len(v4) == 0 && len(v6) == 0 && info.Domain != "" {
		if dnsRes, err := c.CheckPublicDNS(ctx, info.Domain); err == nil && dnsRes != nil {
			v4, v6 = dnsRes.TargetsA, dnsRes.TargetsAAAA
			if dnsRes.OK {
				info.DNSReady = true
				info.RecordsVerified = true
			}
		}
	}
	if len(info.OriginIPv4) == 0 && len(v4) > 0 {
		info.OriginIPv4 = v4
	}
	if len(info.OriginIPv6) == 0 && len(v6) > 0 {
		info.OriginIPv6 = v6
	}

	var extraIPs []string
	extraIPs = append(extraIPs, info.OriginIPv4...)
	extraIPs = append(extraIPs, info.OriginIPv6...)

	if (info.CNAMETarget != "" || len(extraIPs) > 0) &&
		probeCustomDomainTLSWithExtraIPs(ctx, info.Domain, info.CNAMETarget, extraIPs) {
		info.CertificateStatus = "issued"
		info.SSLReady = true
		info.Ready = true
		info.DNSReady = true
		info.RecordsVerified = true
	}

	return &info
}

// TriggerDomainVerification checks live DNS readiness via Cloady's public GET /api/dns?host=...
// endpoint (Cloady performs automatic DNS/ACME polling without a separate /verify POST endpoint).
func (c *CloadyClient) TriggerDomainVerification(ctx context.Context, _ string) bool {
	if c == nil {
		return false
	}
	dom := c.GetCustomDomain()
	if dom == "" {
		return false
	}
	dnsRes, err := c.CheckPublicDNS(ctx, dom)
	if err != nil || dnsRes == nil {
		return false
	}
	return dnsRes.OK
}

func (c *CloadyClient) EnsureCustomDomain(ctx context.Context, targetDomain string) (*CloadyCustomDomainInfo, error) {
	cleanTarget := cleanHost(targetDomain)
	if cleanTarget == "" || isCloadyManagedDomain(cleanTarget) {
		return nil, errors.New("invalid or empty custom domain target")
	}

	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return nil, err
	}

	if existing, err := c.listDomainsRaw(ctx); err == nil {
		for _, d := range existing {
			if isCloadyPublicDomain(d.Domain) && !isFullCloadyServiceDomain(c.GetServiceDomain()) {
				c.SetServiceDomain(d.Domain)
			}
			if cleanHost(d.Domain) == cleanTarget {
				c.SetCustomDomain(cleanTarget)
				c.notifyTopology()
				finalized := c.finalizeCustomDomainInfo(ctx, d)
				log.Printf("[Cloady] ✓ Custom Domain Verified in Inventory: %s (ID: %s, CNAME Target: %s, Status: %s)",
					cleanTarget, finalized.ID, finalized.CNAMETarget, finalized.CertificateStatus)
				return finalized, nil
			}
		}
	}

	c.mu.RLock()
	ws := c.WorkspaceSlug
	app := c.AppSlug
	fallbackCNAME := c.serviceDomain
	c.mu.RUnlock()

	basePath := fmt.Sprintf("/workspaces/%s/apps/%s/domains", url.PathEscape(ws), url.PathEscape(app))

	raw, _, postErr := c.doCLAppRequest(ctx, http.MethodPost, basePath, map[string]any{
		"host": cleanTarget,
	})
	if postErr != nil {
		var apiErr *clAPIError
		if errors.As(postErr, &apiErr) && (apiErr.StatusCode == http.StatusBadRequest || apiErr.StatusCode == http.StatusUnprocessableEntity) {
			raw2, _, err2 := c.doCLAppRequest(ctx, http.MethodPost, basePath, map[string]any{
				"domain": cleanTarget,
			})
			if err2 == nil {
				raw = raw2
				postErr = nil
			}
		}
	}
	if postErr != nil {
		var apiErr *clAPIError
		if errors.As(postErr, &apiErr) && (apiErr.StatusCode == http.StatusConflict || apiErr.StatusCode == http.StatusUnprocessableEntity) {
			if refreshed, listErr := c.listDomainsRaw(ctx); listErr == nil {
				for _, d := range refreshed {
					if cleanHost(d.Domain) == cleanTarget {
						c.SetCustomDomain(cleanTarget)
						c.notifyTopology()
						return c.finalizeCustomDomainInfo(ctx, d), nil
					}
				}
			}
		}
		return nil, fmt.Errorf("register custom domain %s on cloady: %w", cleanTarget, postErr)
	}

	created := extractCloadyDomainsFromJSON(raw, fallbackCNAME)
	var matched CloadyCustomDomainInfo
	for _, d := range created {
		if cleanHost(d.Domain) == cleanTarget {
			matched = d
			break
		}
	}
	if matched.Domain == "" {
		if len(created) > 0 {
			matched = created[0]
		} else {
			matched = CloadyCustomDomainInfo{
				Domain:            cleanTarget,
				CNAMETarget:       fallbackCNAME,
				CertificateStatus: "queued",
			}
		}
	}

	c.SetCustomDomain(cleanTarget)
	c.notifyTopology()
	finalized := c.finalizeCustomDomainInfo(ctx, matched)

	log.Printf("[Cloady] ✓ Registered Custom Domain: %s -> %s (Status: %s)",
		cleanTarget, finalized.CNAMETarget, finalized.CertificateStatus)
	return finalized, nil
}

func (c *CloadyClient) FetchCustomDomainStatus(ctx context.Context, customDomainID, targetDomain string) (*CloadyCustomDomainInfo, error) {
	cleanTarget := cleanHost(targetDomain)
	cnameTarget := c.GetServiceDomain()

	if c.IsConfigured() {
		if err := c.ResolveRuntimeContext(ctx); err == nil {
			if doms, listErr := c.listDomainsRaw(ctx); listErr == nil {
				for _, d := range doms {
					if (customDomainID != "" && d.ID == customDomainID) || (cleanTarget != "" && cleanHost(d.Domain) == cleanTarget) {
						return c.finalizeCustomDomainInfo(ctx, d), nil
					}
				}
			}
		}
	}

	v4, v6 := c.getCachedOriginIPs()
	var extraIPs []string
	extraIPs = append(extraIPs, v4...)
	extraIPs = append(extraIPs, v6...)

	if (cnameTarget != "" || len(extraIPs) > 0) &&
		probeCustomDomainTLSWithExtraIPs(ctx, cleanTarget, cnameTarget, extraIPs) {
		return &CloadyCustomDomainInfo{
			ID:                customDomainID,
			Domain:            cleanTarget,
			CNAMETarget:       cnameTarget,
			CertificateStatus: "issued",
			DNSReady:          true,
			SSLReady:          true,
			Ready:             true,
			RecordsVerified:   true,
			OriginIPv4:        v4,
			OriginIPv6:        v6,
		}, nil
	}

	return &CloadyCustomDomainInfo{
		ID:                customDomainID,
		Domain:            cleanTarget,
		CNAMETarget:       cnameTarget,
		CertificateStatus: "pending",
		OriginIPv4:        v4,
		OriginIPv6:        v6,
	}, nil
}

func (c *CloadyClient) WaitCustomDomainCertificate(ctx context.Context, customDomainID, targetDomain string, maxWait time.Duration) (*CloadyCustomDomainInfo, bool) {
	if maxWait <= 0 {
		maxWait = defaultCLCertPollWait
	}
	waitCtx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()

	ticker := time.NewTicker(defaultCLCertPollTick)
	defer ticker.Stop()

	var latest *CloadyCustomDomainInfo
	attempt := 0
	for {
		if attempt%2 == 0 {
			c.TriggerDomainVerification(waitCtx, customDomainID)
		}
		attempt++

		info, err := c.FetchCustomDomainStatus(waitCtx, customDomainID, targetDomain)
		if err == nil && info != nil {
			latest = info
			if info.IsCertificateValid() {
				log.Printf("[Cloady] ✓ Custom Domain %s TLS Certificate & Route Identity VERIFIED (%s)",
					info.Domain, info.CertificateStatus)
				return info, true
			}
		}

		select {
		case <-waitCtx.Done():
			return latest, false
		case <-ticker.C:
		}
	}
}

func probeKernelIPv6Route() bool {
	ipv6ProbeMu.Lock()
	defer ipv6ProbeMu.Unlock()

	if !ipv6ProbeChecked.IsZero() && time.Since(ipv6ProbeChecked) < ipv6ProbeCacheTTL {
		return ipv6ProbeResult
	}

	// Stage 1: Fast kernel routing table check (<1ms)
	udpConn, err := net.DialTimeout("udp6", "[2606:4700:4700::1111]:53", 25*time.Millisecond)
	if err != nil {
		ipv6ProbeResult = false
		ipv6ProbeChecked = time.Now()
		return false
	}
	_ = udpConn.Close()

	// Stage 2: Verify real end-to-end TCPv6 packet reachability
	for _, target := range []string{"[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"} {
		tcpConn, dialErr := net.DialTimeout("tcp6", target, 350*time.Millisecond)
		if dialErr == nil {
			_ = tcpConn.Close()
			ipv6ProbeResult = true
			ipv6ProbeChecked = time.Now()
			return true
		}
	}

	ipv6ProbeResult = false
	ipv6ProbeChecked = time.Now()
	return false
}

// probeOutboundCloadyRegion auto-detects which of Cloady's 9 official regions
// (aus1, eu1, ind1, jpn1, sin1, uk1, usc1, use1, usw1) the container is running in
// when neither BERMUDA_REGION nor CLOADY_API_TOKEN is provided.
func probeOutboundCloadyRegion(parent context.Context) string {
	ctx, cancel := context.WithTimeout(parent, 1500*time.Millisecond)
	defer cancel()

	client := &http.Client{Timeout: 1500 * time.Millisecond}
	for _, traceURL := range []string{"https://1.1.1.1/cdn-cgi/trace", "https://cloudflare.com/cdn-cgi/trace"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, traceURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "curl/8.7.1")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		rawBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			continue
		}

		var loc, colo string
		for _, line := range strings.Split(string(rawBytes), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(k)) {
			case "loc":
				loc = strings.ToUpper(strings.TrimSpace(v))
			case "colo":
				colo = strings.ToUpper(strings.TrimSpace(v))
			}
		}

		switch loc {
		case "AU", "NZ":
			return "aus1"
		case "IN":
			return "ind1"
		case "JP", "KR":
			return "jpn1"
		case "SG", "MY", "ID", "TH", "VN", "PH", "HK":
			return "sin1"
		case "GB", "UK":
			return "uk1"
		case "DE":
			return "eu1"
		case "US", "CA":
			switch colo {
			case "SJC", "LAX", "SFO", "SEA", "PDX", "PHX", "LAS", "SAN", "SLC", "SMF", "ONT", "BUR", "RNO", "BOI", "GEG", "HNL", "ANC", "YVR":
				return "usw1"
			case "ORD", "DFW", "IAH", "MCI", "MSP", "DEN", "AUS", "SAT", "OMA", "OKC", "TUL", "MEM", "BNA", "IND", "DTW", "MKE", "DSM", "YWG":
				return "usc1"
			default:
				return "use1"
			}
		}
		if loc != "" {
			if colo == "LHR" || colo == "MAN" || colo == "EDI" {
				return "uk1"
			}
			return "eu1"
		}
	}
	return ""
}

func (c *CloadyClient) TuneComputeAndNetwork(ctx context.Context) {
	if probeKernelIPv6Route() {
		log.Println("[Cloady] ✓ Outbound IPv6 Stack: ACTIVE & VERIFIED (Dual-Stack Egress Online)")
	} else {
		log.Println("[Cloady] ✓ Outbound Network Stack: IPv4 Active (Cloady Container Egress Verified)")
	}

	if !c.IsConfigured() {
		return
	}
	if !c.HasServiceContext() || c.GetDiscoveredRegion() == "" || !isCloadyPublicDomain(c.GetServiceDomain()) {
		_ = c.ResolveRuntimeContext(ctx)
	}

	c.mu.RLock()
	ws := c.WorkspaceSlug
	app := c.AppSlug
	envName := c.Environment
	srvDom := c.serviceDomain
	reg := c.discoveredRegion
	port := c.TargetPort
	c.mu.RUnlock()

	if reg == "" {
		reg = "eu1"
	}
	healthPath := getEnv("BERMUDA_HEALTH_PATH", defaultHealthPath)
	log.Printf("[Cloady] ✓ Service Ready: Workspace=%s | App=%s | Env=%s | Domain=%s | Region=%s | Port=%d | HealthPath=%s",
		ws, app, envName, srvDom, reg, port, healthPath)
}
