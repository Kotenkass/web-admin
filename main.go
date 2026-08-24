package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/sony/gobreaker"
	"web-admin/internal/templ"
)

const (
	tokenTTL        = 15 * time.Minute
	sessionTTL      = time.Hour
	upstreamTimeout = 3 * time.Second
)

type Config struct {
	Addr               string
	RedisAddr          string
	RedisPassword      string
	SessionKey         string
	SessionKeyPrevious string
	UsersURL           string
	AnalyticsURL       string
}

type App struct {
	cfg              Config
	redis            *redis.Client
	sessionKey       []byte
	sessionKeyPrev   []byte
	usersClient      *upstreamClient
	analytics        *upstreamClient
	usersBreaker     *gobreaker.CircuitBreaker
	analyticsBreaker *gobreaker.CircuitBreaker
	metrics          *metrics
}

type metrics struct {
	tokenRequests       prometheus.Counter
	tokenErrors         prometheus.Counter
	tokenConsumed       prometheus.Counter
	telegramPreviewSkip prometheus.Counter
	httpsRejected       prometheus.Counter
	internalRejected    prometheus.Counter
	sessionCreated      prometheus.Counter
	sessionMissing      prometheus.Counter
	sessionInvalid      prometheus.Counter
	profileCalls        prometheus.Counter
	analyticsCalls      prometheus.Counter
	upstreamErrors      prometheus.Counter
}

type upstreamClient struct {
	name    string
	baseURL string
	client  *http.Client
}

type tokenRequest struct {
	ChatID int64 `json:"chat_id"`
}

type tokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

func main() {
	cfg := Config{
		Addr:               env("ADDR", ":8080"),
		RedisAddr:          env("REDIS_ADDR", "localhost:6379"),
		RedisPassword:      env("REDIS_PASSWORD", ""),
		SessionKey:         env("SESSION_KEY", ""),
		SessionKeyPrevious: env("SESSION_KEY_PREVIOUS", ""),
		UsersURL:           strings.TrimRight(env("USERS_URL", "http://users-service:8080"), "/"),
		AnalyticsURL:       strings.TrimRight(env("ANALYTICS_URL", "http://analytics-service:8080"), "/"),
	}

	if cfg.SessionKey == "" {
		log.Fatal("SESSION_KEY is required")
	}

	sessionKey := sha256.Sum256([]byte(cfg.SessionKey))
	var sessionKeyPrev []byte
	if cfg.SessionKeyPrevious != "" {
		prev := sha256.Sum256([]byte(cfg.SessionKeyPrevious))
		sessionKeyPrev = prev[:]
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
	})

	app := &App{
		cfg:              cfg,
		redis:            rdb,
		sessionKey:       sessionKey[:],
		sessionKeyPrev:   sessionKeyPrev,
		usersClient:      newUpstreamClient("users", cfg.UsersURL),
		analytics:        newUpstreamClient("analytics", cfg.AnalyticsURL),
		usersBreaker:     gobreaker.NewCircuitBreaker(gobreaker.Settings{Name: "users", Timeout: 10 * time.Second}),
		analyticsBreaker: gobreaker.NewCircuitBreaker(gobreaker.Settings{Name: "analytics", Timeout: 10 * time.Second}),
		metrics:          newMetrics(),
	}
	app.metrics.mustRegister()

	e := echo.New()
	e.HideBanner = true
	e.HTTPErrorHandler = jsonHTTPError
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())
	e.Use(requireInternalNetwork(app))
	e.Use(requireForwardedProtoHTTPS(app))
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{Format: "${time_rfc3339} ${status} ${method} ${uri} ${latency}\n"}))

	e.GET("/healthz", healthz(rdb))
	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()))

	e.POST("/internal/token", app.createToken)
	e.GET("/c/:token", app.consumeToken)
	e.GET("/", app.dashboard)

	log.Printf("web-admin listening on %s", cfg.Addr)
	if err := e.Start(cfg.Addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func healthz(rdb *redis.Client) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx, cancel := context.WithTimeout(c.Request().Context(), 2*time.Second)
		defer cancel()
		if err := rdb.Ping(ctx).Err(); err != nil {
			return c.JSON(http.StatusServiceUnavailable, map[string]any{"status": "error", "redis": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	}
}

func (a *App) createToken(c echo.Context) error {
	var req tokenRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid json"})
	}
	if req.ChatID == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "chat_id is required"})
	}

	a.metrics.tokenRequests.Inc()

	token, err := randomBase64URL(32)
	if err != nil {
		a.metrics.tokenErrors.Inc()
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to generate token"})
	}

	ctx, cancel := context.WithTimeout(c.Request().Context(), upstreamTimeout)
	defer cancel()

	key := tokenKey(token)
	if err := a.redis.Set(ctx, key, req.ChatID, tokenTTL).Err(); err != nil {
		a.metrics.tokenErrors.Inc()
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "redis unavailable"})
	}

	return c.JSON(http.StatusCreated, tokenResponse{
		Token:     token,
		ExpiresAt: time.Now().Add(tokenTTL).Unix(),
	})
}

func (a *App) consumeToken(c echo.Context) error {
	token := c.Param("token")
	tokenDigest := tokenHash(token)
	if isTelegramPreviewRequest(c.Request()) {
		a.metrics.telegramPreviewSkip.Inc()
		log.Printf("telegram preview skipped: token_hash=%s remote=%s client=%s user_agent=%q", tokenDigest, clientIP(c.Request()), peerIP(c.Request()), c.Request().UserAgent())
		return c.String(http.StatusAccepted, "Telegram preview detected. Open the link in your browser.")
	}

	ctx, cancel := context.WithTimeout(c.Request().Context(), upstreamTimeout)
	defer cancel()

	key := tokenKey(token)
	var chatID int64
	if err := a.redis.Get(ctx, key).Scan(&chatID); err != nil {
		if errors.Is(err, redis.Nil) {
			log.Printf("consume token failed: token_hash=%s reason=missing_or_expired remote=%s client=%s user_agent=%q", tokenDigest, clientIP(c.Request()), peerIP(c.Request()), c.Request().UserAgent())
			return c.String(http.StatusGone, "Cabinet link has already been used. Open it again from Telegram.")
		}
		log.Printf("consume token redis error: token_hash=%s error=%q remote=%s client=%s", tokenDigest, err.Error(), clientIP(c.Request()), peerIP(c.Request()))
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "redis unavailable"})
	}

	if err := a.redis.Del(ctx, key).Err(); err != nil {
		log.Printf("consume token delete failed: token_hash=%s chat_id=%d error=%q", tokenDigest, chatID, err.Error())
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "redis unavailable"})
	}

	setSessionCookie(c, fmt.Sprint(chatID), a.sessionKey)
	a.metrics.tokenConsumed.Inc()
	a.metrics.sessionCreated.Inc()
	log.Printf("consume token ok: token_hash=%s chat_id=%d remote=%s client=%s proto=%s forwarded_proto=%s", tokenDigest, chatID, clientIP(c.Request()), peerIP(c.Request()), requestProto(c.Request()), c.Request().Header.Get("X-Forwarded-Proto"))
	c.Response().Header().Add("Cache-Control", "no-store")
	return c.Redirect(http.StatusTemporaryRedirect, "/")
}

func (a *App) dashboard(c echo.Context) error {
	chatID, ok, err := verifySessionCookie(c, a.sessionKey, a.sessionKeyPrev)
	if err != nil {
		a.metrics.sessionInvalid.Inc()
		log.Printf("session invalid: remote=%s client=%s user_agent=%q error=%q", clientIP(c.Request()), peerIP(c.Request()), c.Request().UserAgent(), err.Error())
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid session"})
	}
	if !ok {
		a.metrics.sessionMissing.Inc()
		log.Printf("session missing_or_invalid: remote=%s client=%s user_agent=%q", clientIP(c.Request()), peerIP(c.Request()), c.Request().UserAgent())
		return c.String(http.StatusUnauthorized, "Unauthorized")
	}

	profile := templ.Profile{ChatID: chatID}
	answers := []templ.DailyAnswer{}
	usersOK := true
	analyticsOK := true

	profile, err = a.getProfile(c.Request().Context(), chatID)
	if err != nil {
		usersOK = false
		profile.ChatID = chatID
		profile.Name = "Unknown"
		profile.Role = "unknown"
	}

	answers, err = a.getDailyAnswers(c.Request().Context(), chatID)
	if err != nil {
		analyticsOK = false
		answers = []templ.DailyAnswer{}
	}

	return templ.Dashboard(templ.DashboardData{
		Profile:        profile,
		DailyAnswers:   answers,
		LastUpdated:    time.Now().Format(time.RFC3339),
		UsersSucceeded: usersOK,
		AnalyticsOK:    analyticsOK,
	}).Render(c.Request().Context(), c.Response().Writer)
}

func (a *App) getProfile(ctx context.Context, chatID int64) (templ.Profile, error) {
	a.metrics.profileCalls.Inc()
	var profile templ.Profile
	err := a.callUpstream(ctx, a.usersClient, a.usersBreaker, fmt.Sprintf("%s/users/%d", a.cfg.UsersURL, chatID), &profile)
	return profile, err
}

func (a *App) getDailyAnswers(ctx context.Context, chatID int64) ([]templ.DailyAnswer, error) {
	a.metrics.analyticsCalls.Inc()
	var answers []templ.DailyAnswer
	err := a.callUpstream(ctx, a.analytics, a.analyticsBreaker, fmt.Sprintf("%s/analytics/chat/%d/daily?days=30", a.cfg.AnalyticsURL, chatID), &answers)
	return answers, err
}

func (a *App) callUpstream(ctx context.Context, client *upstreamClient, breaker *gobreaker.CircuitBreaker, endpoint string, out any) error {
	_, err := breaker.Execute(func() (any, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")

		resp, err := client.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 500 {
			return nil, fmt.Errorf("%s returned %d", client.name, resp.StatusCode)
		}
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("%s returned %d", client.name, resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return nil, err
		}
		return nil, nil
	})
	if err != nil {
		a.metrics.upstreamErrors.Inc()
		return err
	}
	return nil
}

func newUpstreamClient(name, baseURL string) *upstreamClient {
	return &upstreamClient{
		name: name,
		client: &http.Client{
			Timeout: upstreamTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
			},
		},
	}
}

func randomBase64URL(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}

func tokenKey(token string) string {
	return "token:" + token
}

func sidKey(sid string) string {
	return "session:" + sid
}

func setSessionCookie(c echo.Context, value string, key []byte) {
	cookieValue, err := signSession(value, key)
	if err != nil {
		return
	}
	c.SetCookie(&http.Cookie{
		Name:     "session",
		Value:    cookieValue,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func signSession(value string, key []byte) (string, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(value)) + "." + sig, nil
}

func verifySessionCookie(c echo.Context, keys ...[]byte) (int64, bool, error) {
	cookie, err := c.Cookie("session")
	if err != nil {
		return 0, false, nil
	}
	parts := strings.SplitN(cookie.Value, ".", 2)
	if len(parts) != 2 {
		return 0, false, nil
	}

	rawValue, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, false, err
	}

	for _, key := range keys {
		if len(key) == 0 {
			continue
		}
		expected, err := signSession(string(rawValue), key)
		if err != nil {
			return 0, false, err
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(cookie.Value)) != 1 {
			continue
		}

		chatID, err := strconv.ParseInt(string(rawValue), 10, 64)
		if err != nil || chatID == 0 {
			return 0, false, nil
		}
		return chatID, true, nil
	}
	return 0, false, nil
}

func verifySessionID(ctx context.Context, rdb *redis.Client, sid string) (int64, bool, error) {
	var chatID int64
	if err := rdb.Get(ctx, sidKey(sid)).Scan(&chatID); err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, false, nil
		}
		return 0, false, err
	}
	if chatID == 0 {
		return 0, false, nil
	}
	return chatID, true, nil
}

func newMetrics() *metrics {
	return &metrics{
		tokenRequests: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "web_admin_token_requests_total",
			Help: "Total POST /internal/token requests.",
		}),
		tokenErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "web_admin_token_errors_total",
			Help: "Total token creation failures.",
		}),
		tokenConsumed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "web_admin_token_consumed_total",
			Help: "Total cabinet tokens consumed.",
		}),
		telegramPreviewSkip: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "web_admin_telegram_preview_skipped_total",
			Help: "Total Telegram preview requests skipped before consuming cabinet tokens.",
		}),
		httpsRejected: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "web_admin_https_rejected_total",
			Help: "Total requests rejected because HTTPS was not detected.",
		}),
		internalRejected: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "web_admin_internal_rejected_total",
			Help: "Total /internal/* requests rejected by network policy.",
		}),
		sessionCreated: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "web_admin_session_created_total",
			Help: "Total session cookies created.",
		}),
		sessionMissing: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "web_admin_session_missing_total",
			Help: "Total dashboard requests without a valid session cookie.",
		}),
		sessionInvalid: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "web_admin_session_invalid_total",
			Help: "Total dashboard requests with malformed session cookies.",
		}),
		profileCalls: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "web_admin_profile_calls_total",
			Help: "Total users service profile calls.",
		}),
		analyticsCalls: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "web_admin_analytics_calls_total",
			Help: "Total analytics service answer count calls.",
		}),
		upstreamErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "web_admin_upstream_errors_total",
			Help: "Total upstream call failures.",
		}),
	}
}

func (m *metrics) mustRegister() {
	prometheus.MustRegister(
		m.tokenRequests,
		m.tokenErrors,
		m.tokenConsumed,
		m.telegramPreviewSkip,
		m.httpsRejected,
		m.internalRejected,
		m.sessionCreated,
		m.sessionMissing,
		m.sessionInvalid,
		m.profileCalls,
		m.analyticsCalls,
		m.upstreamErrors,
	)
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func requireInternalNetwork(app *App) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if !strings.HasPrefix(c.Request().URL.Path, "/internal/") {
				return next(c)
			}
			if c.Request().Header.Get("X-Forwarded-For") != "" || c.Request().Header.Get("X-Forwarded-Host") != "" {
				app.metrics.internalRejected.Inc()
				log.Printf("internal request rejected: path=%s remote=%s client=%s reason=forwarded", c.Request().URL.Path, peerIP(c.Request()), clientIP(c.Request()))
				return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
			}
			if !isPrivateIP(peerIP(c.Request())) {
				app.metrics.internalRejected.Inc()
				log.Printf("internal request rejected: path=%s remote=%s client=%s reason=not_private", c.Request().URL.Path, peerIP(c.Request()), clientIP(c.Request()))
				return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
			}
			return next(c)
		}
	}
}

func requireForwardedProtoHTTPS(app *App) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			path := c.Request().URL.Path
			if path == "/healthz" || path == "/metrics" || strings.HasPrefix(path, "/internal/") {
				return next(c)
			}

			proto, ok := forwardedProto(c.Request())
			if !ok {
				proto = requestProto(c.Request())
			}
			if proto != "" && !strings.EqualFold(proto, "https") {
				app.metrics.httpsRejected.Inc()
				log.Printf("non-https request rejected: path=%s proto=%s remote=%s client=%s", path, proto, peerIP(c.Request()), clientIP(c.Request()))
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "https required"})
			}
			if proto == "https" {
				c.Response().Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			return next(c)
		}
	}
}

func clientIP(r *http.Request) string {
	if isPrivateIP(peerIP(r)) {
		if forwarded := firstXForwardedFor(r); forwarded != "" {
			return forwarded
		}
	}
	return peerIP(r)
}

func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return strings.Trim(host, "[]")
}

func firstXForwardedFor(r *http.Request) string {
	for _, part := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		ip := strings.TrimSpace(part)
		if ip != "" {
			return ip
		}
	}
	return ""
}

func isPrivateIP(value string) bool {
	value = strings.Trim(value, "[]")
	if value == "" {
		return false
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}

func requestProto(r *http.Request) string {
	if proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); proto != "" {
		return proto
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func forwardedProto(r *http.Request) (string, bool) {
	proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if proto == "" {
		return "", false
	}
	if idx := strings.Index(proto, ","); idx >= 0 {
		proto = proto[:idx]
	}
	return strings.TrimSpace(proto), true
}

func isTelegramPreviewRequest(r *http.Request) bool {
	userAgent := r.UserAgent()
	if strings.Contains(userAgent, "TelegramBot") {
		return true
	}
	if strings.Contains(userAgent, "Telegram") && strings.Contains(userAgent, "preview") {
		return true
	}
	if strings.Contains(userAgent, "AppleWebKit") && strings.Contains(userAgent, "Chrome") && strings.Contains(userAgent, "Safari") {
		return false
	}
	return false
}

func jsonHTTPError(err error, c echo.Context) {
	code := http.StatusInternalServerError
	if he, ok := err.(*echo.HTTPError); ok {
		code = he.Code
	}
	_ = c.JSON(code, map[string]string{"error": http.StatusText(code)})
}
