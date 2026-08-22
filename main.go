package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
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
	Addr          string
	RedisAddr     string
	RedisPassword string
	SessionKey    string
	UsersURL      string
	AnalyticsURL  string
}

type App struct {
	cfg         Config
	redis       *redis.Client
	sessionKey  []byte
	usersClient *upstreamClient
	analytics   *upstreamClient
	breaker     *gobreaker.CircuitBreaker
	metrics     *metrics
}

type metrics struct {
	tokenRequests  prometheus.Counter
	tokenErrors    prometheus.Counter
	sessionCreated prometheus.Counter
	profileCalls   prometheus.Counter
	analyticsCalls prometheus.Counter
	upstreamErrors prometheus.Counter
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
		Addr:          env("ADDR", ":8080"),
		RedisAddr:     env("REDIS_ADDR", "localhost:6379"),
		RedisPassword: env("REDIS_PASSWORD", ""),
		SessionKey:    env("SESSION_KEY", ""),
		UsersURL:      strings.TrimRight(env("USERS_URL", "http://users-service:8080"), "/"),
		AnalyticsURL:  strings.TrimRight(env("ANALYTICS_URL", "http://analytics-service:8080"), "/"),
	}

	if cfg.SessionKey == "" {
		cfg.SessionKey = "dev-session-key-change-me"
	}

	sessionKey := sha256.Sum256([]byte(cfg.SessionKey))

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
	})

	app := &App{
		cfg:         cfg,
		redis:       rdb,
		sessionKey:  sessionKey[:],
		usersClient: newUpstreamClient("users", cfg.UsersURL),
		analytics:   newUpstreamClient("analytics", cfg.AnalyticsURL),
		breaker:     gobreaker.NewCircuitBreaker(gobreaker.Settings{Name: "upstreams", Timeout: 10 * time.Second}),
		metrics:     newMetrics(),
	}
	app.metrics.mustRegister()

	e := echo.New()
	e.HideBanner = true
	e.HTTPErrorHandler = jsonHTTPError
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())
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
	ctx, cancel := context.WithTimeout(c.Request().Context(), upstreamTimeout)
	defer cancel()

	key := tokenKey(token)
	var chatID int64
	if err := a.redis.Get(ctx, key).Scan(&chatID); err != nil {
		if errors.Is(err, redis.Nil) {
			return c.Redirect(http.StatusSeeOther, "/")
		}
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "redis unavailable"})
	}
	if err := a.redis.Del(ctx, key).Err(); err != nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "redis unavailable"})
	}

	cookieValue, err := signSession(fmt.Sprint(chatID), a.sessionKey)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to sign session"})
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
	a.metrics.sessionCreated.Inc()
	return c.Redirect(http.StatusSeeOther, "/")
}

func (a *App) dashboard(c echo.Context) error {
	chatID, ok, err := verifySessionCookie(c, a.sessionKey)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid session"})
	}
	if !ok {
		return c.String(http.StatusUnauthorized, "Unauthorized: open cabinet from Telegram link")
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
	err := a.callUpstream(ctx, fmt.Sprintf("%s/users/%d", a.cfg.UsersURL, chatID), &profile)
	return profile, err
}

func (a *App) getDailyAnswers(ctx context.Context, chatID int64) ([]templ.DailyAnswer, error) {
	a.metrics.analyticsCalls.Inc()
	var answers []templ.DailyAnswer
	err := a.callUpstream(ctx, fmt.Sprintf("%s/analytics/chat/%d/daily?days=30", a.cfg.AnalyticsURL, chatID), &answers)
	return answers, err
}

func (a *App) callUpstream(ctx context.Context, endpoint string, out any) error {
	_, err := a.breaker.Execute(func() (any, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")

		resp, err := a.usersClient.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 500 {
			return nil, fmt.Errorf("%s returned %d", a.usersClient.name, resp.StatusCode)
		}
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("%s returned %d", a.usersClient.name, resp.StatusCode)
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

func tokenKey(token string) string {
	return "token:" + token
}

func signSession(value string, key []byte) (string, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(value)) + "." + sig, nil
}

func verifySessionCookie(c echo.Context, key []byte) (int64, bool, error) {
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

	expected, err := signSession(string(rawValue), key)
	if err != nil {
		return 0, false, err
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(cookie.Value)) != 1 {
		return 0, false, nil
	}

	chatID, err := strconv.ParseInt(string(rawValue), 10, 64)
	if err != nil || chatID == 0 {
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
		sessionCreated: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "web_admin_session_created_total",
			Help: "Total session cookies created.",
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
		m.sessionCreated,
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

func jsonHTTPError(err error, c echo.Context) {
	code := http.StatusInternalServerError
	if he, ok := err.(*echo.HTTPError); ok {
		code = he.Code
	}
	_ = c.JSON(code, map[string]string{"error": http.StatusText(code)})
}
