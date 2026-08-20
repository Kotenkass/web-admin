package templ

import (
	"context"
	"html"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
)

type Profile struct {
	ChatID  int64  `json:"chat_id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Role    string `json:"role"`
	Avatar  string `json:"avatar"`
	IsAdmin bool   `json:"is_admin"`
}

type DailyAnswer struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

type DashboardData struct {
	Profile        Profile
	DailyAnswers   []DailyAnswer
	LastUpdated    string
	UsersSucceeded bool
	AnalyticsOK    bool
}

func Dashboard(data DashboardData) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		if data.LastUpdated == "" {
			data.LastUpdated = time.Now().Format(time.RFC3339)
		}
		if data.Profile.Name == "" {
			data.Profile.Name = "Unknown"
		}
		if data.Profile.Role == "" {
			data.Profile.Role = "unknown"
		}

		_, err := io.WriteString(w, "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>Web Admin</title>\n<style>\n:root{color-scheme:light dark;font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;color:#172033;background:#f5f7fb}\nbody{margin:0;background:linear-gradient(135deg,#eef2ff,#f8fafc)}\nmain{max-width:1080px;margin:48px auto;padding:0 24px}\n.card{background:rgba(255,255,255,.88);border:1px solid #e2e8f0;border-radius:24px;box-shadow:0 20px 60px rgba(15,23,42,.08);padding:28px;margin-bottom:24px}\n.badge{display:inline-flex;align-items:center;border-radius:999px;padding:6px 12px;font-size:12px;font-weight:700;background:#e0e7ff;color:#3730a3}\n.badge.ok{background:#dcfce7;color:#166534}.badge.warn{background:#fef3c7;color:#92400e}.badge.err{background:#fee2e2;color:#991b1b}\nh1,h2{margin:0 0 12px}.muted{color:#64748b}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:18px}.metric{background:#f8fafc;border-radius:18px;padding:18px}.metric strong{display:block;font-size:32px;margin-top:8px}\ntable{width:100%;border-collapse:collapse;overflow:hidden;border-radius:14px}td,th{padding:12px 14px;border-bottom:1px solid #e2e8f0;text-align:left}tr:last-child td{border-bottom:0}\n.avatar{width:64px;height:64px;border-radius:18px;background:#e0e7ff;display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:800;color:#3730a3}\n.profile{display:flex;gap:18px;align-items:center}\n</style>\n</head>\n<body>\n<main>\n<section class=\"card\">\n<div class=\"profile\">\n<div class=\"avatar\">")
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, escape(data.Profile.Name))
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "</div><div><h1>Web Admin</h1><p class=\"muted\">Signed in as <strong>")
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, escape(strconv.FormatInt(data.Profile.ChatID, 10)))
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "</strong> · ")
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, escape(data.Profile.Name))
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "</p></div>\n</div>\n</section>\n\n<section class=\"card\">\n<div class=\"grid\">\n<div class=\"metric\"><span class=\"muted\">Role</span><strong>")
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, escape(data.Profile.Role))
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "</strong></div>\n<div class=\"metric\"><span class=\"muted\">Email</span><strong>")
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, escape(defaultString(data.Profile.Email, "Not set")))
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "</strong></div>\n<div class=\"metric\"><span class=\"muted\">Answers / 30d</span><strong>")
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, strconv.Itoa(totalAnswers(data.DailyAnswers)))
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "</strong></div>\n</div>\n</section>\n\n<section class=\"card\">\n<h2>Daily answer counts</h2>\n<p class=\"muted\">Last updated ")
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, escape(data.LastUpdated))
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "</p>\n<table>\n<thead><tr><th>Date</th><th>Count</th><th>Status</th></tr></thead>\n<tbody>\n")
		if err != nil {
			return err
		}
		if len(data.DailyAnswers) == 0 {
			_, err = io.WriteString(w, "<tr><td colspan=\"3\">No analytics data available.</td></tr>\n")
			if err != nil {
				return err
			}
		} else {
			for _, row := range data.DailyAnswers {
				_, err = io.WriteString(w, "<tr><td>")
				if err != nil {
					return err
				}
				_, err = io.WriteString(w, escape(row.Date))
				if err != nil {
					return err
				}
				_, err = io.WriteString(w, "</td><td>")
				if err != nil {
					return err
				}
				_, err = io.WriteString(w, strconv.Itoa(row.Count))
				if err != nil {
					return err
				}
				_, err = io.WriteString(w, "</td><td><span class=\"badge ok\">ok</span></td></tr>\n")
				if err != nil {
					return err
				}
			}
		}
		_, err = io.WriteString(w, "</tbody>\n</table>\n</section>\n\n<section class=\"card\">\n<h2>Service health</h2>\n<div class=\"grid\">\n<div class=\"metric\"><span class=\"muted\">Users service</span><br><span class=\"badge ")
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, statusClass(data.UsersSucceeded))
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "\">")
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, statusText(data.UsersSucceeded))
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "</span></div>\n<div class=\"metric\"><span class=\"muted\">Analytics service</span><br><span class=\"badge ")
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, statusClass(data.AnalyticsOK))
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "\">")
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, statusText(data.AnalyticsOK))
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "</span></div>\n</div>\n</section>\n</main>\n</body>\n</html>\n")
		return err
	})
}

func escape(s string) string {
	return html.EscapeString(s)
}

func defaultString(s, fallback string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	return s
}

func totalAnswers(rows []DailyAnswer) int {
	var total int
	for _, row := range rows {
		total += row.Count
	}
	return total
}

func statusClass(ok bool) string {
	if ok {
		return "ok"
	}
	return "err"
}

func statusText(ok bool) string {
	if ok {
		return "ok"
	}
	return "degraded"
}
