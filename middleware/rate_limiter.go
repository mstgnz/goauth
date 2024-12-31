package middleware

import (
	"net/http"
	"sync"
	"time"
)

type RateLimiter struct {
	requests map[string]*requestLimit
	mu       sync.RWMutex
	limit    int
	window   time.Duration
}

type requestLimit struct {
	count    int
	lastSeen time.Time
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string]*requestLimit),
		limit:    limit,
		window:   window,
	}
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		rl.mu.Lock()
		defer rl.mu.Unlock()

		now := time.Now()
		if limiter, exists := rl.requests[ip]; exists {
			if now.Sub(limiter.lastSeen) > rl.window {
				// Pencere süresi geçmiş, sayacı sıfırla
				limiter.count = 0
				limiter.lastSeen = now
			}

			if limiter.count >= rl.limit {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			limiter.count++
			limiter.lastSeen = now
		} else {
			rl.requests[ip] = &requestLimit{
				count:    1,
				lastSeen: now,
			}
		}

		next.ServeHTTP(w, r)
	})
}

// Temizlik işlemi için opsiyonel metod
func (rl *RateLimiter) CleanupOldEntries() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, limit := range rl.requests {
		if now.Sub(limit.lastSeen) > rl.window {
			delete(rl.requests, ip)
		}
	}
}
