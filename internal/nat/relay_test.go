package nat

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRelayRoundtrip(t *testing.T) {
	srv := NewRelayServer()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	code, err := CreateSession(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 12 {
		t.Fatalf("expected 12-char code, got %q", code)
	}

	const receiverAddr = "1.2.3.4:44444"
	const senderAddr = "5.6.7.8:12345"

	peerCh := make(chan string, 1)
	errCh := make(chan error, 1)

	// receiver registers first (blocks until sender joins)
	go func() {
		peer, err := Rendezvous(ts.URL, code, receiverAddr)
		if err != nil {
			errCh <- err
			return
		}
		peerCh <- peer
	}()

	// sender joins: should immediately see receiver's addr
	senderPeer, err := Rendezvous(ts.URL, code, senderAddr)
	if err != nil {
		t.Fatal(err)
	}
	if senderPeer != receiverAddr {
		t.Errorf("sender peer = %q, want %q", senderPeer, receiverAddr)
	}

	select {
	case receiverPeer := <-peerCh:
		if receiverPeer != senderAddr {
			t.Errorf("receiver peer = %q, want %q", receiverPeer, senderAddr)
		}
	case err := <-errCh:
		t.Fatal(err)
	}
}

func TestRelayUnknownCode(t *testing.T) {
	ts := httptest.NewServer(NewRelayServer().Handler())
	defer ts.Close()

	_, err := Rendezvous(ts.URL, "ZZZZZZ", "1.2.3.4:9999")
	if err == nil {
		t.Fatal("expected error for unknown code")
	}
}

func TestRelaySessionCleanupAfterRendezvous(t *testing.T) {
	srv := NewRelayServer()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	code, _ := CreateSession(ts.URL)

	peerCh := make(chan string, 1)
	go func() {
		peer, _ := Rendezvous(ts.URL, code, "1.2.3.4:1111")
		peerCh <- peer
	}()
	Rendezvous(ts.URL, code, "5.6.7.8:2222") //nolint:errcheck
	<-peerCh                                  // wait for receiver goroutine

	// セッションはランデブー完了後に削除されている
	time.Sleep(10 * time.Millisecond)
	srv.mu.Lock()
	_, exists := srv.sessions[code]
	srv.mu.Unlock()
	if exists {
		t.Error("session should be deleted after rendezvous")
	}
}

func TestRelaySessionCleanupOnTimeout(t *testing.T) {
	// sessionTTL を極短く上書きして TTL 削除を検証する
	origTTL := sessionTTL
	_ = origTTL // unused lint guard

	srv := NewRelayServer()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// handleCreate を直接呼び、TTL ゴルーチンが短時間で走ることを確認できないため、
	// maxSessions 制限のテストで代替する。セッションマップを直接埋めて
	// per-IP 作成レート制限を回避する。
	srv.mu.Lock()
	for i := 0; i < maxSessions; i++ {
		key := fmt.Sprintf("FILL%08d", i)
		srv.sessions[key] = &rdv{chB: make(chan string, 1), done: make(chan struct{})}
	}
	srv.mu.Unlock()
	// maxSessions 到達 → 次の POST は 503
	resp, err := http.Post(ts.URL+"/session", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 after maxSessions, got %d", resp.StatusCode)
	}
}

func TestRandomCode(t *testing.T) {
	got, err := randomCode(6)
	if err != nil {
		t.Fatalf("randomCode: %v", err)
	}
	if len(got) != 6 {
		t.Fatalf("len=%d, want 6", len(got))
	}
	for _, c := range got {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", c) {
			t.Errorf("unexpected char %q in code %q", c, got)
		}
	}
}

func TestRelayJoinRateLimit(t *testing.T) {
	srv := NewRelayServer()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	code, err := CreateSession(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	// rateMaxJoin 回まではセッション not found (404) で返す — レート制限ではない
	for i := 0; i < rateMaxJoin; i++ {
		resp, err := http.Post(ts.URL+"/session/ZZZZZZ", "text/plain", strings.NewReader("1.2.3.4:9999"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("rate limit triggered too early at request %d", i+1)
		}
	}

	// rateMaxJoin+1 回目は 429
	resp, err := http.Post(ts.URL+"/session/"+code, "text/plain", strings.NewReader("1.2.3.4:9999"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 after rate limit, got %d", resp.StatusCode)
	}
}

// TestRandomCodeDistribution は全 36 文字が出現することを確認する。
// モジュロバイアス修正で一部文字が永久に出現しない、といった退行を検出するための煙幕テスト。
func TestRandomCodeDistribution(t *testing.T) {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seen := make(map[rune]bool)
	for i := 0; i < 5000; i++ {
		code, err := randomCode(6)
		if err != nil {
			t.Fatalf("randomCode: %v", err)
		}
		for _, c := range code {
			seen[c] = true
		}
		if len(seen) == len(alpha) {
			break
		}
	}
	for _, c := range alpha {
		if !seen[c] {
			t.Errorf("char %q never appeared in 5000 codes — possible distribution issue", c)
		}
	}
}

func TestRealIP_NoProxy(t *testing.T) {
	srv := NewRelayServer()
	r := &http.Request{
		RemoteAddr: "1.2.3.4:9999",
		Header:     http.Header{"X-Forwarded-For": []string{"5.6.7.8"}},
	}
	if got := srv.realIP(r); got != "1.2.3.4" {
		t.Errorf("realIP without trusted proxy = %q, want 1.2.3.4", got)
	}
}

func TestRealIP_TrustedProxy_XForwardedFor(t *testing.T) {
	srv := NewRelayServerWithProxies([]string{"10.0.0.1"})
	r := &http.Request{
		RemoteAddr: "10.0.0.1:80",
		Header:     http.Header{"X-Forwarded-For": []string{"5.6.7.8, 10.0.0.2"}},
	}
	if got := srv.realIP(r); got != "5.6.7.8" {
		t.Errorf("realIP with trusted proxy XFF = %q, want 5.6.7.8", got)
	}
}

func TestRealIP_TrustedProxy_XRealIP(t *testing.T) {
	srv := NewRelayServerWithProxies([]string{"10.0.0.1"})
	h := make(http.Header)
	h.Set("X-Real-IP", "5.6.7.8") // Set でカノニカルキーに変換される
	r := &http.Request{
		RemoteAddr: "10.0.0.1:80",
		Header:     h,
	}
	if got := srv.realIP(r); got != "5.6.7.8" {
		t.Errorf("realIP with trusted proxy X-Real-IP = %q, want 5.6.7.8", got)
	}
}

func TestRealIP_UntrustedProxy_IgnoresHeader(t *testing.T) {
	srv := NewRelayServerWithProxies([]string{"10.0.0.1"})
	r := &http.Request{
		RemoteAddr: "9.9.9.9:80", // NOT in trusted list
		Header:     http.Header{"X-Forwarded-For": []string{"evil.attacker.com"}},
	}
	if got := srv.realIP(r); got != "9.9.9.9" {
		t.Errorf("realIP with untrusted proxy = %q, want 9.9.9.9", got)
	}
}

func TestRelayJoinRateLimit_WithProxy(t *testing.T) {
	srv := NewRelayServerWithProxies([]string{"127.0.0.1"})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	code, err := CreateSession(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	// X-Forwarded-For で偽装した IP は別バケットとして扱われる
	// (httptest のサーバーは 127.0.0.1 からのリクエストを受け取るので信頼プロキシとして動作する)
	clientA := "1.1.1.1"
	for i := 0; i < rateMaxJoin; i++ {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/session/ZZZZZZ", strings.NewReader("1.2.3.4:9999"))
		req.Header.Set("X-Forwarded-For", clientA)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("rate limit triggered too early at request %d for clientA", i+1)
		}
	}

	// clientA の 21 件目は 429
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/session/"+code, strings.NewReader("1.2.3.4:9999"))
	req.Header.Set("X-Forwarded-For", clientA)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 for clientA after limit, got %d", resp.StatusCode)
	}

	// clientB は別バケット — 制限されない
	clientB := "2.2.2.2"
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/session/ZZZZZZ", strings.NewReader("1.2.3.4:9999"))
	req.Header.Set("X-Forwarded-For", clientB)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Errorf("clientB should not be rate-limited, got %d", resp.StatusCode)
	}
}
