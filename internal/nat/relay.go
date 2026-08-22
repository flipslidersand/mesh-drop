package nat

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// randReader はテストで差し替え可能な乱数ソース。
var randReader io.Reader = rand.Reader

// RelayServer は2ピアのアドレスを交換するランデブーサーバー。
// 受信側が CreateSession でコードを取得し、送受信双方が Rendezvous を呼ぶと
// 互いの外部アドレスを返す (long-poll 方式)。
type RelayServer struct {
	mu             sync.RWMutex          // #177: read-heavy パスに RWMutex を使用
	sessions       map[string]*rdv
	ipRate         map[string]*ipBucket // handleJoin の IP ベースレート制限
	ipCreateRate   map[string]*ipBucket // handleCreate の IP ベースレート制限 (#164)
	trustedProxies []string             // X-Forwarded-For を信頼するプロキシ IP/CIDR (#162)
	trustedCIDRs   []*net.IPNet         // #214: 起動時に一度 parse した CIDR リスト
	stopEvict      chan struct{}         // #208: evictExpiredBuckets goroutine を停止する
}

// ipBucket は IP ごとのスライディングウィンドウカウンタ。
type ipBucket struct {
	count int
	since time.Time
}

// maxSessions はメモリ枯渇防止のためのセッション数上限。
const maxSessions = 10_000

// sessionTTL は handleJoin が一度も呼ばれなかったセッションの有効期限。
// handleJoin 内の long-poll タイムアウト (30s) より余裕を持たせる。
const sessionTTL = 70 * time.Second

// rateWindow / rateMaxJoin はコード総当たり攻撃を緩和するレート制限定数。
// 1 分間に rateMaxJoin 回を超えた handleJoin リクエストを 429 で拒否する。
const (
	rateWindow    = time.Minute
	rateMaxJoin   = 20
	rateMaxCreate = 5 // #164: セッション作成は1分間に最大5回/IP
)

// rateBucketGrace は ipRate / ipCreateRate エントリの削除猶予期間。
// ウィンドウ満了後もしばらく残すことで、満了直後の再カウントを正確に行う。
// #176/#180: TTL ベースの立ち退きでマップ無制限成長を防止する。
const rateBucketGrace = rateWindow

// joinWaitTimeout は handleJoin の long-poll 最大待機時間 (#145)。
// 60s から 30s に短縮してサードパーティの不正接続による goroutine リークを軽減する。
const joinWaitTimeout = 30 * time.Second

type rdv struct {
	mu       sync.Mutex   // addrA / paired の読み書きを保護する
	addrA    string       // 最初に登録したピア (受信側)
	paired   bool         // 2番目のピアが確定したら true — 3番目以降の侵入を防ぐ
	chB      chan string  // 2番目のピア (送信側) が登録すると addrA の待機を解除
	done     chan struct{} // ランデブー完了またはタイムアウトで close される
	doneOnce sync.Once    // #215: done の二重 close を防ぐ
}

// closeDone は sess.done を一度だけ close する。
// #215: safe-close イディオムを1か所に集約し、コピペによる漏れを排除する。
func (r *rdv) closeDone() {
	r.doneOnce.Do(func() { close(r.done) })
}

// NewRelayServer は信頼プロキシなしのリレーサーバーを生成する。
// リバースプロキシ背後で動かす場合は NewRelayServerWithProxies を使うこと。
func NewRelayServer() *RelayServer {
	return NewRelayServerWithProxies(nil)
}

// NewRelayServerWithProxies は信頼プロキシ IP/CIDR リスト付きでリレーサーバーを生成する。
// trustedProxies に含まれる IP またはそのサブネットからのリクエストは
// X-Forwarded-For / X-Real-IP をクライアント IP として採用する。
// #162: CIDR 表記をサポートする。
func NewRelayServerWithProxies(trustedProxies []string) *RelayServer {
	// #214: CIDR を起動時に一度だけ parse してリクエストごとのアロケーションを排除する。
	var cidrs []*net.IPNet
	for _, entry := range trustedProxies {
		if _, network, err := net.ParseCIDR(entry); err == nil {
			cidrs = append(cidrs, network)
		}
	}
	s := &RelayServer{
		sessions:       make(map[string]*rdv),
		ipRate:         make(map[string]*ipBucket),
		ipCreateRate:   make(map[string]*ipBucket),
		trustedProxies: trustedProxies,
		trustedCIDRs:   cidrs,
		stopEvict:      make(chan struct{}),
	}
	// #176/#180: 定期的に期限切れレートバケットを退避してマップ肥大化を防ぐ。
	go s.evictExpiredBuckets()
	return s
}

// evictExpiredBuckets は定期的に ipRate / ipCreateRate から期限切れエントリを削除する。
// #176/#180: unbounded growth 対策。ウィンドウ + 猶予期間を超えたバケットを削除する。
// #208: stopEvict が close されると即座に返り、goroutine リークを防ぐ。
func (s *RelayServer) evictExpiredBuckets() {
	ticker := time.NewTicker(rateWindow)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopEvict:
			return
		case <-ticker.C:
		}
		cutoff := time.Now().Add(-(rateWindow + rateBucketGrace))
		s.mu.Lock()
		for ip, b := range s.ipRate {
			if b.since.Before(cutoff) {
				delete(s.ipRate, ip)
			}
		}
		for ip, b := range s.ipCreateRate {
			if b.since.Before(cutoff) {
				delete(s.ipCreateRate, ip)
			}
		}
		s.mu.Unlock()
	}
}

// safeClose はチャネルを冪等に close する。
// #215: 同一 select パターンが複数箇所に存在したためヘルパーに集約。
func safeClose(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}

// Stop は evictExpiredBuckets goroutine を停止する。
// #208: Start/StartTLS が返った後に呼ぶことで goroutine リークを防ぐ。
func (s *RelayServer) Stop() {
	safeClose(s.stopEvict)
}

// isTrustedProxy は ip が trustedProxies リストに含まれるか（完全一致または CIDR）を返す。
// #162: CIDR 表記のサポートを追加。
// #214: CIDR は起動時に parse 済みの trustedCIDRs を使いリクエストごとのアロケーションを排除。
// trustedProxies / trustedCIDRs はイミュータブルなのでミューテックスなしで安全に参照できる。
func (s *RelayServer) isTrustedProxy(ip string) bool {
	for _, entry := range s.trustedProxies {
		if entry == ip {
			return true
		}
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, network := range s.trustedCIDRs {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

// realIP はリクエストの実際のクライアント IP を返す。
// r.RemoteAddr が trustedProxies に含まれる場合に限り
// X-Forwarded-For / X-Real-IP を採用し、それ以外は r.RemoteAddr を使う。
// これにより信頼できないプロキシヘッダーによる IP スプーフィングを防ぐ。
// #162: CIDR ベースの信頼プロキシ判定をサポート。trustedProxies はイミュータブルなので
// ミューテックスなしで安全に参照できる。
// #177: sessions/ipRate 読み書きは mu.RLock/RUnlock で保護するが、
// realIP 自体はロックを取得しない（isTrustedProxy がロック不要のため）。
func (s *RelayServer) realIP(r *http.Request) string {
	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remote = r.RemoteAddr
	}
	if !s.isTrustedProxy(remote) {
		return remote
	}
	// X-Forwarded-For: client, proxy1, proxy2 — 最左のアドレスがクライアント
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if client := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0]); client != "" {
			return client
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return remote
}

// allowJoin は IP ごとのレート制限を確認する。制限内なら true を返す。
// mu を Write ロックして呼び出すこと。
func (s *RelayServer) allowJoin(ip string) bool {
	return s.allowRate(s.ipRate, ip, rateMaxJoin)
}

// allowCreate は IP ごとのセッション作成レート制限を確認する。制限内なら true を返す。
// mu を Write ロックして呼び出すこと。
// #164: セッション作成のレート制限。
func (s *RelayServer) allowCreate(ip string) bool {
	return s.allowRate(s.ipCreateRate, ip, rateMaxCreate)
}

// allowRate は汎用スライディングウィンドウレート制限ヘルパー。
// mu を Write ロックして呼び出すこと。
func (s *RelayServer) allowRate(bucket map[string]*ipBucket, ip string, max int) bool {
	now := time.Now()
	b, ok := bucket[ip]
	if !ok || now.Sub(b.since) >= rateWindow {
		// 期限切れエントリを削除してから新規登録することでメモリリークを防ぐ。
		delete(bucket, ip)
		bucket[ip] = &ipBucket{count: 1, since: now}
		return true
	}
	// インクリメント前にチェックして固定ウィンドウ境界でのバーストを防ぐ。
	if b.count >= max {
		return false
	}
	b.count++
	return true
}

func (s *RelayServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/session", s.handleCreate)
	mux.HandleFunc("/session/", s.handleJoin)
	return mux
}

// Start は addr でリレーサーバーを起動する (ブロッキング)。
// certFile, keyFile が空でない場合は HTTPS で起動する。
func (s *RelayServer) Start(addr string) error {
	return s.StartTLS(addr, "", "")
}

// StartTLS は addr でリレーサーバーを起動する (ブロッキング)。
// certFile, keyFile が指定されている場合は HTTPS で起動し、
// 両方が空の場合は HTTP で起動する。
// #208: サーバー停止時に evictExpiredBuckets goroutine を確実に停止する。
func (s *RelayServer) StartTLS(addr, certFile, keyFile string) error {
	defer s.Stop()
	srv := &http.Server{
		Addr:         addr,
		Handler:      s.Handler(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 70 * time.Second, // rendezvous long-poll は最大 30s、余裕を持たせて 70s
		IdleTimeout:  60 * time.Second,
	}
	if certFile != "" && keyFile != "" {
		return srv.ListenAndServeTLS(certFile, keyFile)
	}
	return srv.ListenAndServe()
}

func (s *RelayServer) handleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	// #164: IP ごとのセッション作成レート制限。
	// #177: allowCreate は書き込みが必要なので Lock/Unlock を使う。
	clientIP := s.realIP(r)
	s.mu.Lock()
	allowed := s.allowCreate(clientIP)
	s.mu.Unlock()
	if !allowed {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	sess := &rdv{chB: make(chan string, 1), done: make(chan struct{})}

	// コード生成・上限チェック・挿入をロック内で行い、重複コードの上書きを防ぐ。
	s.mu.Lock()
	if len(s.sessions) >= maxSessions {
		s.mu.Unlock()
		http.Error(w, "too many sessions", http.StatusServiceUnavailable)
		return
	}
	var code string
	for {
		// #161: コードを6文字から12文字に拡張して列挙攻撃耐性を向上させる。
		// 36^12 ≈ 4.7×10^18 の空間は6文字の36^6 ≈ 2.2×10^9 の約21億倍。
		var err error
		code, err = randomCode(12)
		if err != nil {
			s.mu.Unlock()
			http.Error(w, "internal server error", http.StatusServiceUnavailable)
			return
		}
		if _, exists := s.sessions[code]; !exists {
			break
		}
	}
	s.sessions[code] = sess
	s.mu.Unlock()

	// handleJoin が一度も呼ばれない場合の TTL クリーンアップ。
	// #186: TTL クリーンアップ時に sess.done を close してリソースを確実に解放する。
	go func() {
		select {
		case <-sess.done:
			// 正常なランデブー完了またはタイムアウトで既に処理済み
		case <-time.After(sessionTTL):
			s.mu.Lock()
			delete(s.sessions, code)
			s.mu.Unlock()
			sess.closeDone()
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"code": code}) //nolint:errcheck
}

func (s *RelayServer) handleJoin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	// IP ベースのレート制限: コード総当たり攻撃を緩和する。
	// realIP は信頼プロキシ設定に応じて X-Forwarded-For を読む。
	// #177: allowJoin は書き込みが必要なので Lock/Unlock を使う。
	clientIP := s.realIP(r)
	s.mu.Lock()
	allowed := s.allowJoin(clientIP)
	s.mu.Unlock()
	if !allowed {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	code := strings.TrimPrefix(r.URL.Path, "/session/")
	// 64 バイト上限: IPv6 アドレス最大長 ([xxxx:...:xxxx]:65535) は約 47 文字で収まる
	const maxAddrLen = 64
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxAddrLen+1))
	if len(body) > maxAddrLen {
		http.Error(w, "address too long", http.StatusBadRequest)
		return
	}
	myAddr := strings.TrimSpace(string(body))
	if myAddr == "" {
		http.Error(w, "body must be external addr (ip:port)", http.StatusBadRequest)
		return
	}
	if _, _, err := net.SplitHostPort(myAddr); err != nil {
		http.Error(w, "invalid addr format: "+err.Error(), http.StatusBadRequest)
		return
	}

	// #177: セッション読み取りは RLock で十分。
	s.mu.RLock()
	sess, ok := s.sessions[code]
	s.mu.RUnlock()
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	// addrA / paired の判定と書き込みを rdv のミューテックスで保護する。
	// 2接続が同時に sess.addrA == "" を見て両方が "最初の登録者" になるのを防ぐ。
	// paired フラグにより3番目以降のピアが chB へ送信できないようにする。
	sess.mu.Lock()
	isFirst := sess.addrA == ""
	isSecond := !isFirst && !sess.paired
	if isFirst {
		sess.addrA = myAddr
	} else if isSecond {
		sess.paired = true
	}
	peerAddrA := sess.addrA // 2番目登録者が使う
	sess.mu.Unlock()

	if !isFirst && !isSecond {
		http.Error(w, "session already paired", http.StatusConflict)
		return
	}

	var peerAddr string
	if isFirst {
		// #145: 最初の登録 (受信側): 送信側が来るまで待機。
		// コンテキストにタイムアウトを設定して、サードパーティが同じコードに POST しても
		// goroutine が永久ブロックしないようにする。
		joinCtx, joinCancel := context.WithTimeout(r.Context(), joinWaitTimeout)
		defer joinCancel()
		select {
		case peerAddr = <-sess.chB:
			// ランデブー完了 — セッションを削除して TTL ゴルーチンを終了させる
			s.mu.Lock()
			delete(s.sessions, code)
			s.mu.Unlock()
			sess.closeDone()
		case <-joinCtx.Done():
			s.mu.Lock()
			delete(s.sessions, code)
			s.mu.Unlock()
			sess.closeDone()
			http.Error(w, "timeout: peer did not connect within 30s", http.StatusRequestTimeout)
			return
		}
	} else {
		// 2番目の登録 (送信側): 受信側を即時解除してピアアドレスを交換
		peerAddr = peerAddrA
		sess.chB <- myAddr
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"peer": peerAddr}) //nolint:errcheck
}

// CreateSession は relayURL に新しいセッションを作成してペアリングコードを返す。
// #151: Use an explicit HTTP client with a timeout instead of http.DefaultClient.
func CreateSession(relayURL string) (string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(relayURL+"/session", "text/plain", nil)
	if err != nil {
		return "", fmt.Errorf("relay create: %w", err)
	}
	defer resp.Body.Close()
	var r map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", fmt.Errorf("relay decode: %w", err)
	}
	code, ok := r["code"]
	if !ok {
		return "", fmt.Errorf("relay: missing code in response")
	}
	return code, nil
}

// Rendezvous は code セッションに myAddr を登録し、ピアの外部アドレスを返す。
// 最初の呼び出しはピアが登録するまで最大 60 秒ブロックする。
func Rendezvous(relayURL, code, myAddr string) (string, error) {
	client := &http.Client{Timeout: 70 * time.Second}
	resp, err := client.Post(
		relayURL+"/session/"+code,
		"text/plain",
		strings.NewReader(myAddr),
	)
	if err != nil {
		return "", fmt.Errorf("relay join: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("relay: %s", strings.TrimSpace(string(b)))
	}
	var r map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", fmt.Errorf("relay decode: %w", err)
	}
	peer, ok := r["peer"]
	if !ok {
		return "", fmt.Errorf("relay: missing peer in response")
	}
	return peer, nil
}

func randomCode(n int) (string, error) {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// rejection sampling でモジュロバイアスを排除する。
	// 256 % 36 = 4 なのでバイト値 252-255 を棄却することで均一分布を保証する。
	const maxAccepted = byte(len(alpha) * (256 / len(alpha))) // = 252
	out := make([]byte, 0, n)
	buf := make([]byte, n+8) // 棄却分の余裕
	for len(out) < n {
		if _, err := io.ReadFull(randReader, buf); err != nil {
			return "", err
		}
		for _, v := range buf {
			if len(out) == n {
				break
			}
			if v >= maxAccepted {
				continue
			}
			out = append(out, alpha[int(v)%len(alpha)])
		}
	}
	return string(out), nil
}
