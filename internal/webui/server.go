package webui

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flipslidersand/mesh-drop/internal/discovery"
	"github.com/flipslidersand/mesh-drop/internal/transfer"
)

//go:embed static
var staticFiles embed.FS

// ProgressEvent is sent over SSE for both send and receive events.
type ProgressEvent struct {
	ID        string `json:"id"`
	Direction string `json:"direction"` // "send" | "recv"
	File      string `json:"file"`
	Peer      string `json:"peer"`
	Sent      int64  `json:"sent,omitempty"`
	Total     int64  `json:"total,omitempty"`
	Done      bool   `json:"done"`
	ErrMsg    string `json:"error,omitempty"`
}

// HistoryEntry records a completed transfer.
type HistoryEntry struct {
	ID        string    `json:"id"`
	Direction string    `json:"direction"`
	File      string    `json:"file"`
	Peer      string    `json:"peer"`
	Size      int64     `json:"size"`
	ErrMsg    string    `json:"error,omitempty"`
	At        time.Time `json:"at"`
}

type hub struct {
	mu      sync.Mutex
	clients map[chan ProgressEvent]struct{}
}

func newHub() *hub {
	return &hub{clients: make(map[chan ProgressEvent]struct{})}
}

func (h *hub) subscribe() chan ProgressEvent {
	ch := make(chan ProgressEvent, 32)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *hub) unsubscribe(ch chan ProgressEvent) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
}

func (h *hub) publish(e ProgressEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- e:
		default:
		}
	}
}

// Server is the meshdrop Web UI HTTP server.
type Server struct {
	addr    string
	timeout time.Duration
	hub     *hub
	runCtx  context.Context

	histMu  sync.Mutex
	history []HistoryEntry

	dlMu      sync.RWMutex
	downloads map[string]string // id → abs file path
	recvDir   string
}

func New(addr string, discoverTimeout time.Duration) *Server {
	return &Server{
		addr:      addr,
		timeout:   discoverTimeout,
		hub:       newHub(),
		runCtx:    context.Background(),
		downloads: make(map[string]string),
	}
}

func (s *Server) Run(ctx context.Context) error {
	s.runCtx = ctx
	// Create persistent recv dir for the session.
	recvDir, err := os.MkdirTemp("", "meshdrop-ui-recv-*")
	if err != nil {
		return fmt.Errorf("recv dir: %w", err)
	}
	s.recvDir = recvDir
	defer os.RemoveAll(recvDir)

	go s.runReceiver(ctx, recvDir)

	mux := http.NewServeMux()

	sub, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/peers", s.handlePeers)
	mux.HandleFunc("/api/send", s.handleSend)
	mux.HandleFunc("/api/send-dir", s.handleSendDir)
	mux.HandleFunc("/api/history", s.handleHistory)
	mux.HandleFunc("/api/downloads/", s.handleDownload)
	mux.HandleFunc("/sse/progress", s.handleSSE)

	srv := &http.Server{Addr: s.addr, Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background()) //nolint:errcheck
	}()
	return srv.ListenAndServe()
}

func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), s.timeout)
	defer cancel()

	peers, err := discovery.Browse(ctx, s.timeout)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type peerDTO struct {
		Name string `json:"name"`
		Addr string `json:"addr"`
	}
	out := make([]peerDTO, len(peers))
	for i, p := range peers {
		out[i] = peerDTO{Name: p.Name, Addr: p.Addr()}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out) //nolint:errcheck
}

// handleHistory returns the in-memory transfer history (newest first, max 50).
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.histMu.Lock()
	h := make([]HistoryEntry, len(s.history))
	copy(h, s.history)
	s.histMu.Unlock()

	if len(h) > 50 {
		h = h[len(h)-50:]
	}
	for i, j := 0, len(h)-1; i < j; i, j = i+1, j-1 {
		h[i], h[j] = h[j], h[i]
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h) //nolint:errcheck
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(512 << 20); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	peerAddr := r.FormValue("peer")
	if peerAddr == "" {
		http.Error(w, "peer is required", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	tmp, err := os.CreateTemp("", "meshdrop-ui-*-"+filepath.Base(header.Filename))
	if err != nil {
		http.Error(w, "temp file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(tmp, file); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		http.Error(w, "write temp: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmp.Close()

	// Optional: rate-limit and compression settings (#239).
	rateLimitStr := strings.TrimSpace(r.FormValue("rate_limit"))
	compress := r.FormValue("compress") == "true"
	compLevel, _ := strconv.Atoi(r.FormValue("compress_level"))

	lim, limErr := transfer.ParseRateLimit(rateLimitStr)
	if limErr != nil {
		os.Remove(tmp.Name())
		http.Error(w, limErr.Error(), http.StatusBadRequest)
		return
	}

	id := fmt.Sprintf("%d", time.Now().UnixNano())
	total := header.Size

	go func() {
		defer os.Remove(tmp.Name())

		// Publish heartbeat progress events while sending (#238).
		done := make(chan struct{})
		go func() {
			ticker := time.NewTicker(300 * time.Millisecond)
			defer ticker.Stop()
			pct := int64(0)
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					// Increment by a small amount so the bar is animated;
					// exact bytes are not available without deeper integration.
					if pct < total*9/10 {
						pct += total / 20
					}
					s.hub.publish(ProgressEvent{
						ID: id, Direction: "send",
						File: header.Filename, Peer: peerAddr,
						Sent: pct, Total: total,
					})
				}
			}
		}()

		sendErr := transfer.Send(r.Context(), peerAddr, tmp.Name(), 4, nil, lim, compress, compLevel, false)
		close(done)

		ev := ProgressEvent{
			ID: id, Direction: "send",
			File: header.Filename, Peer: peerAddr,
			Sent: total, Total: total, Done: true,
		}
		if sendErr != nil {
			ev.ErrMsg = sendErr.Error()
			ev.Sent = 0
		}
		s.hub.publish(ev)

		entry := HistoryEntry{
			ID: id, Direction: "send",
			File: header.Filename, Peer: peerAddr,
			Size: total, At: time.Now(),
		}
		if sendErr != nil {
			entry.ErrMsg = sendErr.Error()
		}
		s.histMu.Lock()
		s.history = append(s.history, entry)
		s.histMu.Unlock()
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"id": id}) //nolint:errcheck
}

func (s *Server) handleSendDir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	const (
		maxDirUploadSize = int64(2 << 30)
		multipartMemory  = 32 << 20
	)
	r.Body = http.MaxBytesReader(w, r.Body, maxDirUploadSize)
	if err := r.ParseMultipartForm(multipartMemory); err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "request body too large") {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, "parse form: "+err.Error(), status)
		return
	}
	peerAddr := r.FormValue("peer")
	if peerAddr == "" {
		http.Error(w, "peer is required", http.StatusBadRequest)
		return
	}
	fileHeaders := r.MultipartForm.File["files"]
	if len(fileHeaders) == 0 {
		http.Error(w, "files is required", http.StatusBadRequest)
		return
	}
	var paths []string
	if err := json.Unmarshal([]byte(r.FormValue("paths")), &paths); err != nil || len(paths) != len(fileHeaders) {
		http.Error(w, "paths must be a JSON array matching files length", http.StatusBadRequest)
		return
	}

	rateLimitStr := strings.TrimSpace(r.FormValue("rate_limit"))
	compress := r.FormValue("compress") == "true"
	compLevel, _ := strconv.Atoi(r.FormValue("compress_level"))
	lim, limErr := transfer.ParseRateLimit(rateLimitStr)
	if limErr != nil {
		http.Error(w, limErr.Error(), http.StatusBadRequest)
		return
	}

	tmpDir, err := os.MkdirTemp("", "meshdrop-ui-dir-*")
	if err != nil {
		http.Error(w, "temp dir: "+err.Error(), http.StatusInternalServerError)
		return
	}
	absBase, _ := filepath.Abs(tmpDir)

	var totalSize int64
	var topDir string
	for i, fh := range fileHeaders {
		cleanPath := filepath.Clean(filepath.ToSlash(paths[i]))
		if cleanPath == "." || cleanPath == ".." || strings.HasPrefix(cleanPath, "../") || filepath.IsAbs(cleanPath) {
			os.RemoveAll(tmpDir)
			http.Error(w, "invalid path: "+paths[i], http.StatusBadRequest)
			return
		}
		slash := strings.IndexByte(cleanPath, '/')
		if slash <= 0 || i == 0 && slash == len(cleanPath)-1 {
			os.RemoveAll(tmpDir)
			http.Error(w, "invalid directory path: "+paths[i], http.StatusBadRequest)
			return
		}
		currentTop := cleanPath[:slash]
		if topDir == "" {
			topDir = currentTop
		} else if topDir != currentTop {
			os.RemoveAll(tmpDir)
			http.Error(w, "all files must be from one top-level directory", http.StatusBadRequest)
			return
		}
		relPath := filepath.FromSlash(cleanPath)
		absOut, _ := filepath.Abs(filepath.Join(absBase, relPath))
		rel, relErr := filepath.Rel(absBase, absOut)
		if relErr != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			os.RemoveAll(tmpDir)
			http.Error(w, "invalid path: "+paths[i], http.StatusBadRequest)
			return
		}
		if err := os.MkdirAll(filepath.Dir(absOut), 0o755); err != nil {
			os.RemoveAll(tmpDir)
			http.Error(w, "mkdir: "+err.Error(), http.StatusInternalServerError)
			return
		}
		src, err := fh.Open()
		if err != nil {
			os.RemoveAll(tmpDir)
			http.Error(w, "open upload: "+err.Error(), http.StatusInternalServerError)
			return
		}
		f, err := os.Create(absOut)
		if err != nil {
			src.Close()
			os.RemoveAll(tmpDir)
			http.Error(w, "create: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = io.Copy(f, src)
		src.Close()
		f.Close()
		if err != nil {
			os.RemoveAll(tmpDir)
			http.Error(w, "write: "+err.Error(), http.StatusInternalServerError)
			return
		}
		totalSize += fh.Size
	}

	// webkitRelativePath is always "dirName/..." — extract the top-level dir.
	dirName := topDir
	sendPath := filepath.Join(tmpDir, dirName)

	id := fmt.Sprintf("%d", time.Now().UnixNano())
	total := totalSize

	go func() {
		defer os.RemoveAll(tmpDir)

		done := make(chan struct{})
		go func() {
			ticker := time.NewTicker(300 * time.Millisecond)
			defer ticker.Stop()
			pct := int64(0)
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					if pct < total*9/10 {
						pct += total / 20
					}
					s.hub.publish(ProgressEvent{
						ID: id, Direction: "send",
						File: dirName, Peer: peerAddr,
						Sent: pct, Total: total,
					})
				}
			}
		}()

		sendErr := transfer.SendDir(s.runCtx, peerAddr, sendPath, 4, nil, lim, compress, compLevel, false)
		close(done)

		ev := ProgressEvent{
			ID: id, Direction: "send",
			File: dirName, Peer: peerAddr,
			Sent: total, Total: total, Done: true,
		}
		if sendErr != nil {
			ev.ErrMsg = sendErr.Error()
			ev.Sent = 0
		}
		s.hub.publish(ev)

		entry := HistoryEntry{
			ID: id, Direction: "send",
			File: dirName, Peer: peerAddr,
			Size: total, At: time.Now(),
		}
		if sendErr != nil {
			entry.ErrMsg = sendErr.Error()
		}
		s.histMu.Lock()
		s.history = append(s.history, entry)
		s.histMu.Unlock()
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"id": id}) //nolint:errcheck
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := s.hub.subscribe()
	defer s.hub.unsubscribe(ch)

	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			data, _ := json.Marshal(ev)
			fmt.Fprintf(w, "data: %s\n\n", data)
			fl.Flush()
		}
	}
}

// handleDownload serves a received file for browser download.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/downloads/")
	s.dlMu.RLock()
	path, ok := s.downloads[id]
	s.dlMu.RUnlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	name := filepath.Base(path)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	http.ServeFile(w, r, path)
}

// runReceiver starts a QUIC listener that accepts incoming transfers in a loop.
// Received files land in recvDir and become available via /api/downloads/{id}.
func (s *Server) runReceiver(ctx context.Context, recvDir string) {
	bundle, err := transfer.NewTLSBundle()
	if err != nil {
		return
	}
	go discovery.Advertise(ctx, discovery.DefaultPort, bundle.Fingerprint) //nolint:errcheck

	addr := fmt.Sprintf("0.0.0.0:%d", discovery.DefaultPort)
	_ = transfer.ListenContinuous(ctx, addr, bundle, recvDir, func(name, path string, size int64, peer string) {
		id := fmt.Sprintf("recv-%d", time.Now().UnixNano())

		s.dlMu.Lock()
		s.downloads[id] = path
		s.dlMu.Unlock()

		s.hub.publish(ProgressEvent{
			ID: id, Direction: "recv",
			File: name, Peer: peer,
			Sent: size, Total: size, Done: true,
		})
		s.histMu.Lock()
		s.history = append(s.history, HistoryEntry{
			ID: id, Direction: "recv",
			File: name, Peer: peer,
			Size: size, At: time.Now(),
		})
		s.histMu.Unlock()
	})
}
