package httpupload

import (
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

type Backend interface {
	PutHandler() http.Handler
	GetHandler() http.Handler
	Verify(slotID, token string) (filename string, expiresAt time.Time, ok bool)
}

type DiskBackend struct {
	root    string
	service *Service
}

func NewDiskBackend(root string, svc *Service) *DiskBackend {
	return &DiskBackend{root: root, service: svc}
}

func (d *DiskBackend) Verify(slotID, token string) (string, time.Time, bool) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 || parts[0] != slotID {
		return "", time.Time{}, false
	}
	expUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", time.Time{}, false
	}
	expiry := time.Unix(expUnix, 0)
	if time.Now().After(expiry) {
		return "", expiry, false
	}

	// Reconstruct the filename from the metadata file.
	metaPath := filepath.Join(d.root, slotID+".meta")
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		return "", expiry, false
	}
	fields := strings.SplitN(string(metaBytes), "\n", 3)
	if len(fields) < 3 {
		return "", expiry, false
	}
	filename := fields[0]
	size, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return "", expiry, false
	}
	storedExpiry := fields[2]

	msg := []byte(slotID + "|" + storedExpiry + "|" + filename + "|" + strconv.FormatInt(size, 10))
	mac, err := wolfcrypt.HMACSHA256(d.service.secret, msg)
	if err != nil {
		return "", expiry, false
	}
	expected := slotID + "." + storedExpiry + "." + base64.RawURLEncoding.EncodeToString(mac)
	if token != expected {
		return "", expiry, false
	}
	return filename, expiry, true
}

func (d *DiskBackend) PutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// path: /upload/{slotID}
		slotID := strings.TrimPrefix(r.URL.Path, "/upload/")
		token := r.URL.Query().Get("token")

		filename, _, ok := d.Verify(slotID, token)
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if err := os.MkdirAll(d.root, 0o750); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		dst, err := os.Create(filepath.Join(d.root, slotID))
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		defer dst.Close()

		if _, err := io.Copy(dst, r.Body); err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		_ = filename
		w.WriteHeader(http.StatusCreated)
	})
}

func (d *DiskBackend) GetHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// path: /download/{slotID}/{filename}
		path := strings.TrimPrefix(r.URL.Path, "/download/")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) < 1 {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		slotID := parts[0]
		http.ServeFile(w, r, filepath.Join(d.root, slotID))
	})
}

// WriteSlotMeta persists filename/size/expiry so Verify can reconstruct the HMAC.
func (d *DiskBackend) WriteSlotMeta(slotID, filename string, size int64, expiry string) error {
	if err := os.MkdirAll(d.root, 0o750); err != nil {
		return err
	}
	content := filename + "\n" + strconv.FormatInt(size, 10) + "\n" + expiry
	return os.WriteFile(filepath.Join(d.root, slotID+".meta"), []byte(content), 0o640)
}
