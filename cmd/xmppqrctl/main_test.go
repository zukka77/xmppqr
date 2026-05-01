package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binPath string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "xmppqrctl-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmp)

	bin := filepath.Join(tmp, "xmppqrctl")
	out, err := exec.Command("go", "build", "-o", bin, "github.com/danielinux/xmppqr/cmd/xmppqrctl").CombinedOutput()
	if err != nil {
		panic("build failed: " + string(out))
	}
	binPath = bin
	os.Exit(m.Run())
}

func TestVersion(t *testing.T) {
	cmd := exec.Command(binPath, "version")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("version exited non-zero: %v", err)
	}
	if !strings.HasPrefix(string(out), "xmppqrctl") {
		t.Fatalf("unexpected output: %q", string(out))
	}
}

func TestNoArgs(t *testing.T) {
	cmd := exec.Command(binPath)
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit with no args")
	}
}

func TestUseraddRequiresPostgres(t *testing.T) {
	cfgFile := writeTempMemoryConfig(t)
	cmd := exec.Command(binPath, "useradd", "testuser", "-config", cfgFile, "-password", "pw123")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for memory driver")
	}
	if !strings.Contains(strings.ToLower(string(out)), "postgres") {
		t.Fatalf("expected mention of postgres in stderr, got: %q", string(out))
	}
}

func TestLoadConfigAutodetectsLocalFile(t *testing.T) {
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldwd) })

	content := "server:\n  domain: autodetect.local\nlisteners:\n  c2s_starttls: \":5222\"\ndb:\n  driver: postgres\n  dsn: \"host=127.0.0.1 dbname=xmppqr\"\n"
	if err := os.WriteFile(filepath.Join(tmp, "xmppqrd.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	if cfg.DB.Driver != "postgres" {
		t.Fatalf("expected postgres driver, got %q", cfg.DB.Driver)
	}
	if cfg.Server.Domain != "autodetect.local" {
		t.Fatalf("expected autodetected domain, got %q", cfg.Server.Domain)
	}
}

func TestTLSProbeNoServer(t *testing.T) {
	cmd := exec.Command(binPath, "tls-probe", "127.0.0.1:19999", "-insecure")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit when no server is reachable")
	}
}

func TestUseraddPostgres(t *testing.T) {
	dsn := os.Getenv("XMPPQR_TEST_DSN")
	if dsn == "" {
		t.Skip("XMPPQR_TEST_DSN not set")
	}

	cfgFile := writeTempConfig(t, dsn)

	user := "testuser_integration"
	add := exec.Command(binPath, "useradd", user, "-config", cfgFile, "-password", "hunter2", "-replace")
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("useradd failed: %v\n%s", err, out)
	}

	list := exec.Command(binPath, "userlist", "-config", cfgFile)
	out, err := list.Output()
	if err != nil {
		t.Fatalf("userlist failed: %v", err)
	}
	if !strings.Contains(string(out), user) {
		t.Fatalf("user %q not in userlist output:\n%s", user, string(out))
	}

	del := exec.Command(binPath, "userdel", user, "-config", cfgFile)
	if out, err := del.CombinedOutput(); err != nil {
		t.Fatalf("userdel failed: %v\n%s", err, out)
	}
}

func writeTempConfig(t *testing.T, dsn string) string {
	t.Helper()
	f, err := os.CreateTemp("", "xmppqr-cfg-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	content := "server:\n  domain: test.local\nlisteners:\n  c2s_starttls: \":5222\"\ndb:\n  driver: postgres\n  dsn: \"" + dsn + "\"\n  migrate_on_start: true\n"
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func writeTempMemoryConfig(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "xmppqr-cfg-memory-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	content := "server:\n  domain: test.local\nlisteners:\n  c2s_starttls: \":5222\"\ndb:\n  driver: memory\n"
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}
