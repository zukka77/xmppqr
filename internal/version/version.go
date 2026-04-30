package version

import "strings"
import "runtime"

var version = "0.1.0-dev"

func Name() string { return "xmppqr" }

func Version() string { return version }

func OS() string {
	s := runtime.GOOS
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
