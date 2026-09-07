//go:build !windows && !plan9

package logging

import "log/syslog"

// writeJournal sends the record to the local syslog/journal socket. On systemd
// systems this lands in the journal (journalctl -t classify-bash). A dial error is
// how sink=auto detects journal absence and falls back to the file.
//
// log/syslog is unavailable on Windows/Plan9, which is why this lives in a
// build-tagged file; see journal_other.go for the stub there.
func writeJournal(line string) error {
	if line == "" {
		return nil
	}
	w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_USER, "classify-bash")
	if err != nil {
		return err
	}
	defer w.Close()
	return w.Info(line)
}
