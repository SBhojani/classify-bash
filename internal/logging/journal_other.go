//go:build windows || plan9

package logging

import "errors"

// writeJournal is a stub on platforms without log/syslog (Windows, Plan9). It
// always errors, so sink=auto falls back to the file and sink=journal drops the
// line — the binary still builds and the file sink works everywhere.
func writeJournal(string) error {
	return errors.New("journal sink unavailable on this platform")
}
