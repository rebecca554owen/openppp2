package instance

import "regexp"

// StripANSI removes ANSI escape sequences and terminal control codes from text.
// Matches: CSI sequences (ESC [ ...), OSC sequences (ESC ] ... BEL/ST),
// DCS sequences (ESC P ... ESC \), and cursor visibility codes.
var ansiRegex = regexp.MustCompile(
	`\x1b\[[0-9;?]*[a-zA-Z]|` + // CSI: ESC [ params letter
	`\x1b\][^\x07]*\x07|` + // OSC: ESC ] ... BEL
	`\x1b\][^\x1b]*\x1b\\|` + // OSC: ESC ] ... ST
	`\x1bP[^\x1b]*\x1b\\|` + // DCS
	`\x1b\]0;[^\x07]*\x07`, // OSC 0 (window title)
)

func StripANSI(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}
