// Package logger provides animated, colorful terminal output for k8s-eu-audit.
// Zero external dependencies beyond github.com/fatih/color (already in go.mod).
// All animation uses ANSI escape codes + goroutines — works on macOS, Linux,
// and Windows Terminal.
package logger

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

// ── Terminal detection ────────────────────────────────────────────────────────

// isTTY returns true when stderr is an interactive terminal.
// Animations are disabled when piping output (CI logs, files).
func isTTY() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

var tty = isTTY()

// ── ANSI escape codes ─────────────────────────────────────────────────────────

const (
	ansiReset      = "\033[0m"
	ansiHideCursor = "\033[?25l"
	ansiShowCursor = "\033[?25h"
	ansiClearLine  = "\r\033[2K"
	ansiUp1        = "\033[1A"
	ansiClearEOL   = "\033[0K"
)

// ── Colors ────────────────────────────────────────────────────────────────────

var (
	bold    = color.New(color.Bold)
	dimmed  = color.New(color.Faint)
	green   = color.New(color.FgGreen, color.Bold)
	yellow  = color.New(color.FgYellow, color.Bold)
	red     = color.New(color.FgRed, color.Bold)
	cyan    = color.New(color.FgCyan, color.Bold)
	blue    = color.New(color.FgBlue, color.Bold)
	magenta = color.New(color.FgMagenta, color.Bold)
	white   = color.New(color.FgHiWhite)
)

// out is stderr — keeps stdout clean for JSON output
var out io.Writer = os.Stderr

// ── Animated banner ───────────────────────────────────────────────────────────

// bannerLines is the ASCII art split so we can animate it line by line.
var bannerLines = []string{
	`  ██╗  ██╗ █████╗ ███████╗      ███████╗██╗   ██╗`,
	`  ██║ ██╔╝██╔══██╗██╔════╝      ██╔════╝██║   ██║`,
	`  █████╔╝ ╚█████╔╝███████╗█████╗█████╗  ██║   ██║`,
	`  ██╔═██╗ ██╔══██╗╚════██║╚════╝██╔══╝  ██║   ██║`,
	`  ██║  ██╗╚█████╔╝███████║      ███████╗╚██████╔╝ `,
	`  ╚═╝  ╚═╝ ╚════╝ ╚══════╝      ╚══════╝ ╚═════╝  `,
}

// PrintBanner renders the animated startup banner.
// On non-TTY (CI), prints instantly without animation.
func PrintBanner(version, mode string, frameworks []string) {
	if tty {
		fmt.Fprint(out, ansiHideCursor)
		defer fmt.Fprint(out, ansiShowCursor)
		animateBanner(version, mode, frameworks)
	} else {
		staticBanner(version, mode, frameworks)
	}
}

func animateBanner(version, mode string, frameworks []string) {
	fmt.Fprintln(out)

	// Animate each banner line — fade in with cyan gradient
	shades := []string{
		"\033[38;5;24m", // dark blue
		"\033[38;5;31m", // medium blue
		"\033[38;5;38m", // teal
		"\033[38;5;45m", // light cyan
		"\033[38;5;51m", // bright cyan
		"\033[38;5;87m", // white-cyan
	}
	for i, line := range bannerLines {
		shade := shades[i%len(shades)]
		fmt.Fprintf(out, "%s%s%s\n", shade, line, ansiReset)
		time.Sleep(55 * time.Millisecond)
	}

	fmt.Fprintln(out)

	// Typewriter effect for subtitle
	subtitle := fmt.Sprintf("  k8s-eu-audit %s  —  Kubernetes EU Compliance Scanner", version)
	typewrite(subtitle, cyan, 18*time.Millisecond)
	fmt.Fprintln(out)
	fmt.Fprintln(out)

	// Fade in metadata
	time.Sleep(80 * time.Millisecond)
	fmt.Fprintf(out, "  %-14s %s\n", "Mode:", cyan.Sprint(mode))
	time.Sleep(40 * time.Millisecond)
	fmt.Fprintf(out, "  %-14s %s\n", "Frameworks:", cyan.Sprint(strings.Join(frameworks, ", ")))
	time.Sleep(40 * time.Millisecond)

	fmt.Fprintln(out)
	animateSeparator(52, 12*time.Millisecond)
	fmt.Fprintln(out)
}

func staticBanner(version, mode string, frameworks []string) {
	fmt.Fprintln(out)
	for _, line := range bannerLines {
		cyan.Fprintln(out, line)
	}
	fmt.Fprintln(out)
	bold.Fprintf(out, "  k8s-eu-audit %s — Kubernetes EU Compliance Scanner\n", version)
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  %-14s %s\n", "Mode:", mode)
	fmt.Fprintf(out, "  %-14s %s\n", "Frameworks:", strings.Join(frameworks, ", "))
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  "+strings.Repeat("─", 52))
	fmt.Fprintln(out)
}

// typewrite prints text character by character.
func typewrite(text string, c *color.Color, delay time.Duration) {
	runes := []rune(text)
	for _, r := range runes {
		c.Fprintf(out, "%c", r)
		time.Sleep(delay)
	}
}

// animateSeparator draws a horizontal rule character by character.
func animateSeparator(width int, delay time.Duration) {
	fmt.Fprint(out, "  ")
	for i := 0; i < width; i++ {
		dimmed.Fprint(out, "─")
		time.Sleep(delay)
	}
	fmt.Fprintln(out)
}

// ── Spinner ───────────────────────────────────────────────────────────────────

// Spinner shows an animated spinner with a live elapsed timer.
type Spinner struct {
	msg   string
	done  chan struct{}
	wg    sync.WaitGroup
	start time.Time
	// findingCount is updated atomically from outside while spinner runs
	FindingCount *int64
}

var spinnerFrames = []string{
	"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏",
}

// StartSpinner starts an animated spinner.
// Returns a Spinner — call Stop(success) when done.
func StartSpinner(msg string) *Spinner {
	if !tty {
		fmt.Fprintf(out, "  → %s ...\n", msg)
		return &Spinner{msg: msg, done: make(chan struct{})}
	}
	var count int64
	s := &Spinner{
		msg:          msg,
		done:         make(chan struct{}),
		start:        time.Now(),
		FindingCount: &count,
	}
	fmt.Fprint(out, ansiHideCursor)
	s.wg.Add(1)
	go s.run()
	return s
}

func (s *Spinner) run() {
	defer s.wg.Done()
	i := 0
	for {
		select {
		case <-s.done:
			return
		default:
			elapsed := time.Since(s.start).Seconds()
			frame := cyan.Sprint(spinnerFrames[i%len(spinnerFrames)])

			var suffix string
			if s.FindingCount != nil {
				n := atomic.LoadInt64(s.FindingCount)
				if n > 0 {
					suffix = dimmed.Sprintf("  [%d findings]", n)
				}
			}

			fmt.Fprintf(out, "%s  %s  %s  %s%s",
				ansiClearLine,
				frame,
				s.msg,
				dimmed.Sprintf("%.1fs", elapsed),
				suffix,
			)
			time.Sleep(80 * time.Millisecond)
			i++
		}
	}
}

// Stop stops the spinner and prints a final status line.
func (s *Spinner) Stop(success bool) {
	s.StopWithMsg(success, s.msg)
}

// StopWithMsg stops the spinner and prints a custom final message.
func (s *Spinner) StopWithMsg(success bool, msg string) {
	if !tty {
		if success {
			fmt.Fprintf(out, "  ✓  %s\n", msg)
		} else {
			fmt.Fprintf(out, "  ✗  %s\n", msg)
		}
		return
	}
	close(s.done)
	s.wg.Wait()
	fmt.Fprint(out, ansiShowCursor)
	fmt.Fprint(out, ansiClearLine)
	if success {
		fmt.Fprintf(out, "  %s  %s\n", green.Sprint("✓"), msg)
	} else {
		fmt.Fprintf(out, "  %s  %s\n", red.Sprint("✗"), msg)
	}
}

// ── Step headers ──────────────────────────────────────────────────────────────

// Step prints an animated numbered step header.
func Step(n, total int, msg string) {
	fmt.Fprintln(out)
	if tty {
		// Animate the step number bouncing in
		time.Sleep(60 * time.Millisecond)
		bold.Fprintf(out, "  [%d/%d] %s\n", n, total, msg)
		time.Sleep(30 * time.Millisecond)
	} else {
		bold.Fprintf(out, "\n  [%d/%d] %s\n", n, total, msg)
	}
}

// Info prints an informational line.
func Info(msg string) { fmt.Fprintf(out, "  %s  %s\n", blue.Sprint("→"), msg) }

// Success prints a success line.
func Success(msg string) { fmt.Fprintf(out, "  %s  %s\n", green.Sprint("✓"), msg) }

// Warn prints a warning line.
func Warn(msg string) { fmt.Fprintf(out, "  %s  %s\n", yellow.Sprint("⚠"), msg) }

// Error prints an error line.
func Error(msg string) { fmt.Fprintf(out, "  %s  %s\n", red.Sprint("✗"), msg) }

// Skip prints a skipped item.
func Skip(msg string) { fmt.Fprintf(out, "  %s  %s\n", dimmed.Sprint("–"), msg) }

// Detail prints a dimmed detail line.
func Detail(msg string) { fmt.Fprintf(out, "       %s\n", dimmed.Sprint(msg)) }

// ── Scanner progress ──────────────────────────────────────────────────────────

// ScannerStart prints the scanner launch line.
func ScannerStart(name string) {
	icon := scannerIcon(name)
	if tty {
		time.Sleep(30 * time.Millisecond)
	}
	fmt.Fprintf(out, "\n  %s  %s\n",
		cyan.Sprint(icon),
		bold.Sprintf("Running %s ...", name),
	)
}

// ScannerDone prints the scanner completion with animated finding count.
func ScannerDone(name string, findingCount int, elapsed time.Duration) {
	if tty {
		animateFindingCount(name, findingCount, elapsed)
	} else {
		fmt.Fprintf(out, "  ✓  %s — %d findings  (%.1fs)\n",
			name, findingCount, elapsed.Seconds())
	}
}

// animateFindingCount counts up to the finding total visually.
func animateFindingCount(name string, total int, elapsed time.Duration) {
	if total == 0 {
		fmt.Fprintf(out, "  %s  %s — %s\n",
			green.Sprint("✓"), bold.Sprint(name), dimmed.Sprint("0 findings"))
		return
	}

	// Count from 0 to total in ~300ms
	steps := 20
	if total < 20 {
		steps = total
	}
	delay := 300 * time.Millisecond / time.Duration(steps)

	for i := 1; i <= steps; i++ {
		current := int(math.Round(float64(total) * float64(i) / float64(steps)))
		fmt.Fprintf(out, "%s  %s  %s — %s",
			ansiClearLine,
			green.Sprint("✓"),
			bold.Sprint(name),
			green.Sprintf("%d findings", current),
		)
		if i == steps {
			break
		}
		time.Sleep(delay)
	}
	fmt.Fprintf(out, "  %s\n", dimmed.Sprintf("%.1fs", elapsed.Seconds()))
}

// ScannerSkip prints a skipped scanner.
func ScannerSkip(name, reason string) {
	fmt.Fprintf(out, "  %s  %-12s  %s\n",
		dimmed.Sprint("–"), name, dimmed.Sprint(reason))
}

// ScannerError prints a scanner error.
func ScannerError(name string, err error) {
	fmt.Fprintf(out, "  %s  %s — %s\n",
		yellow.Sprint("⚠"), name, yellow.Sprintf("%v", err))
}

func scannerIcon(name string) string {
	switch name {
	case "kubescape":
		return "⎈"
	case "trivy":
		return "🛡"
	case "kube-bench":
		return "📋"
	case "lynis":
		return "🐧"
	case "macos":
		return ""
	case "windows":
		return "🪟"
	default:
		return "▸"
	}
}

// ── Mapping progress ──────────────────────────────────────────────────────────

// MappingStart prints the mapping phase header.
func MappingStart(framework string, findingCount int) {
	fmt.Fprintf(out, "\n  %s  Mapping %s findings → %s controls ...\n",
		cyan.Sprint("→"),
		bold.Sprintf("%d", findingCount),
		bold.Sprint(strings.ToUpper(framework)),
	)
}

// MappingDone prints mapping results with an animated summary bar.
func MappingDone(framework string, controlCount, pass, warn, fail, skip int) {
	fmt.Fprintf(out, "  %s  %s: %d controls\n",
		green.Sprint("✓"),
		bold.Sprint(strings.ToUpper(framework)),
		controlCount,
	)

	if tty {
		animateMappingBar(pass, warn, fail, skip, controlCount)
	} else {
		fmt.Fprintf(out, "       %s  %s  %s  %s\n",
			green.Sprintf("PASS %-2d", pass),
			yellow.Sprintf("WARN %-2d", warn),
			red.Sprintf("FAIL %-2d", fail),
			dimmed.Sprintf("SKIP %-2d", skip),
		)
	}
}

// animateMappingBar draws a colored segmented bar showing pass/warn/fail/skip.
func animateMappingBar(pass, warn, fail, skip, total int) {
	if total == 0 {
		return
	}
	const barWidth = 40
	passW := int(math.Round(float64(pass) / float64(total) * barWidth))
	warnW := int(math.Round(float64(warn) / float64(total) * barWidth))
	failW := int(math.Round(float64(fail) / float64(total) * barWidth))
	skipW := barWidth - passW - warnW - failW
	if skipW < 0 {
		skipW = 0
	}

	fmt.Fprint(out, "       ")

	// Animate bar growing left-to-right
	segments := []struct {
		count int
		char  string
		c     *color.Color
	}{
		{passW, "█", green},
		{warnW, "█", yellow},
		{failW, "█", red},
		{skipW, "░", dimmed},
	}

	drawn := 0
	for _, seg := range segments {
		for i := 0; i < seg.count; i++ {
			seg.c.Fprint(out, seg.char)
			drawn++
			if tty && drawn%4 == 0 {
				time.Sleep(12 * time.Millisecond)
			}
		}
	}

	fmt.Fprintf(out, "  %s  %s  %s  %s\n",
		green.Sprintf("✓%d", pass),
		yellow.Sprintf("⚠%d", warn),
		red.Sprintf("✗%d", fail),
		dimmed.Sprintf("–%d", skip),
	)
}

// ── Score reveal ──────────────────────────────────────────────────────────────

// PrintScoreLine prints the framework score with an animated reveal.
func PrintScoreLine(framework string, score float64, status string) {
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  %s\n", dimmed.Sprint(strings.Repeat("─", 52)))

	if tty {
		animateScoreReveal(framework, score, status)
	} else {
		staticScoreLine(framework, score, status)
	}

	fmt.Fprintf(out, "  %s\n", dimmed.Sprint(strings.Repeat("─", 52)))
}

func animateScoreReveal(framework string, finalScore float64, status string) {
	// Count up from 0 to final score
	steps := 30
	delay := 600 * time.Millisecond / time.Duration(steps)

	scoreColor := red
	switch status {
	case "PASS":
		scoreColor = green
	case "WARN":
		scoreColor = yellow
	}

	for i := 0; i <= steps; i++ {
		current := finalScore * float64(i) / float64(steps)
		line := fmt.Sprintf("  %s Overall:  %s  %s",
			strings.ToUpper(framework),
			scoreColor.Sprintf("%5.1f%%", current),
			dimmed.Sprint(status),
		)
		fmt.Fprintf(out, "%s%s", ansiClearLine, line)
		time.Sleep(delay)
	}
	// Final — overwrite with exact value
	finalLine := fmt.Sprintf("  %s Overall:  %s  %s",
		bold.Sprint(strings.ToUpper(framework)),
		scoreColor.Sprintf("%5.1f%%", finalScore),
		scoreColor.Sprint(status),
	)
	fmt.Fprintf(out, "%s%s\n", ansiClearLine, finalLine)
}

func staticScoreLine(framework string, score float64, status string) {
	scoreColor := red
	switch status {
	case "PASS":
		scoreColor = green
	case "WARN":
		scoreColor = yellow
	}
	fmt.Fprintf(out, "  %s Overall:  %s  %s\n",
		strings.ToUpper(framework),
		scoreColor.Sprintf("%.1f%%", score),
		scoreColor.Sprint(status),
	)
}

// PrintProgressBar renders an animated progress bar for a score.
func PrintProgressBar(score float64, status string) {
	if tty {
		animateProgressBar(score, status)
	} else {
		staticProgressBar(score, status)
	}
}

func animateProgressBar(finalScore float64, status string) {
	const width = 44

	barColor := red
	switch status {
	case "PASS":
		barColor = green
	case "WARN":
		barColor = yellow
	}

	steps := 35
	delay := 500 * time.Millisecond / time.Duration(steps)

	for i := 0; i <= steps; i++ {
		current := finalScore * float64(i) / float64(steps)
		filled := int(current / 100 * width)
		if filled > width {
			filled = width
		}
		bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
		fmt.Fprintf(out, "%s  %s %s",
			ansiClearLine,
			barColor.Sprint(bar),
			dimmed.Sprintf("%.0f%%", current),
		)
		time.Sleep(delay)
	}
	// Final with exact value
	filled := int(finalScore / 100 * width)
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	fmt.Fprintf(out, "%s  %s %s\n",
		ansiClearLine,
		barColor.Sprint(bar),
		barColor.Sprintf("%.0f%%", finalScore),
	)
}

func staticProgressBar(score float64, status string) {
	const width = 44
	filled := int(score / 100 * width)
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	fmt.Fprintf(out, "  [%s] %.0f%%\n", bar, score)
}

// ── Priority findings ─────────────────────────────────────────────────────────

// PriorityFinding holds the data for a critical/high finding.
type PriorityFinding struct {
	Article     string
	Name        string
	Severity    string
	Status      string
	Score       float64
	Remediation string
}

// PrintPriorityFindings lists CRITICAL/HIGH failures with animated reveal.
func PrintPriorityFindings(findings []PriorityFinding) {
	if len(findings) == 0 {
		return
	}

	fmt.Fprintln(out)
	if tty {
		time.Sleep(80 * time.Millisecond)
	}
	red.Fprintln(out, "  ⚡ Priority findings requiring immediate attention:")
	fmt.Fprintln(out)

	for i, f := range findings {
		if tty {
			time.Sleep(60 * time.Millisecond)
		}

		icon := red.Sprint("✗")
		sevColor := red
		if f.Status == "WARN" {
			icon = yellow.Sprint("⚠")
			sevColor = yellow
		}

		fmt.Fprintf(out, "  %s  %s  %s — %s\n",
			icon,
			sevColor.Sprintf("[%-8s]", f.Severity),
			bold.Sprint(f.Article),
			f.Name,
		)

		// Score mini-bar
		if tty {
			miniBar(f.Score, f.Status)
		}

		if f.Remediation != "" {
			rem := firstSentence(f.Remediation)
			dimmed.Fprintf(out, "       → %s\n", rem)
		}

		if i < len(findings)-1 {
			fmt.Fprintln(out)
		}
	}
	fmt.Fprintln(out)
}

// miniBar draws a compact 20-char progress bar inline.
func miniBar(score float64, status string) {
	const width = 20
	filled := int(score / 100 * width)
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("▪", filled) + strings.Repeat("·", width-filled)

	barColor := red
	switch status {
	case "PASS":
		barColor = green
	case "WARN":
		barColor = yellow
	}
	fmt.Fprintf(out, "       %s %.0f%%\n", barColor.Sprint(bar), score)
}

// ── Scan summary ──────────────────────────────────────────────────────────────

// PrintScanSummary prints the final animated summary box.
func PrintScanSummary(clusterName string, scanners []string, elapsed time.Duration) {
	fmt.Fprintln(out)
	if tty {
		animateSeparator(52, 8*time.Millisecond)
	} else {
		fmt.Fprintln(out, "  "+strings.Repeat("─", 52))
	}

	bold.Fprintln(out, "  Scan complete")

	lines := []struct{ label, value string }{
		{"Cluster:", clusterName},
		{"Scanners:", strings.Join(scanners, ", ")},
		{"Duration:", fmt.Sprintf("%.1fs", elapsed.Seconds())},
	}
	for i, l := range lines {
		if tty {
			time.Sleep(50 * time.Millisecond)
		}
		_ = i
		fmt.Fprintf(out, "  %-16s %s\n", l.label, cyan.Sprint(l.value))
	}
	fmt.Fprintln(out)
}

// ── CI/CD threshold ───────────────────────────────────────────────────────────

// PrintFailOnResult prints the CI/CD threshold result with a flash effect.
func PrintFailOnResult(score float64, threshold int, passed bool) {
	fmt.Fprintln(out)
	if passed {
		if tty {
			// Flash green twice
			for i := 0; i < 2; i++ {
				green.Fprintf(out, "%s  ✓ Score %.0f%% ≥ threshold %d%% — CI/CD PASS\n",
					ansiClearLine, score, threshold)
				time.Sleep(120 * time.Millisecond)
				fmt.Fprintf(out, "%s", ansiUp1)
				time.Sleep(120 * time.Millisecond)
			}
			green.Fprintf(out, "  ✓ Score %.0f%% ≥ threshold %d%% — CI/CD PASS\n",
				score, threshold)
		} else {
			green.Fprintf(out, "  ✓ Score %.0f%% ≥ threshold %d%% — CI/CD PASS\n",
				score, threshold)
		}
	} else {
		if tty {
			// Flash red twice
			for i := 0; i < 2; i++ {
				red.Fprintf(out, "%s  ✗ Score %.0f%% < threshold %d%% — CI/CD FAIL\n",
					ansiClearLine, score, threshold)
				time.Sleep(120 * time.Millisecond)
				fmt.Fprintf(out, "%s", ansiUp1)
				time.Sleep(120 * time.Millisecond)
			}
			red.Fprintf(out, "  ✗ Score %.0f%% < threshold %d%% — CI/CD FAIL\n",
				score, threshold)
		} else {
			red.Fprintf(out, "  ✗ Score %.0f%% < threshold %d%% — CI/CD FAIL\n",
				score, threshold)
		}
	}
}

// PrintReportWritten notifies the user that a report file was written.
func PrintReportWritten(path string) {
	fmt.Fprintf(out, "\n  %s  Report → %s\n",
		green.Sprint("✓"),
		bold.Sprint(path),
	)
}

// ── Report output notification ────────────────────────────────────────────────

// PrintReportSection prints a section separator before the terminal table.
func PrintReportSection(framework string) {
	fmt.Fprintln(out)
	if tty {
		time.Sleep(60 * time.Millisecond)
	}
	magenta.Fprintf(out, "  ▶  %s Compliance Controls\n", strings.ToUpper(framework))
	fmt.Fprintln(out)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	for _, sep := range []string{". ", ".\n", "K8s:", "Linux:", "macOS:", "Windows:"} {
		if i := strings.Index(s, sep); i > 0 {
			return strings.TrimSpace(s[:i+1])
		}
	}
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}
