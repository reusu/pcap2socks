package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// prettyHandler emits log lines in a Log4j / Spring Boot style:
//
//	yyyy-MM-dd HH:mm:ss.SSS  LEVEL PID --- [thread-name    ] logger.name        : message  k=v k=v
//
// (translation of `%d{yyyy-MM-dd HH:mm:ss.SSS} %5p ${sys:PID} --- [%15.15t] %-40.40c{1.} : %m%n`)
type prettyHandler struct {
	mu      *sync.Mutex
	w       io.Writer
	level   slog.Level
	color   bool
	pid     int
	preAttr []slog.Attr
}

func newPrettyHandler(w io.Writer, level slog.Level) *prettyHandler {
	return &prettyHandler{
		mu:    &sync.Mutex{},
		w:     w,
		level: level,
		color: isTerminal(w),
		pid:   os.Getpid(),
	}
}

func (h *prettyHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *prettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.preAttr = append(append([]slog.Attr(nil), h.preAttr...), attrs...)
	return &c
}

func (h *prettyHandler) WithGroup(string) slog.Handler { return h }

func (h *prettyHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder

	t := r.Time
	if t.IsZero() {
		t = time.Now()
	}
	b.WriteString(t.Format("2006-01-02 15:04:05.000"))
	b.WriteByte(' ')

	// %5p
	lvl := levelLabel(r.Level)
	if h.color {
		b.WriteString(levelColor(r.Level))
	}
	b.WriteString(lvl)
	if h.color {
		b.WriteString("\x1b[0m")
	}
	b.WriteByte(' ')

	// ${sys:PID}
	b.WriteString(strconv.Itoa(h.pid))
	b.WriteString(" --- ")

	// [%15.15t]
	thread := goroutineName()
	b.WriteByte('[')
	b.WriteString(padLeft(truncate(thread, 15), 15))
	b.WriteString("] ")

	// %-40.40c{1.}
	logger := abbreviateLogger(callerLogger(r.PC), 40)
	if h.color {
		b.WriteString("\x1b[36m") // cyan
	}
	b.WriteString(padRight(truncate(logger, 40), 40))
	if h.color {
		b.WriteString("\x1b[0m")
	}
	b.WriteString(" : ")

	// %m
	b.WriteString(r.Message)

	// k=v attrs (extension over the Spring Boot template — slog brings them along)
	writeAttr := func(a slog.Attr) {
		if a.Equal(slog.Attr{}) {
			return
		}
		b.WriteByte(' ')
		writeKV(&b, h.color, a)
	}
	for _, a := range h.preAttr {
		writeAttr(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(a)
		return true
	})

	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func writeKV(b *strings.Builder, color bool, a slog.Attr) {
	if color {
		b.WriteString("\x1b[2m") // dim key
	}
	b.WriteString(a.Key)
	b.WriteByte('=')
	if color {
		b.WriteString("\x1b[0m")
	}
	v := a.Value.Resolve().String()
	if needsQuote(v) {
		fmt.Fprintf(b, "%q", v)
	} else {
		b.WriteString(v)
	}
}

func needsQuote(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		if r == ' ' || r == '"' || r == '\t' || r == '\n' {
			return true
		}
	}
	return false
}

func levelLabel(l slog.Level) string {
	switch {
	case l < slog.LevelInfo:
		return "DEBUG"
	case l < slog.LevelWarn:
		return " INFO"
	case l < slog.LevelError:
		return " WARN"
	default:
		return "ERROR"
	}
}

func levelColor(l slog.Level) string {
	switch {
	case l < slog.LevelInfo:
		return "\x1b[90m"
	case l < slog.LevelWarn:
		return "\x1b[32m" // green
	case l < slog.LevelError:
		return "\x1b[33m" // yellow
	default:
		return "\x1b[31m" // red
	}
}

func padLeft(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return strings.Repeat(" ", n-len(s)) + s
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// callerLogger derives a "pkg.func" identifier from the slog record's PC.
// Returns "" when the PC is unavailable (e.g. the record was constructed
// without source info), in which case the caller column will be empty.
func callerLogger(pc uintptr) string {
	if pc == 0 {
		return ""
	}
	frames := runtime.CallersFrames([]uintptr{pc})
	frame, _ := frames.Next()
	if frame.Function == "" {
		return ""
	}
	return frame.Function
}

// abbreviateLogger trims a fully-qualified Go function name to fit `width`,
// shortening leading path segments to a single letter (Log4j `c{1.}` style):
//
//	pcap2socks/internal/stack.pipe  →  p.i.stack.pipe
//
// Only the trailing function (last segment after the rightmost '.') is kept
// in full; everything before it is reduced.
func abbreviateLogger(fn string, width int) string {
	if fn == "" {
		return ""
	}
	// Split into "import/path" and "Type.func" by the last '/'.
	slash := strings.LastIndex(fn, "/")
	pkgFull, tail := "", fn
	if slash >= 0 {
		pkgFull = fn[:slash]
		tail = fn[slash+1:]
	}
	// `tail` is now `pkg.Func` or `pkg.Type.func`. Take the last dot segment
	// as the function name, the rest as part of the package qualifier.
	dot := strings.IndexByte(tail, '.')
	pkgLast, funcName := tail, ""
	if dot >= 0 {
		pkgLast = tail[:dot]
		funcName = tail[dot+1:]
	}

	var prefix []string
	if pkgFull != "" {
		for _, seg := range strings.Split(pkgFull, "/") {
			if seg == "" {
				continue
			}
			prefix = append(prefix, seg[:1])
		}
	}
	prefix = append(prefix, pkgLast)
	out := strings.Join(prefix, ".")
	if funcName != "" {
		out += "." + funcName
	}
	if len(out) <= width {
		return out
	}
	// Truncate from the left, since the function name is what we care about.
	return "…" + out[len(out)-width+1:]
}

// goroutineName returns "main" for the main goroutine and "g-N" otherwise.
// Parsing runtime.Stack is cheap enough at log frequency.
func goroutineName() string {
	id := goroutineID()
	if id == 1 {
		return "main"
	}
	return "g-" + strconv.FormatUint(id, 10)
}

func goroutineID() uint64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	// "goroutine N [...]"
	line := buf[:n]
	const prefix = "goroutine "
	if !bytes.HasPrefix(line, []byte(prefix)) {
		return 0
	}
	line = line[len(prefix):]
	end := bytes.IndexByte(line, ' ')
	if end < 0 {
		return 0
	}
	id, _ := strconv.ParseUint(string(line[:end]), 10, 64)
	return id
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// slogWriter routes lines from stdlib log through slog at INFO level so
// gvisor's internal log calls share the format.
type slogWriter struct{}

func (slogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	if msg != "" {
		slog.Info(msg)
	}
	return len(p), nil
}
