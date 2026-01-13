package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

// ANSI color codes
const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	white   = "\033[37m"
	gray    = "\033[90m"
)

// ColorHandler is a colorized slog handler for terminal output
type ColorHandler struct {
	opts      slog.HandlerOptions
	output    io.Writer
	useColors bool
}

// NewColorHandler creates a new colorized log handler
// It automatically detects if the output is a terminal and enables colors accordingly
func NewColorHandler(w io.Writer, opts *slog.HandlerOptions) *ColorHandler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}

	// Check if output is a terminal
	useColors := false
	if f, ok := w.(*os.File); ok {
		useColors = term.IsTerminal(int(f.Fd()))
	}

	return &ColorHandler{
		opts:      *opts,
		output:    w,
		useColors: useColors,
	}
}

func (h *ColorHandler) Enabled(_ context.Context, level slog.Level) bool {
	minLevel := slog.LevelInfo
	if h.opts.Level != nil {
		minLevel = h.opts.Level.Level()
	}
	return level >= minLevel
}

func (h *ColorHandler) Handle(_ context.Context, r slog.Record) error {
	var sb strings.Builder

	// Timestamp
	timestamp := r.Time.Format("15:04:05")
	if h.useColors {
		sb.WriteString(gray)
		sb.WriteString(timestamp)
		sb.WriteString(reset)
	} else {
		sb.WriteString(timestamp)
	}
	sb.WriteString(" ")

	// Level with color
	levelStr := h.formatLevel(r.Level)
	sb.WriteString(levelStr)
	sb.WriteString(" ")

	// Message
	if h.useColors {
		sb.WriteString(bold)
		sb.WriteString(r.Message)
		sb.WriteString(reset)
	} else {
		sb.WriteString(r.Message)
	}

	// Attributes
	r.Attrs(func(a slog.Attr) bool {
		sb.WriteString(" ")
		if h.useColors {
			sb.WriteString(cyan)
			sb.WriteString(a.Key)
			sb.WriteString(reset)
			sb.WriteString("=")
			sb.WriteString(h.formatValue(a.Value))
		} else {
			sb.WriteString(a.Key)
			sb.WriteString("=")
			sb.WriteString(a.Value.String())
		}
		return true
	})

	sb.WriteString("\n")

	_, err := h.output.Write([]byte(sb.String()))
	return err
}

func (h *ColorHandler) formatLevel(level slog.Level) string {
	var levelColor, levelText string

	switch {
	case level >= slog.LevelError:
		levelColor = red
		levelText = "ERR"
	case level >= slog.LevelWarn:
		levelColor = yellow
		levelText = "WRN"
	case level >= slog.LevelInfo:
		levelColor = green
		levelText = "INF"
	default:
		levelColor = gray
		levelText = "DBG"
	}

	if h.useColors {
		return fmt.Sprintf("%s%s%-3s%s", bold, levelColor, levelText, reset)
	}
	return fmt.Sprintf("%-5s", level.String())
}

func (h *ColorHandler) formatValue(v slog.Value) string {
	switch v.Kind() {
	case slog.KindString:
		s := v.String()
		if h.useColors {
			return fmt.Sprintf("%s\"%s\"%s", yellow, s, reset)
		}
		return fmt.Sprintf("\"%s\"", s)
	case slog.KindInt64:
		if h.useColors {
			return fmt.Sprintf("%s%d%s", magenta, v.Int64(), reset)
		}
		return fmt.Sprintf("%d", v.Int64())
	case slog.KindUint64:
		if h.useColors {
			return fmt.Sprintf("%s%d%s", magenta, v.Uint64(), reset)
		}
		return fmt.Sprintf("%d", v.Uint64())
	case slog.KindFloat64:
		if h.useColors {
			return fmt.Sprintf("%s%.2f%s", magenta, v.Float64(), reset)
		}
		return fmt.Sprintf("%.2f", v.Float64())
	case slog.KindBool:
		if h.useColors {
			if v.Bool() {
				return fmt.Sprintf("%strue%s", green, reset)
			}
			return fmt.Sprintf("%sfalse%s", red, reset)
		}
		return fmt.Sprintf("%t", v.Bool())
	case slog.KindDuration:
		d := v.Duration()
		if h.useColors {
			return fmt.Sprintf("%s%s%s", blue, formatDuration(d), reset)
		}
		return formatDuration(d)
	case slog.KindTime:
		if h.useColors {
			return fmt.Sprintf("%s%s%s", gray, v.Time().Format(time.RFC3339), reset)
		}
		return v.Time().Format(time.RFC3339)
	default:
		if h.useColors {
			return fmt.Sprintf("%s%v%s", white, v.Any(), reset)
		}
		return fmt.Sprintf("%v", v.Any())
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	return d.String()
}

func (h *ColorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// For simplicity, we don't support pre-set attrs in this handler
	return h
}

func (h *ColorHandler) WithGroup(name string) slog.Handler {
	// For simplicity, we don't support groups in this handler
	return h
}
