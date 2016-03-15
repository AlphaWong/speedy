package logging

import (
	"fmt"
	"io"
	"text/template"
	"time"
)

// Level describes how bad things have gotten
type Level uint

func (l Level) String() string {
	switch {
	case l == TRACE:
		return "trace"
	case l == DEBUG:
		return "debug"
	case l == INFO:
		return "info"
	case l == WARN:
		return "warn"
	case l == ERROR:
		return "error"
	}
	return fmt.Sprintf("%d", l)
}

// TRACE for when you're needy
const TRACE Level = 10

// DEBUG for when you need to know
const DEBUG Level = 20

// INFO for when you just want to know
const INFO Level = 30

// WARN for when things seem suspect
const WARN Level = 40

// ERROR for when things are way past good
const ERROR Level = 50

// TimeKey is the key you can use in a template
const TimeKey string = "time"

// LevelKey is the key for placing the level
const LevelKey string = "level"

// MsgKey is the key for the message
const MsgKey string = "msg"

var defaultFormat, _ = template.New("log-format").Parse("{{.time}} : {{.level}} : {{.msg}}\n")

// Logger is the interface for logging information
type Logger struct {
	currentLevel Level
	logTemplate  *template.Template
	writer       io.Writer
	timeFormat   string
}

// Error will log at ERROR level, special handling for error as the last arg
func (l Logger) Error(templateString string, args ...interface{}) error {
	return l.Log(ERROR, templateString, args)
}

// Warn does what it says
func (l Logger) Warn(templateString string, args ...interface{}) error {
	return l.Log(WARN, templateString, args...)
}

// Info logs at info level
func (l Logger) Info(templateString string, args ...interface{}) error {
	return l.Log(INFO, templateString, args...)
}

// Debug logs at debug level
func (l Logger) Debug(templateString string, args ...interface{}) error {
	return l.Log(DEBUG, templateString, args...)
}

// Trace logs at trace level
func (l Logger) Trace(templateString string, args ...interface{}) error {
	return l.Log(TRACE, templateString, args...)
}

// Log logs what it is told
func (l Logger) Log(level Level, templateString string, args ...interface{}) error {
	if l.currentLevel <= level {
		msg := map[string]string{
			MsgKey:   fmt.Sprintf(templateString, args...),
			TimeKey:  time.Now().Format(l.timeFormat),
			LevelKey: fmt.Sprintf("%s", level),
		}

		return l.logTemplate.Execute(l.writer, msg)
	}

	return nil
}

// NewLogger returns a logger instance with the specified backend
func NewLogger(writer io.Writer) (*Logger, error) {
	l := new(Logger)
	l.currentLevel = INFO
	l.writer = writer
	l.logTemplate = defaultFormat
	l.timeFormat = time.RFC3339

	return l, nil
}
