package udig

import (
	"fmt"
	"os"
)

// Logging levels: the smaller value the more verbose the output will be.
const (
	LogLevelDebug = 0
	LogLevelInfo  = 10
	LogLevelErr   = 100
	LogLevelNone  = 1000
)

// LogLevel contains the actual log level setting.
var LogLevel = LogLevelDebug

// LogPanic formats and prints a given log on STDERR and panics.
func LogPanic(format string, a ...interface{}) {
	LogErr(format, a)
	panic(nil)
}

// LogErr formats and prints a given log on STDERR.
func LogErr(format string, a ...interface{}) {
	if LogLevel <= LogLevelErr {
		fmt.Fprintf(os.Stderr, "[!] "+format+"\n", a...)
	}
}

// LogInfo formats and prints a given log on STDOUT.
func LogInfo(format string, a ...interface{}) {
	if LogLevel <= LogLevelInfo {
		fmt.Printf("[+] "+format+"\n", a...)
	}
}

// LogDebug formats and prints a given log on STDOUT.
func LogDebug(format string, a ...interface{}) {
	if LogLevel <= LogLevelDebug {
		fmt.Printf("[~] "+format+"\n", a...)
	}
}
