package udig

import (
	"fmt"
	"os"
)

// Logging levels: the smaller value the more verbose the output will be.
const (
	LogLevelDebug = 0
	LogLevelInfo  = 10
	LogLevelWarn  = 100
	LogLevelErr   = 1000
	LogLevelNone  = 10000
)

const (
	errColor   = "\033[1;91m"
	warnColor  = "\033[93m"
	infoColor  = "\033[1;92m"
	debugColor = ""
	noColor    = "\033[0m"
)

// LogLevel contains the actual log level setting.
var LogLevel = LogLevelInfo

// LogPanic formats and prints a given log on STDERR and panics.
func LogPanic(format string, a ...interface{}) {
	LogErr(format, a...)
	panic(fmt.Sprintf(format, a...))
}

// LogErr formats and prints a given log on STDERR.
func LogErr(format string, a ...interface{}) {
	if LogLevel <= LogLevelErr {
		fmt.Fprintf(os.Stderr, errColor+"[!] "+format+"\n"+noColor, a...)
	}
}

// LogWarn formats and prints a given log on STDERR.
func LogWarn(format string, a ...interface{}) {
	if LogLevel <= LogLevelErr {
		fmt.Fprintf(os.Stderr, warnColor+"[!] "+format+"\n"+noColor, a...)
	}
}

// LogInfo formats and prints a given log on STDOUT.
func LogInfo(format string, a ...interface{}) {
	if LogLevel <= LogLevelInfo {
		fmt.Printf(infoColor+"[+] "+format+"\n"+noColor, a...)
	}
}

// LogDebug formats and prints a given log on STDOUT.
func LogDebug(format string, a ...interface{}) {
	if LogLevel <= LogLevelDebug {
		fmt.Printf(debugColor+"[~] "+format+"\n"+noColor, a...)
	}
}
