package udig

import (
	"fmt"
	"os"
)

const LogLevelDebug = 0
const LogLevelInfo = 10
const LogLevelErr = 100
const LogLevelNone = 1000

var LogLevel = LogLevelDebug

func LogPanic(format string, a ...interface{}) {
	LogErr(format, a)
	panic(nil)
}

func LogErr(format string, a ...interface{}) {
	if LogLevel <= LogLevelErr {
		fmt.Fprintf(os.Stderr,"[!] " + format + "\n", a...)
	}
}

func LogInfo(format string, a ...interface{}) {
	if LogLevel <= LogLevelInfo {
		fmt.Printf("[+] " + format + "\n", a...)
	}
}

func LogDebug(format string, a ...interface{}) {
	if LogLevel <= LogLevelDebug {
		fmt.Printf("[~] " + format + "\n", a...)
	}
}