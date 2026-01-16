package main

import (
	"fmt"
	"os"
	"time"
)

var debugFile *os.File

func initDebug() {
	f, err := os.OpenFile("debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	debugFile = f
}

func logDebug(format string, args ...interface{}) {
	if debugFile != nil {
		timestamp := time.Now().Format("15:04:05.000")
		fmt.Fprintf(debugFile, "["+timestamp+"] "+format+"\n", args...)
	}
}

// vprintln prints to stdout only when verbose mode is enabled.
func vprintln(a ...interface{}) {
	if debugFile != nil {
		fmt.Println(a...)
	}
}

// vprintf prints to stdout only when verbose mode is enabled.
func vprintf(format string, a ...interface{}) {
	if debugFile != nil {
		fmt.Printf(format, a...)
	}
}
