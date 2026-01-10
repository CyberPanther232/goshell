package main

import (
	f "fmt"
	"os"
)

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func parseArgs(args []string) (string, error) {

	if contains(args, "--help") {
		f.Println("GoSHELL - A Simple SSH Client in Go")
		f.Println("Usage: goshell [options]")
		f.Println("Options:")
		f.Println("  --help                     Show this help message")
		f.Println("  --verbose                  Enable verbose debug output")
		f.Println("  --config <file>            Specify alternative configuration file")
		f.Println("  --version                  Show version information")
		f.Println("  --host <host-config-name>  Specify host to connect to")
		os.Exit(0)
	}

	if contains(args, "--verbose") {
		initDebug()
		f.Println("Verbose debug output enabled.")
	}

	// Allows user to specific alternative location for config file
	if contains(args, "--config") {
		// Future: Load config from specified file
		f.Println("Custom config file option not yet implemented.")
		return "", nil
	}

	if contains(args, "--version") {
		f.Println("GoSHELL version 0.1")
		os.Exit(0)
	}

	if contains(args, "--host") {
		// Future: Directly connect to specified host
		f.Println("Direct host connection option not yet implemented.")
		return string(args[+1]), nil
	}

	return "", nil

}
