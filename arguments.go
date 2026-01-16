package main

// Version 0.2 - Beta
// arguments.go - Command Line Argument Parsing
// Author: CyberPanther232

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

func indexOf(slice []string, item string) int {
	for i, s := range slice {
		if s == item {
			return i
		}
	}
	return -1
}

func generateSampleConfig() error {

	if _, err := os.Stat("goshell.conf"); err == nil {
		f.Println("Configuration file 'goshell.conf' already exists. Aborting generation.")
		return nil
	}

	sampleConfig := `# Sample GoSHELL Configuration File
# Format:
# Host host_config_name
# Hostname your.ssh.server
# Port 22
# User your_username
# KeybasedAuthentication yes|no
# Password your_password (if using password auth)
# IdentityFile /path/to/your/private/key (if using key auth)
Host sample_host
Hostname example.com
Port 22
User testuser
KeybasedAuthentication yes
Password your_password_here # Only if not using key-based authentication
IdentityFile /path/to/your/private/key # Only if using key-based authentication
`

	err := os.WriteFile("goshell.conf", []byte(sampleConfig), 0644)
	if err != nil {
		return err
	}
	f.Println("Sample configuration file 'goshell.conf' generated.")
	return nil
}

func parseArgs(args []string) (map[string]string, error) {

	parsedArgs := make(map[string]string)

	if contains(args, "--help") {
		f.Println("GoSHELL - Version 0.2 - Beta - A Simple SSH Client in Go")
		f.Println("Usage: goshell [options]")
		f.Println("Options:")
		f.Println("  --help                     Show this help message")
		f.Println("  --verbose                  Enable verbose debug output")
		f.Println("  --config <file>            Specify alternative configuration file")
		f.Println("  --version                  Show version information")
		f.Println("  --host <host-config-name>  Specify host to connect to")
		f.Println("  --list-hosts               List available hosts in configuration")
		f.Println("  --generate-config          Generate a sample configuration file")
		f.Println("  --test                     Run in test mode (Tests if configuration profile loads correctly)")
		os.Exit(0)
	}

	if contains(args, "--verbose") {
		initDebug()
		f.Println("Verbose debug output enabled.")
		parsedArgs["verbose"] = "true"
	}

	if contains(args, "--generate-config") {
		err := generateSampleConfig()
		if err != nil {
			return nil, err
		}
		os.Exit(0)
	}

	// Allows user to specific alternative location for config file
	if contains(args, "--config") {
		idx := indexOf(args, "--config")
		if idx >= 0 && idx+1 < len(args) {
			parsedArgs["configurationPath"] = args[idx+1]
		} else {
			return nil, f.Errorf("--config requires a value")
		}
	}

	if contains(args, "--version") {
		f.Println("GoSHELL version 0.2 - Beta")
		os.Exit(0)
	}

	if contains(args, "--list-hosts") {

		configurationPath := "goshell.conf"

		if parsedArgs["configurationPath"] != "" {
			configurationPath = parsedArgs["configurationPath"]
			f.Println("Loading configuration from:", configurationPath)
		}

		configuration, err := loadConfig(configurationPath)
		if err != nil {
			return nil, err
		}

		if len(configuration) == 0 {
			f.Println("No hosts found in configuration.")
			return nil, nil
		}

		f.Println("Available Hosts:")
		for host := range configuration {
			f.Println(" -", host)
		}
		os.Exit(0)
	}

	if contains(args, "--host") {
		idx := indexOf(args, "--host")
		if idx >= 0 && idx+1 < len(args) {
			parsedArgs["host"] = args[idx+1]
		} else {
			return nil, f.Errorf("--host requires a value")
		}
	}

	if contains(args, "--test") {
		parsedArgs["test"] = "true"
		idx := indexOf(args, "--test")
		if idx >= 0 && idx+1 < len(args) {
			parsedArgs["host"] = args[idx+1]
		}
	}

	if contains(args, "--cmd") {
		idx := indexOf(args, "--cmd")
		if idx >= 0 && idx+1 < len(args) {
			parsedArgs["cmd"] = args[idx+1]
		} else {
			return nil, f.Errorf("--cmd requires a value")
		}
	}

	return parsedArgs, nil

}
