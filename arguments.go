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
# host_config_name
#   hostname your.ssh.server
#   port 22
#   user your_username
#   auth_method password|key
#   password your_password (if using password auth)
#   key_path /path/to/your/private/key (if using key auth)
sample_host
  hostname example.com
  port 22
  user testuser
  auth_method password
  password your_password_here
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
		// Future: Load config from specified file
		f.Println("Custom config file option not yet implemented.")
		parsedArgs["config"] = "custom"
	}

	if contains(args, "--version") {
		f.Println("GoSHELL version 0.1")
		os.Exit(0)
	}

	if contains(args, "--list-hosts") {
		configuration, err := loadConfig()
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
	}

	if len(parsedArgs) > 0 {
		return parsedArgs, nil
	}
	return nil, nil

}
