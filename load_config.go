package main

// Version 0.2 - Beta
// load_config.go - Configuration Loading and Parsing
// Author: CyberPanther232

import (
	"os"
	"strconv"
	"strings"
)

type HostConfig struct {
	Host                   string
	Port                   int
	User                   string
	KeybasedAuthentication bool
	IdentityFile           string
	Hostname               string
}

func loadConfig(configurationPath string) (map[string]HostConfig, error) {
	if _, err := os.Stat(configurationPath); os.IsNotExist(err) {
		return map[string]HostConfig{}, nil
	}

	data, err := os.ReadFile(configurationPath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")

	cfgs := map[string]HostConfig{}
	var current HostConfig

	commitCurrent := func() {
		if strings.TrimSpace(current.Host) != "" {
			cfgs[current.Host] = current
		}
		current = HostConfig{}
	}

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			commitCurrent()
			continue
		}

		sp := strings.IndexFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
		var key, val string
		if sp == -1 {
			key = line
			val = ""
		} else {
			key = strings.TrimSpace(line[:sp])
			val = strings.TrimSpace(line[sp+1:])
		}

		switch key {
		case "Host":
			if strings.TrimSpace(current.Host) != "" {
				commitCurrent()
			}
			current.Host = val
		case "Port":
			p, _ := strconv.Atoi(val)
			current.Port = p
		case "User":
			current.User = val
		case "KeybasedAuthentication":
			current.KeybasedAuthentication = parseYesNo(val)
		case "IdentityFile":
			current.IdentityFile = val
		case "Hostname":
			current.Hostname = val
		}
	}

	commitCurrent()
	return cfgs, nil
}

func parseYesNo(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "yes", "true", "1", "y":
		return true
	default:
		return false
	}
}
