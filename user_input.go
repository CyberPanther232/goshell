package main

// Version 0.2 - Beta
// user_input.go - User Input Handling
// Author: CyberPanther232

import (
	bufio "bufio"
	f "fmt"
	"os"
	"strings"
)

func getUserInput(prompt string) string {
	f.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}
