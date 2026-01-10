package main

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