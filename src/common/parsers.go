package common

import (
	"strings"
)

// GetCommand: returns the first string from a command line, separated by spaces
func GetCommand(line string) string {
	command := ""
	s := strings.Split(line, " ")
	if len(s) > 0 {
		command = s[0]
	}
	return command
}

// GetValue: returns a value from a key=value pair
func GetValue(line, key string) string {
	value := ""
	pairs := strings.Split(line, " ")

	for _, pair := range pairs {
		if strings.Contains(pair, "=") {
			kv := strings.Split(pair, "=")
			if len(kv) == 2 {
				if kv[0] == key {
					value = kv[1]
					break
				}
			}
		}
	}

	return value
}
