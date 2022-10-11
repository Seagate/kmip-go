package kmipapi

import (
	"fmt"
	"strings"
)

const (
	LastUID = "lastuid"
)

var g_variables = map[string]string{}

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

	// Check the special case where the user passed in a ${variable}
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		variable := strings.Replace(value, "${", "", 1)
		variable = strings.Replace(variable, "}", "", 1)

		newvalue, ok := g_variables[variable]
		if ok {
			value = newvalue
		} else {
			fmt.Printf("No value stored for (%s)\n", variable)
		}
	}

	return value
}

// SetValue: store a value in a global table to be used with script variables ${variable}
func SetValue(key, value string) {
	g_variables[key] = value
}
