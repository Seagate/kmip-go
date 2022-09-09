package common

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"k8s.io/klog/v2"
)

// Store: Save all configuration settings to a JSON file
func Store(ctx context.Context, settings *ConfigurationSettings) (err error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("Store configuration settings", "config", settings.SettingsFile)

	// Convert object into JSON format
	js, err := json.MarshalIndent(settings, "", " ")
	if err != nil {
		fmt.Printf("unable to translate configuration settings to JSON, error: %v\n", err)
		return fmt.Errorf("unable to translate configuration settings to JSON, error: %v", err)
	}

	// Write report to file
	// Set permissions so that owner can read/write (6), group can read (first 4), all others can read (second 4)
	err = os.WriteFile(settings.SettingsFile, js, 0o644)
	if err != nil {
		fmt.Printf("unable to write configuration settings to storage, error: %v\n", err)
		return fmt.Errorf("unable to write configuration settings to storage, error: %v", err)
	}

	// fmt.Printf("configuration settings written to (%s)\n", settings.SettingsFile)
	return nil
}

// Restore: Read all configuration settings from a JSON file
func Restore(ctx context.Context, settings *ConfigurationSettings, filename string) (err error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("Restore configuration settings", "config", filename)

	file2, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("unable to restore configuration settings from (%s), error: %v\n", filename, err)
		return fmt.Errorf("unable to restore configuration settings from (%s), error: %v", filename, err)
	}

	err = json.Unmarshal([]byte(file2), settings)
	if err != nil {
		fmt.Printf("unable to unmarshal configuration settings from (%s), error: %v\n", filename, err)
		return fmt.Errorf("unable to unmarshal configuration settings from (%s), error: %v", filename, err)
	}

	// Set pointers to nil
	settings.Connection = nil

	return nil
}
