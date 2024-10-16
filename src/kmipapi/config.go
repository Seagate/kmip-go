package kmipapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/Seagate/kmip-go/pkg/common"
)

var kmsConfigurationFile = "kms.json"

// Store: Save all configuration settings to a JSON file
func Store(ctx context.Context, settings *ConfigurationSettings) (err error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Info("Store configuration settings", "config", kmsConfigurationFile)

	// Convert object into JSON format
	js, err := json.MarshalIndent(settings, "", " ")
	if err != nil {
		fmt.Printf("unable to translate configuration settings to JSON, error: %v\n", err)
		return fmt.Errorf("unable to translate configuration settings to JSON, error: %v", err)
	}

	// Write report to file
	// Set permissions so that owner can read/write (6), group can read (first 4), all others can read (second 4)
	err = os.WriteFile(kmsConfigurationFile, js, 0o644)
	if err != nil {
		fmt.Printf("store unable to write configuration settings to storage, error: %v\n", err)
		return fmt.Errorf("store unable to write configuration settings to storage, error: %v", err)
	}

	return nil
}

// Restore: Read all configuration settings from a JSON file
func Restore(ctx context.Context, settings *ConfigurationSettings, filename string) (err error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("Restore configuration settings", "filename", filename)

	if filename == "" {
		filename = kmsConfigurationFile
	}

	if _, err := os.Stat(kmsConfigurationFile); err == nil {
		logger.Debug("configuration file exists", "filename", filename)
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

	} else {
		logger.Debug("configuration file does NOT exist", "filename", filename)
		file, err := os.Create(filename)
		if err != nil {
			return fmt.Errorf("unable to create file, error: %v", err)
		}
		defer file.Close()

		// Convert object into JSON format
		js, err := json.MarshalIndent(settings, "", " ")
		if err != nil {
			fmt.Printf("unable to translate configuration settings to JSON, error: %v\n", err)
			return fmt.Errorf("unable to translate configuration settings to JSON, error: %v", err)
		}

		// Write report to file
		// Set permissions so that owner can read/write (6), group can read (first 4), all others can read (second 4)
		_, err = file.Write(js)
		if err != nil {
			fmt.Printf("create unable to write configuration settings to storage, error: %v\n", err)
			return fmt.Errorf("create unable to write configuration settings to storage, error: %v", err)
		}
	}

	return nil
}
