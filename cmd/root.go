package cmd

import (
	"context"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	appName                    = "eth-ejector"
	defaultFormatterConsoleUse = &logrus.TextFormatter{FullTimestamp: true}
)

func init() {
	logrus.SetFormatter(defaultFormatterConsoleUse)
}

// NewRootCmd returns the root command.
func NewRootCmd() *cobra.Command {
	// RootCmd represents the base command when called without any subcommands
	var rootCmd = &cobra.Command{
		Use:   appName,
		Short: "eth ejector",
	}

	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {

		return nil
	}

	rootCmd.AddCommand(
		startCmd(),
		versionCmd(),
	)
	return rootCmd
}

func Execute() {
	cobra.EnableCommandSorting = false

	rootCmd := NewRootCmd()
	rootCmd.SilenceUsage = true
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	ctx := context.Background()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
