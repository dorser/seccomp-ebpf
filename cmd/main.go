package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "seccomp-ebpf",
		Short: "Seccomp to eBPF gadget CLI Tool",
		Long:  "Create and execute eBPF gadgets created from seccomp profiles",
		Run: func(cmd *cobra.Command, args []string) {
			if err := cmd.Help(); err != nil {
				logrus.Warnf("printing help: %s", err.Error())
			}
		},
	}

	rootCmd.AddCommand(generateCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
