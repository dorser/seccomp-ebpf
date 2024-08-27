package main

import (
	"github.com/spf13/cobra"
	"os"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "seccomp-ebpf",
		Short: "Seccomp to eBPF gadget CLI Tool",
		Long:  "This tool reads a seccomp profile and generates eBPF gadget code to notify when a syscall is called with specified parameters.",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	rootCmd.AddCommand(generateCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
