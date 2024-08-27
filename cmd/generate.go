package main

import (
	"fmt"
	"github.com/dorser/seccomp-ebpf/pkg/gadget"
	"github.com/dorser/seccomp-ebpf/pkg/seccomp"
	"github.com/spf13/cobra"
	"os"
)

type cmdOpts struct {
	profilePath string
	outputPath  string
}

func generateCmd() *cobra.Command {
	opts := &cmdOpts{}

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate eBPF gadgets from a seccomp profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, err := seccomp.LoadProfile(opts.profilePath)
			if err != nil {
				return fmt.Errorf("failed to load seccomp profile: %v", err)
			}

			fmt.Println("Loaded seccomp profile successfully!")
			gadgetCode, err := gadget.GenerateGadgetCode(profile)
			if err != nil {
				return fmt.Errorf("failed to generate gadget code: %v", err)
			}

			err = os.WriteFile(opts.outputPath, []byte(gadgetCode), 0644)
			if err != nil {
				return fmt.Errorf("failed to write gadget code to file: %v", err)
			}

			fmt.Printf("Gadget code generated and saved to %s\n", opts.outputPath)

			return nil
		},
	}

	cmd.Flags().StringVarP(&opts.profilePath, "profile", "p", "", "Path to the seccomp profile (required)")
	cmd.Flags().StringVarP(&opts.outputPath, "output", "o", "program.bpf.c", "Path to save the generated gadget code")
	cmd.MarkFlagRequired("profile")
	return cmd
}
