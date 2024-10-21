package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/containers/common/pkg/seccomp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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
		RunE: func(_ *cobra.Command, _ []string) error {
			seccompProfileJSON, err := os.ReadFile(opts.profilePath)
			if err != nil {
				return fmt.Errorf("opening seccomp profile failed: %w", err)
			}

			var seccompProfile seccomp.Seccomp
			err = json.Unmarshal(seccompProfileJSON, &seccompProfile)
			if err != nil {
				return fmt.Errorf("error unmarshaling JSON: %v", err)
			}

			logrus.Infof("Loaded seccomp profile successfully!")

			return nil
		},
	}

	cmd.Flags().StringVarP(&opts.profilePath, "profile", "p", "", "Path to the seccomp profile (required)")
	cmd.Flags().StringVarP(&opts.outputPath, "output", "o", "program.bpf.c", "Path to save the generated gadget code")
	if err := cmd.MarkFlagRequired("profile"); err != nil {
		logrus.Warnf("mark profile flag required: %s", err.Error())
	}
	return cmd
}
