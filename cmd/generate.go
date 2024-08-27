package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dorser/seccomp-ebpf/pkg/gadget"
	"github.com/dorser/seccomp-ebpf/pkg/seccomp"
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
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, err := seccomp.LoadProfile(opts.profilePath)
			if err != nil {
				return fmt.Errorf("load seccomp profile: %v", err)
			}

			logrus.Infof("Loaded seccomp profile successfully!")
			gadgetCode, err := gadget.GenerateGadgetCode(getGadgetNameFromProfilePath(opts.profilePath), profile)
			if err != nil {
				return fmt.Errorf("generate gadget code: %v", err)
			}

			err = os.WriteFile(opts.outputPath, []byte(gadgetCode), 0644)
			if err != nil {
				return fmt.Errorf("write gadget code to file: %v", err)
			}

			logrus.Infof("Gadget code generated and saved to %s\n", opts.outputPath)

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

func getGadgetNameFromProfilePath(path string) string {
	return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
}
