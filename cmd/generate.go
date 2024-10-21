package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/containers/common/pkg/seccomp"
	"github.com/dorser/seccomp-ebpf/pkg/gadget"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type cmdOpts struct {
	profilePath string
	profileName string
	outputPath  string
}

func readSeccompProfile(filepath string) (*seccomp.Seccomp, error) {
	seccompProfileJSON, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("opening seccomp profile failed: %w", err)
	}

	var seccompProfile seccomp.Seccomp
	err = json.Unmarshal(seccompProfileJSON, &seccompProfile)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON: %v", err)
	}

	return &seccompProfile, nil
}

func getProfileName(opts *cmdOpts) string {
	if opts.profileName != "" {
		return opts.profileName
	}

	return strings.TrimSuffix(filepath.Base(opts.profilePath), filepath.Ext(opts.profilePath))
}

func generateCmd() *cobra.Command {
	opts := &cmdOpts{}

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate eBPF gadgets from a seccomp profile",
		RunE: func(_ *cobra.Command, _ []string) error {
			seccompProfile, err := readSeccompProfile(opts.profilePath)
			if err != nil {
				logrus.Error("Reading seccomp profile")
				return err
			}

			profileName := getProfileName(opts)
			gadgetCode, err := gadget.GenerateGadget(profileName, seccompProfile)
			if err != nil {
				return err
			}

			os.WriteFile(opts.outputPath, []byte(gadgetCode), 0644)

			logrus.Infof("Loaded seccomp profile successfully!")

			return nil
		},
	}

	cmd.Flags().StringVarP(&opts.profilePath, "profile", "p", "", "Path to the seccomp profile (required)")
	cmd.Flags().StringVarP(&opts.profileName, "name", "n", "", "The name of the generated profile gadget")
	cmd.Flags().StringVarP(&opts.outputPath, "output", "o", "gadget/program.bpf.c", "Path to save the generated gadget code")
	if err := cmd.MarkFlagRequired("profile"); err != nil {
		logrus.Warnf("mark profile flag required: %s", err.Error())
	}
	return cmd
}
