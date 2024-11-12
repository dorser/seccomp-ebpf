package gadget

import (
	"embed"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"text/template"

	"github.com/containers/common/pkg/seccomp"
	"github.com/dorser/seccomp-ebpf/pkg/syscalls"
	"github.com/dorser/seccomp-ebpf/pkg/tracepoints"
	"github.com/sirupsen/logrus"
)

const (
	SCMP_CMP_EQ        string = "SCMP_CMP_EQ"
	SCMP_CMP_NE        string = "SCMP_CMP_NE"
	SCMP_CMP_LT        string = "SCMP_CMP_LT"
	SCMP_CMP_LE        string = "SCMP_CMP_LE"
	SCMP_CMP_GT        string = "SCMP_CMP_GT"
	SCMP_CMP_GE        string = "SCMP_CMP_GE"
	SCMP_CMP_MASKED_EQ string = "SCMP_CMP_MASKED_EQ"
)

func convertSeccompOperator(op seccomp.Operator) (string, error) {
	switch op {
	case seccomp.OpEqualTo:
		return "==", nil
	case seccomp.OpNotEqual:
		return "!=", nil
	case seccomp.OpLessThan:
		return "<", nil
	case seccomp.OpLessEqual:
		return "<=", nil
	case seccomp.OpGreaterThan:
		return ">", nil
	case seccomp.OpGreaterEqual:
		return ">=", nil
	case seccomp.OpMaskedEqual:
		return "&", nil
	default:
		return "", fmt.Errorf("unsupported seccomp operator: %s", op)
	}
}

type Arg struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo"`
	Op       string `json:"op"`
}

type SyscallRule struct {
	Action   seccomp.Action
	Args     []Arg
	Includes seccomp.Filter
	Excludes seccomp.Filter
	Errno    string
}

type Syscall struct {
	Rules       []SyscallRule
	ArgsIndices map[uint]uint
}

type GadgetCodeTemplateData struct {
	Name           string
	DefaultAction  seccomp.Action
	Syscalls       map[string]Syscall
	RawTracepoints map[string]seccomp.Action
}

type MakefileTemplateData struct {
	Name string
}

//go:embed program.bpf.c.tmpl
var gadgetCodeTemplate string

//go:embed Makefile.tmpl
var makeFileTemplate string

//go:embed include
var includeFiles embed.FS

func shouldDiscardSyscallObject(seccompSyscall *seccomp.Syscall, arch string) bool {
	// Defaulting to x86_64
	if arch == "" {
		// https://github.com/seccomp/libseccomp-golang/blob/main/seccomp.go#L327
		arch = "amd64"
	}

	var isArchIncluded bool = true
	if len(seccompSyscall.Includes.Arches) > 0 {
		isArchIncluded = slices.Contains(seccompSyscall.Includes.Arches, arch)
	}

	var isArchExcluded bool = false
	if len(seccompSyscall.Includes.Arches) > 0 {
		isArchExcluded = slices.Contains(seccompSyscall.Excludes.Arches, arch)
	}

	return !isArchIncluded || isArchExcluded
}

func tracepointExists(syscallName string) bool {
	exists := tracepoints.SyscallHasEnterTracepoint(syscallName)
	if !exists {
		logrus.Warnf("tracepoint doesn't exist for: %s. Using raw tracepoint", syscallName)
	}
	return exists
}

func shouldDiscardSyscallByName(syscallName string) bool {
	exists := syscalls.SyscallExists(syscallName)
	if !exists {
		logrus.Debugf("syscall %s doesn't exist. Ignoring.", syscallName)
	}
	return !exists
}

func seccompToTemplateData(profileName string, seccompProfile *seccomp.Seccomp) (GadgetCodeTemplateData, error) {
	defaultAction := seccompProfile.DefaultAction

	templateProfile := GadgetCodeTemplateData{
		Name:           profileName,
		DefaultAction:  defaultAction,
		Syscalls:       make(map[string]Syscall),
		RawTracepoints: make(map[string]seccomp.Action),
	}

	for _, seccompSyscall := range seccompProfile.Syscalls {
		if !shouldDiscardSyscallObject(seccompSyscall, "") {
			syscallNames := seccompSyscall.Names

			// If "Name" is set, we ignore "Names"
			if seccompSyscall.Name != "" {
				syscallNames = []string{seccompSyscall.Name}
			}

			for _, syscallName := range syscallNames {
				if !shouldDiscardSyscallByName(syscallName) {
					if tracepointExists(syscallName) {
						if _, exists := templateProfile.Syscalls[syscallName]; !exists {
							templateProfile.Syscalls[syscallName] = Syscall{
								Rules:       []SyscallRule{},
								ArgsIndices: make(map[uint]uint),
							}
						}

						syscallRules := templateProfile.Syscalls[syscallName].Rules
						argsIndices := templateProfile.Syscalls[syscallName].ArgsIndices
						args := []Arg{}
						for _, seccompArg := range seccompSyscall.Args {
							op, err := convertSeccompOperator(seccompArg.Op)
							if err != nil {
								return GadgetCodeTemplateData{}, err
							}

							if _, exists := argsIndices[seccompArg.Index]; !exists {
								argsIndices[seccompArg.Index] = seccompArg.Index
							}
							args = append(args, Arg{
								Index:    seccompArg.Index,
								Value:    seccompArg.Value,
								ValueTwo: seccompArg.ValueTwo,
								Op:       op,
							})
						}
						syscallRule := SyscallRule{
							Action:   seccompSyscall.Action,
							Args:     args,
							Includes: seccompSyscall.Includes,
							Excludes: seccompSyscall.Excludes,
							Errno:    seccompSyscall.Errno,
						}

						syscallRules = append(syscallRules, syscallRule)
						templateProfile.Syscalls[syscallName] = Syscall{
							Rules:       syscallRules,
							ArgsIndices: argsIndices,
						}
					} else {
						// We currently do not support filters for syscalls that doesn't have tracepoints
						// This is a naive approach, as it'll take the action of last rule processed for this syscall
						templateProfile.RawTracepoints["__NR_"+syscallName] = seccompSyscall.Action
					}
				}
			}
		}
	}

	return templateProfile, nil
}

func sub(a, b int) int {
	return a - b
}

func syscallHasFilters(syscall Syscall) bool {
	for _, rule := range syscall.Rules {
		if len(rule.Includes.Caps) > 0 || len(rule.Excludes.Caps) > 0 || len(rule.Args) > 0 {
			return true
		}
	}
	return false
}

func syscallHasCapsFilters(syscall Syscall) bool {
	for _, rule := range syscall.Rules {
		if len(rule.Includes.Caps) > 0 || len(rule.Excludes.Caps) > 0 {
			return true
		}
	}
	return false
}

func generateGadgetCodeTemplate(profileName string, seccompProfile *seccomp.Seccomp) (string, error) {
	templateProfile, err := seccompToTemplateData(profileName, seccompProfile)
	if err != nil {
		return "", err
	}

	tmpl, err := template.New("gadgetTemplate").Funcs(template.FuncMap{
		"sub":                   sub,
		"syscallHasFilters":     syscallHasFilters,
		"syscallHasCapsFilters": syscallHasCapsFilters,
	}).Parse(gadgetCodeTemplate)
	if err != nil {
		return "", fmt.Errorf("error parsing template: %v", err)
	}

	var output strings.Builder
	err = tmpl.Execute(&output, templateProfile)
	if err != nil {
		return "", fmt.Errorf("error executing template: %v", err)
	}

	return output.String(), nil
}

func generateMakefileTemplate(profileName string) (string, error) {
	tmpl, err := template.New("gadgetManigestTemplate").Parse(makeFileTemplate)
	if err != nil {
		return "", fmt.Errorf("error parsing manigest template: %v", err)
	}

	var output strings.Builder
	err = tmpl.Execute(&output, MakefileTemplateData{Name: profileName})
	if err != nil {
		return "", fmt.Errorf("error executing template: %v", err)
	}

	return output.String(), nil
}

func GenerateGadget(profileName string, seccompProfile *seccomp.Seccomp) (map[string]string, error) {
	gadgetCode, err := generateGadgetCodeTemplate(profileName, seccompProfile)
	gadgetFiles := make(map[string]string)
	if err != nil {
		return gadgetFiles, err
	}

	makefile, err := generateMakefileTemplate((profileName))
	if err != nil {
		return gadgetFiles, err
	}

	gadgetFiles["program.bpf.c"] = gadgetCode
	gadgetFiles["Makefile"] = makefile
	files, err := includeFiles.ReadDir("include")
	if err != nil {
		return gadgetFiles, fmt.Errorf("reading include: %w", err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		data, err := includeFiles.ReadFile(filepath.Join("include", file.Name()))
		if err != nil {
			return gadgetFiles, fmt.Errorf("reading include file: %w", err)
		}

		gadgetFiles[file.Name()] = string(data)
	}

	return gadgetFiles, nil
}
