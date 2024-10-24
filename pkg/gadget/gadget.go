package gadget

import (
	_ "embed"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/template"

	"github.com/containers/common/pkg/seccomp"
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

type TemplateProfile struct {
	Name          string
	DefaultAction seccomp.Action
	Syscalls      map[string]Syscall
}

//go:embed gadget.tmpl
var gadgetTemplate string

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
	tracepointBase := "/sys/kernel/tracing/events/syscalls/sys_enter_"
	if _, err := os.Stat(tracepointBase + syscallName); err != nil {
		if os.IsNotExist(err) {
			logrus.Warnf("tracepoint doesn't exist for: %s", syscallName)
			return false
		}
		logrus.Errorf("error reading format for syscall: %s. error: %v", syscallName, err)
		return false
	}
	return true
}

func shouldDiscardSyscallByName(syscallName string) bool {
	return !tracepointExists(syscallName)
}

func seccompToTemplateData(profileName string, seccompProfile *seccomp.Seccomp) (TemplateProfile, error) {
	defaultAction := seccompProfile.DefaultAction

	templateProfile := TemplateProfile{
		Name:          profileName,
		DefaultAction: defaultAction,
		Syscalls:      make(map[string]Syscall),
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
							return TemplateProfile{}, err
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
				}
			}
		}
	}

	return templateProfile, nil
}

func generateGadgetTemplate(profileName string, seccompProfile *seccomp.Seccomp) (string, error) {
	templateProfile, err := seccompToTemplateData(profileName, seccompProfile)
	if err != nil {
		return "", err
	}

	tmpl, err := template.New("gadgetTemplate").Parse(gadgetTemplate)
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

func GenerateGadget(profileName string, seccompProfile *seccomp.Seccomp) (string, error) {
	gadgetCode, err := generateGadgetTemplate(profileName, seccompProfile)
	if err != nil {
		return "", err
	}

	return gadgetCode, nil
}
