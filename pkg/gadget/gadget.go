package gadget

import (
	_ "embed"
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/containers/common/pkg/seccomp"
	"github.com/sirupsen/logrus"
)

type Syscall struct {
	Action   seccomp.Action
	Args     []*seccomp.Arg
	Includes seccomp.Filter
	Excludes seccomp.Filter
	Errno    string
}

type TemplateProfile struct {
	Name          string
	DefaultAction seccomp.Action
	Syscalls      map[string][]Syscall
}

//go:embed gadget.tmpl
var gadgetTemplate string

func shouldDiscardSyscallObject(_ *seccomp.Syscall) bool {
	return false
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
		Syscalls:      make(map[string][]Syscall),
	}

	for _, seccompSyscall := range seccompProfile.Syscalls {
		if !shouldDiscardSyscallObject(seccompSyscall) {
			syscallNames := seccompSyscall.Names

			// If "Name" is set, we ignore "Names"
			if seccompSyscall.Name != "" {
				syscallNames = []string{seccompSyscall.Name}
			}

			for _, syscallName := range syscallNames {
				if !shouldDiscardSyscallByName(syscallName) {
					if _, exists := templateProfile.Syscalls[syscallName]; !exists {
						templateProfile.Syscalls[syscallName] = []Syscall{}
					}

					syscallRule := Syscall{
						Action:   seccompSyscall.Action,
						Args:     seccompSyscall.Args,
						Includes: seccompSyscall.Includes,
						Excludes: seccompSyscall.Excludes,
						Errno:    seccompSyscall.Errno,
					}

					templateProfile.Syscalls[syscallName] = append(templateProfile.Syscalls[syscallName], syscallRule)
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
