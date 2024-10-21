package gadget

import (
	// _ "embed"
	"github.com/containers/common/pkg/seccomp"
)

type Rule struct {
	Action seccomp.Action
}

type Rules []Rule

type TemplateProfile struct {
	Name          string
	DefaultAction seccomp.Action
	Syscalls      map[string]Rules
}

// //go:embed gadget.tmpl
// var gadgetTemplate string

func shouldDiscardSyscall(_ *seccomp.Syscall) bool {
	return false
}

func seccompToTemplateData(profileName string, seccompProfile *seccomp.Seccomp) (TemplateProfile, error) {
	templateProfile := TemplateProfile{
		Name:          profileName,
		DefaultAction: seccompProfile.DefaultAction,
		Syscalls:      make(map[string]Rules),
	}

	for _, seccompSyscall := range seccompProfile.Syscalls {
		if !shouldDiscardSyscall(seccompSyscall) {
			syscallNames := seccompSyscall.Names

			// If "Name" is set, we ignore "Names"
			if seccompSyscall.Name != "" {
				syscallNames = []string{seccompSyscall.Name}
			}

			for _, syscallName := range syscallNames {
				if _, exists := templateProfile.Syscalls[syscallName]; !exists {
					templateProfile.Syscalls[syscallName] = Rules{}
				}

				templateProfile.Syscalls[syscallName] = append(templateProfile.Syscalls[syscallName], Rule{Action: seccompSyscall.Action})
			}
		}
	}

	return templateProfile, nil
}

func generateGadgetTemplate(profileName string, seccompProfile *seccomp.Seccomp) error {
	_, err := seccompToTemplateData(profileName, seccompProfile)
	if err != nil {
		return err
	}
	return nil
}

func GenerateGadget(profileName string, seccompProfile *seccomp.Seccomp) error {
	err := generateGadgetTemplate(profileName, seccompProfile)
	if err != nil {
		return err
	}
	return nil
}
