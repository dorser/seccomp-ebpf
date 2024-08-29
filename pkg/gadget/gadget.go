package gadget

import (
	_ "embed"
	"fmt"
	"github.com/dorser/seccomp-ebpf/pkg/seccomp"
	"github.com/dorser/seccomp-ebpf/pkg/syscalls"
	"strings"
	"text/template"
)

type TemplateData struct {
	Name     string
	Syscalls syscalls.SyscallMap
}

//go:embed gadget.tmpl
var gadgetTemplate string

func GenerateGadgetCode(gadgetName string, profile *seccomp.SeccompProfile) (string, error) {

	tmpl, err := template.New("gadgetTemplate").Parse(gadgetTemplate)
	if err != nil {
		return "", fmt.Errorf("Error parsing template: %v", err)
	}

	syscallsMap := syscalls.LoadSystemMap("x86_64")

	for _, syscall := range profile.Syscalls {
		for _, name := range syscall.Names {
			if syscall.Action == "SCMP_ACT_ALLOW" {
				delete(syscallsMap, name)
			}
		}
	}

	data := TemplateData{
		Name:     gadgetName,
		Syscalls: syscallsMap,
	}

	var output strings.Builder

	err = tmpl.Execute(&output, data)
	if err != nil {
		return "", fmt.Errorf("Error executing template: %v", err)
	}

	return output.String(), nil

}
