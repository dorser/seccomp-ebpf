package gadget

import (
	"fmt"
	"github.com/dorser/seccomp-ebpf/pkg/seccomp"
	"strings"
	"text/template"
)

type TemplateData struct {
	Name     string
	Syscalls []string
}

func GenerateGadgetCode(gadgetName string, profile *seccomp.SeccompProfile) (string, error) {
	tmpl, err := template.New("gadgetTemplate").Parse(gadgetTemplate)
	if err != nil {
		return "", fmt.Errorf("Error parsing template: %v", err)
	}

	var syscalls []string

	for _, syscall := range profile.Syscalls {
		syscalls = append(syscalls, syscall.Names...)
	}

	data := TemplateData{
		Name:     gadgetName,
		Syscalls: syscalls,
	}

	var output strings.Builder

	err = tmpl.Execute(&output, data)
	if err != nil {
		return "", fmt.Errorf("Error executing template: %v", err)
	}

	return output.String(), nil

}
