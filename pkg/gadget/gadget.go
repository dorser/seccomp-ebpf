package gadget

import (
	_ "embed"
	"fmt"
	"github.com/dorser/seccomp-ebpf/pkg/seccomp"
	"github.com/dorser/seccomp-ebpf/pkg/syscalls"
	"strings"
	"text/template"
)

type templateSyscall struct {
	Name   string
	Nr     int64
	Action string
	Args   []seccomp.Arg
}

type TemplateData struct {
	Name     string
	Syscalls map[string]templateSyscall
}

//go:embed gadget.tmpl
var gadgetTemplate string

func GenerateGadgetCode(gadgetName string, profile *seccomp.SeccompProfile) (string, error) {

	tmpl, err := template.New("gadgetTemplate").Parse(gadgetTemplate)
	if err != nil {
		return "", fmt.Errorf("Error parsing template: %v", err)
	}

	syscallsMap := syscalls.LoadSystemMap("x86_64")

	templateData := TemplateData{Name: gadgetName, Syscalls: make(map[string]templateSyscall)}
	for _, syscall := range profile.Syscalls {
		for _, name := range syscall.Names {
			templateDataEntry := templateSyscall{
				Name:   name,
				Nr:     syscallsMap[name],
				Action: syscall.Action,
			}

			templateDataEntry.Args = append(templateDataEntry.Args, syscall.Args...)
			templateDataEntry.Args = append(templateDataEntry.Args, templateData.Syscalls[name].Args...)
			templateData.Syscalls[name] = templateDataEntry
			delete(syscallsMap, name)
		}
	}

	for name, nr := range syscallsMap {
		templateData.Syscalls[name] = templateSyscall{
			Name:   name,
			Nr:     nr,
			Action: profile.DefaultAction,
		}
	}

	var output strings.Builder

	err = tmpl.Execute(&output, templateData)
	if err != nil {
		return "", fmt.Errorf("Error executing template: %v", err)
	}

	return output.String(), nil

}
