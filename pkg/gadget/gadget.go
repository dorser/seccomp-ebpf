package gadget

import (
	_ "embed"
	"fmt"
	"github.com/dorser/seccomp-ebpf/pkg/seccomp"
	"github.com/dorser/seccomp-ebpf/pkg/syscalls"
	"strings"
	"text/template"
)

type templateArgs struct {
	Args   seccomp.Arg
	Action string
}

type templateSyscall struct {
	Name   string
	Nr     int64
	Args   []templateArgs
	Action string
}

type TemplateData struct {
	Name     string
	Syscalls map[string]templateSyscall
}

//go:embed gadget.tmpl
var gadgetTemplate string

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func GenerateGadgetCode(gadgetName string, profile *seccomp.SeccompProfile) (string, error) {

	tmpl, err := template.New("gadgetTemplate").Parse(gadgetTemplate)
	if err != nil {
		return "", fmt.Errorf("Error parsing template: %v", err)
	}

	syscallsMap := syscalls.LoadSystemMap("x86_64")

	templateData := TemplateData{Name: gadgetName, Syscalls: make(map[string]templateSyscall)}
	for _, syscall := range profile.Syscalls {
		for _, name := range syscall.Names {
			if (len(syscall.Includes.Arches) == 0 || contains(syscall.Includes.Arches, "amd64")) && len(syscall.Includes.Caps) == 0 && len(syscall.Excludes.Caps) == 0 {
				templateDataEntry := templateSyscall{
					Name: name,
					Nr:   syscallsMap[name],
				}

				if len(syscall.Args) > 0 {
					// Preserve args if syscall already exists
					templateDataEntry.Args = append(templateDataEntry.Args, templateData.Syscalls[name].Args...)

					for _, arg := range syscall.Args {
						templateDataEntry.Args = append(templateDataEntry.Args, templateArgs{Args: arg, Action: syscall.Action})

					}
					templateDataEntry.Action = profile.DefaultAction
				} else {
					templateDataEntry.Action = syscall.Action
				}
				templateData.Syscalls[name] = templateDataEntry
				delete(syscallsMap, name)
			}
		}
	}

	for name, nr := range syscallsMap {
		fmt.Println(name)
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
