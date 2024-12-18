package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/template"
)

const availableEventsPath = "/sys/kernel/debug/tracing/available_events"

// Template for the generated Go file
const templateContent = `// Code generated by generator; DO NOT EDIT. See: github.com/dorser/seccomp-ebpf/tools/tracepoints

package tracepoints

type SyscallTracepoint struct {
	Enter bool
	Exit  bool
}

func SyscallHasEnterTracepoint(syscall string) bool {
	tracepoints, exists := tracepoints[syscall]
	if exists {
		return tracepoints.Enter
	}
	return false
}

func SyscallHasExitTracepoint(syscall string) bool {
	tracepoints, exists := tracepoints[syscall]
	if exists {
		return tracepoints.Exit
	}
	return false
}

func SyscallHasTracepoint(syscall string) bool {
	_, exists := tracepoints[syscall]
	return exists
}

var tracepoints = map[string]SyscallTracepoint{
	{{- range $syscallName, $tracepoints := . }}
	"{{ $syscallName }}": {
		Enter: {{ $tracepoints.Enter }},
		Exit: {{ $tracepoints.Exit }},
	},
	{{- end }}
}
`

type SyscallTracepoint struct {
	Enter bool
	Exit  bool
}

func addSyscallTracepoints(syscalls map[string]SyscallTracepoint, syscallName string, tracepoints SyscallTracepoint) {
	if _, exists := syscalls[syscallName]; !exists {
		syscalls[syscallName] = SyscallTracepoint{}
	}

	syscalls[syscallName] = SyscallTracepoint{
		Enter: syscalls[syscallName].Enter || tracepoints.Enter,
		Exit:  syscalls[syscallName].Exit || tracepoints.Exit,
	}
}

func main() {
	// Define and parse the output file flag
	outputFile := flag.String("output", "syscall_tracepoints_generated.go", "Name of the output file")
	flag.Parse()

	// Open the available events file
	file, err := os.Open(availableEventsPath)
	if err != nil {
		fmt.Printf("Failed to open %s: %v\n", availableEventsPath, err)
		return
	}
	defer file.Close()

	// Read and parse the available events
	syscalls := make(map[string]SyscallTracepoint)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "syscalls:sys_enter_") {
			syscallName := strings.TrimPrefix(line, "syscalls:sys_enter_")
			addSyscallTracepoints(syscalls, syscallName, SyscallTracepoint{
				Enter: true,
			})
		}
		if strings.HasPrefix(line, "syscalls:sys_exit_") {
			syscallName := strings.TrimPrefix(line, "syscalls:sys_exit_")
			addSyscallTracepoints(syscalls, syscallName, SyscallTracepoint{
				Exit: true,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Failed to read %s: %v\n", availableEventsPath, err)
		return
	}

	// Prepare the template
	tmpl, err := template.New("syscallTracepoints").Parse(templateContent)
	if err != nil {
		fmt.Printf("Failed to parse template: %v\n", err)
		return
	}

	// Create the output file
	output, err := os.Create(*outputFile)
	if err != nil {
		fmt.Printf("Failed to create %s: %v\n", *outputFile, err)
		return
	}
	defer output.Close()

	// Execute the template with the syscall data
	err = tmpl.Execute(output, syscalls)
	if err != nil {
		fmt.Printf("Failed to execute template: %v\n", err)
		return
	}

	fmt.Printf("Generated file %s successfully.\n", *outputFile)
}
