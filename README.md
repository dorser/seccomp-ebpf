# seccomp-ebpf
## Overview
seccomp-ebpf is an experimental tool designed to convert seccomp profiles (in JSON format) into gadgets (eBPF programs). This project was developed as a practical experiment for the session ["Reinventing seccomp for Fun and Profiles"](https://colocatedeventsna2024.sched.com/event/1izqj/reinventing-seccomp-for-fun-and-profiles-ben-hirschberg-armo-dor-serero-microsoft) at Cilium + eBPF Day NA 2024, exploring the feasibility of using eBPF as a potential replacement for seccomp in managing syscall filtering.

The aim is to bridge the concepts of security and observability by leveraging eBPF’s dynamic capabilities. However, this tool is not intended for production use and should be seen as a proof of concept and a topic for further discussion and exploration.

## Disclaimer
**Experimental Status**: This project is an experimental venture and not intended for use in production environments.
**Compatibility**: The tool was developed and tested on Ubuntu 22.04 with kernel version 6.8 and x86_64 architecture. Other environments have not been tested and may not be supported.
**Limitations**: The current version does not support syscalls that do not have a tracepoint defined, so certain filters may not be created. Only syscalls with downstream LSM hooks can be blocked.

## Background
Seccomp has been a robust method for syscall filtering, but it comes with limitations in flexibility and observability. This project seeks to explore whether eBPF, known for its programmability and dynamic nature, can provide an effective alternative while maintaining security and enhancing observability.

## How To
### Prerequistes
Install Inspektor Gadget's CLI for Linux:
https://github.com/inspektor-gadget/inspektor-gadget?tab=readme-ov-file#linux

### Build
```
make build
```

### Generate seccomp profile gadget
```
Usage:
  seccomp-ebpf generate [flags]

Flags:
  -h, --help             help for generate
  -n, --name string      The name of the generated profile gadget
  -o, --output string    Path to the output directory to save the generated gadget code (default "gadget/")
  -p, --profile string   Path to the seccomp profile (required)
```

### Loading the profile
```
# go to the generated gadget directory
make build
make run
```

## Contributions
This is an experimental project with a focus on community learning and discussion. Contributions are welcome to extend its capabilities or refine its current functionality. However, please be aware that this project is in its early stages and subject to change.

## Acknowledgements
Thank you to the Cilium + eBPF Day NA 2024 attendees and community for inspiring this exploration and supporting the ongoing dialogue around modern security practices.