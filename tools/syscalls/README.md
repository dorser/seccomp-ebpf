# Syscalls
This program checks available syscalls in the current system and generates a .go file with a function that returns whether a syscall exists by its name.

Please note this is a naive approach to get the available syscalls for the current system it runs on and doesn't account for different versions/configurations/architectures of the kernel.

**usage:**
```
sudo -E $(which go) run tools/syscalls/syscalls.go -output <output> 
```
