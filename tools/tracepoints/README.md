# Tracepoints
This program checks available tracepoints in the current system and generates a .go file with a function that returns whether a tracepoint exists for a given syscall.

Please note this is a naive approach to get the available syscall tracepoints for the system it runs on and doesn't account for different versions/configurations/architectures of the kernel.

**usage:**
```
sudo -E $(which go) run tools/tracepoints/tracepoints.go -output <output> 
```
