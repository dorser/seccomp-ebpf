# Research: Mapping System Calls to Downstream LSM Functions

## Overview
This research aims to map syscalls to downstream LSM (Linux Security Module) hooks. The idea of replacing rewriting seccomp profile with eBPF requires LSM hooks to manipulate the return code of syscalls, similar to seccomp's `SECCOMP_RET_ERRNO` action. The results of this research are used to better understand what are the gaps for eBPF to as a "drop-in replacement" for seccomp.

At this point in time, this research covers only syscalls for x86-64.

## Motivation
We've heard of folks toying with the idea of using seccomp with eBPF - making it more extensible. We believe this is a novel approach and instead, eBPF is already well equipped to achieve this without having to wait for changes in the Linux kernel - eBPF style.

## Approach
We used dynamic profiling to check what downstream functions are being called by different syscalls. To do that, we used several projects to execute different syscalls and properly tracing them. The [LTP project](https://github.com/linux-test-project/ltp) implements a wide variety of tests for different syscalls, which we executed and examined using `ftrace`. To find the mapping between syscalls and their function symbols, we used the [Systrack](https://github.com/mebeim/systrack) and then parsed the output to check whether LSM functions are being called for that function.

Basically, this can be achieved by invoking the following for each syscall that has a tested implemetned in LTP:
```
sudo trace-cmd record -p function_graph -g '<FUNCTION_SYMBOL>' /ltp/testcases/kernel/syscalls/<SYSCALL>/<TEST_BINARY>
```

and then examine the output to see whether any LSM functions are being called.

## Results
### Findings 
### Limitations

## Next Steps
- Compare performance of eBPF vs seccomp
