import subprocess
import re
import os
import datetime
from typing import List, Dict, Set

def get_syscalls() -> List[str]:
    # This command lists all syscalls
    result: subprocess.CompletedProcess = subprocess.run(["ausyscall", "--dump"], capture_output=True, text=True)
    syscalls: List[str] = re.findall(r'(\w+)\s+\d+', result.stdout)
    return syscalls

def run_trace_cmd(syscall: str) -> None:
    # Run trace-cmd for the given syscall
    cmd: str = f"trace-cmd record -p function_graph -g '*{syscall}*' -F true"
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def parse_trace_output() -> str:
    # Parse the trace.dat file
    result: subprocess.CompletedProcess = subprocess.run(["trace-cmd", "report"], capture_output=True, text=True)
    return result.stdout

def check_for_lsm_hooks(output: str) -> List[str]:
    # Look for LSM-related function calls
    lsm_patterns: List[str] = [
        r'security_\w+',
        r'selinux_\w+',
        r'apparmor_\w+',
        r'tomoyo_\w+',
        r'smack_\w+'
    ]
    
    hooks_found: Set[str] = set()
    for line in output.split('\n'):
        for pattern in lsm_patterns:
            match = re.search(pattern, line)
            if match:
                hooks_found.add(match.group())
    
    return list(hooks_found)

def write_results_to_file(results: Dict[str, List[str]], filename: str) -> None:
    with open(filename, 'w') as f:
        f.write("Summary of LSM hooks found:\n\n")
        for syscall, hooks in results.items():
            if hooks:
                f.write(f"{syscall}: {', '.join(hooks)}\n")
            else:
                f.write(f"{syscall}: No LSM hooks found\n")

def main() -> None:
    syscalls: List[str] = get_syscalls()
    results: Dict[str, List[str]] = {}

    for syscall in syscalls:
        print(f"Analyzing syscall: {syscall}")
        run_trace_cmd(syscall)
        output: str = parse_trace_output()
        hooks: List[str] = check_for_lsm_hooks(output)
        results[syscall] = hooks

    # Generate a unique filename with timestamp
    timestamp: str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename: str = f"lsm_hooks_summary_{timestamp}.txt"

    # Write results to file
    write_results_to_file(results, filename)

    # Print results to console
    print(f"\nSummary of LSM hooks found (also written to {filename}):")
    for syscall, hooks in results.items():
        if hooks:
            print(f"{syscall}: {', '.join(hooks)}")
        else:
            print(f"{syscall}: No LSM hooks found")

    # Clean up trace.dat file
    os.remove("trace.dat")

if __name__ == "__main__":
    main()