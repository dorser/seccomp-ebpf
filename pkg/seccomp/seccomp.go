package seccomp

import (
	"encoding/json"
	"fmt"
	"os"
)

type SeccompProfile struct {
	DefaultAction string    `json:"defaultAction"`
	Syscalls      []Syscall `json:"syscalls"`
}

type Syscall struct {
	Names    []string `json:"names"`
	Action   string   `json:"action"`
	Args     []Arg    `json:"args,omitempty"`
	Includes Includes `json:"includes,omitempty"`
	Excludes Includes `json:"excludes,omitempty"`
}

type Arg struct {
	Index    int    `json:"index"`
	Value    int    `json:"value"`
	ValueTwo int    `json:"valueTwo"`
	Op       string `json:"op"`
}

type Includes struct {
	MinKernel string   `json:"minKernel"`
	Arches    []string `json:"arches"`
	Caps      []string `json:"caps"`
}

const (
	SCMP_CMP_EQ        string = "SCMP_CMP_EQ"
	SCMP_CMP_NE        string = "SCMP_CMP_NE"
	SCMP_CMP_LT        string = "SCMP_CMP_LT"
	SCMP_CMP_LE        string = "SCMP_CMP_LE"
	SCMP_CMP_GT        string = "SCMP_CMP_GT"
	SCMP_CMP_GE        string = "SCMP_CMP_GE"
	SCMP_CMP_MASKED_EQ string = "SCMP_CMP_MASKED_EQ"
)

func convertOp(op string) (string, error) {
	switch op {
	case SCMP_CMP_EQ:
		return "==", nil
	case SCMP_CMP_NE:
		return "!=", nil
	case SCMP_CMP_LT:
		return "<", nil
	case SCMP_CMP_LE:
		return "<=", nil
	case SCMP_CMP_GT:
		return ">", nil
	case SCMP_CMP_GE:
		return ">=", nil
	case SCMP_CMP_MASKED_EQ:
		return "&", nil
	default:
		return "", fmt.Errorf("unsupported seccomp operator: %s", op)
	}
}

func LoadProfile(filename string) (*SeccompProfile, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var profile SeccompProfile
	err = json.Unmarshal(data, &profile)
	if err != nil {
		return nil, err
	}

	for i := range profile.Syscalls {
		for j := range profile.Syscalls[i].Args {
			profile.Syscalls[i].Args[j].Op, err = convertOp(profile.Syscalls[i].Args[j].Op)
			if err != nil {
				return nil, err
			}
		}
	}

	return &profile, nil
}
