package seccomp

import (
	"encoding/json"
	"os"
)

type SeccompProfile struct {
	DefaultAction string    `json:"defaultAction"`
	Syscalls      []Syscall `json:"syscalls"`
}

type Syscall struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
	Args   []Arg    `json:"args,omitempty"`
}

type Arg struct {
	Index    int    `json:"index"`
	Value    int    `json:"value"`
	ValueTwo int    `json:"valueTwo"`
	Op       string `json:"op"`
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

	return &profile, nil
}
