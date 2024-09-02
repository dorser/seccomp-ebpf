package syscalls

//This package is inspired by https://github.com/falcosecurity/syscalls-bumper/blob/main/main.go#L146
import (
	"bufio"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type syscallEventChecker struct {
	events []string
}

type SyscallMap map[string]int64

func newSyscallEventChecker() (*syscallEventChecker, error) {
	file, err := os.Open("/sys/kernel/debug/tracing/available_events")
	if err != nil {
		return nil, fmt.Errorf("Error opening file: %v\n", err)
	}
	defer file.Close()

	var lines []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("Error reading file: %v\n", err)
	}

	return &syscallEventChecker{events: lines}, nil
}

func (s *syscallEventChecker) CheckSyscallEvent(syscallName string) bool {
	syscallEnter := fmt.Sprintf("syscalls:sys_enter_%s", syscallName)
	for _, event := range s.events {
		if strings.HasSuffix(event, syscallEnter) {
			return true
		}
	}

	return false
}

func filterSyscall(line string, checker *syscallEventChecker) (string, int64) {
	fields := strings.Fields(line)
	if len(fields) == 2 && checker.CheckSyscallEvent(fields[0]) {
		syscallNr, _ := strconv.ParseInt(fields[1], 10, 64)
		return fields[0], syscallNr
	}
	return "", -1
}

func downloadFile(filepath string, url string) (err error) {
	log.Debugln("Downloading from", url)
	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Writer the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func loadSyscallMap(filepath string, filter func(string, *syscallEventChecker) (string, int64)) SyscallMap {
	m := make(SyscallMap, 0)

	// Support http(s) urls
	if strings.HasPrefix(filepath, "http") {
		if err := downloadFile("/tmp/syscall.txt", filepath); err != nil {
			log.Fatal(err)
		}
		filepath = "/tmp/syscall.txt"
	}

	f, err := os.Open(filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	checker, err := newSyscallEventChecker()
	if err != nil {
		log.Fatal(err)
	}
	for scanner.Scan() {
		line := scanner.Text()
		syscallName, syscallNR := filter(line, checker)
		if syscallName != "" {
			m[strings.TrimPrefix(syscallName, "__NR_")] = syscallNR
		}
	}

	if err = scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return m
}

func LoadSystemMap(arch string) SyscallMap {
	return loadSyscallMap("https://raw.githubusercontent.com/hrw/syscalls-table/master/data/tables/syscalls-"+arch, filterSyscall)
}
