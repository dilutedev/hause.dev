package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const clockTicksPerSecond = 100

var errProcessGone = errors.New("That process has already exited.")

type protectedProcessError struct {
	reason string
}

func (err protectedProcessError) Error() string {
	return "This process is protected. " + err.reason
}

var protectedCommandNames = map[string]string{
	"sshd":               "Stopping the SSH server would lock you out of the terminal.",
	"tailscaled":         "Stopping Tailscale would cut off SSH access.",
	"caddy":              "Stopping Caddy would take this panel and hause.dev offline.",
	"dockerd":            "Stopping the Docker engine would stop every container.",
	"containerd":         "Docker depends on this container runtime.",
	"dbus-daemon":        "systemd depends on this message bus.",
	"dbus-broker":        "systemd depends on this message bus.",
	"dbus-broker-launch": "systemd depends on this message bus.",
	"hause-admin":        "It runs this panel.",
}

type Process struct {
	PID         int     `json:"pid"`
	ParentPID   int     `json:"ppid"`
	Name        string  `json:"name"`
	Command     string  `json:"command"`
	User        string  `json:"user"`
	State       string  `json:"state"`
	CPUPercent  float64 `json:"cpu"`
	MemoryBytes uint64  `json:"memory"`
	Threads     int     `json:"threads"`
	StartedAt   int64   `json:"startedAt"`
	StartTicks  uint64  `json:"startTicks"`
	Protected   string  `json:"protected,omitempty"`
	Executable  string  `json:"executable,omitempty"`
	Ports       []int   `json:"ports,omitempty"`
	commandName string
	userID      uint32
	cpuTicks    uint64
}

type SystemSummary struct {
	Hostname      string     `json:"hostname"`
	CPUPercent    float64    `json:"cpu"`
	Cores         int        `json:"cores"`
	MemoryTotal   uint64     `json:"memoryTotal"`
	MemoryUsed    uint64     `json:"memoryUsed"`
	SwapTotal     uint64     `json:"swapTotal"`
	SwapUsed      uint64     `json:"swapUsed"`
	DiskTotal     uint64     `json:"diskTotal"`
	DiskUsed      uint64     `json:"diskUsed"`
	DiskAvailable uint64     `json:"diskAvailable"`
	Load          [3]float64 `json:"load"`
	UptimeSeconds int64      `json:"uptime"`
	SampledAt     int64      `json:"sampledAt"`
}

type Snapshot struct {
	System    SystemSummary `json:"system"`
	Processes []Process     `json:"processes"`
}

type processKey struct {
	pid        int
	startTicks uint64
}

type ProcessMonitor struct {
	ownPID   int
	bootTime time.Time
	pageSize uint64

	mutex  sync.RWMutex
	latest Snapshot

	userNames          map[uint32]string
	previousCPUTicks   map[processKey]uint64
	previousSampleAt   time.Time
	previousTotalTicks uint64
	previousIdleTicks  uint64
}

func newProcessMonitor() (*ProcessMonitor, error) {
	statContents, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil, err
	}
	var bootSeconds int64
	for _, line := range strings.Split(string(statContents), "\n") {
		if value, found := strings.CutPrefix(line, "btime "); found {
			bootSeconds, err = strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil {
				return nil, err
			}
		}
	}
	if bootSeconds == 0 {
		return nil, errors.New("boot time missing from /proc/stat")
	}
	return &ProcessMonitor{
		ownPID:           os.Getpid(),
		bootTime:         time.Unix(bootSeconds, 0),
		pageSize:         uint64(os.Getpagesize()),
		userNames:        map[uint32]string{},
		previousCPUTicks: map[processKey]uint64{},
	}, nil
}

func (monitor *ProcessMonitor) run(interval time.Duration) {
	monitor.sample()
	ticker := time.NewTicker(interval)
	for range ticker.C {
		monitor.sample()
	}
}

func (monitor *ProcessMonitor) snapshot() Snapshot {
	monitor.mutex.RLock()
	defer monitor.mutex.RUnlock()
	return monitor.latest
}

func (monitor *ProcessMonitor) sample() {
	now := time.Now()
	elapsedSeconds := now.Sub(monitor.previousSampleAt).Seconds()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	currentCPUTicks := make(map[processKey]uint64, len(entries))
	portsByPID := monitor.listeningPorts()
	processes := make([]Process, 0, len(entries))
	for _, entry := range entries {
		processID, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		process, err := monitor.readProcess(processID)
		if err != nil {
			continue
		}
		process.Ports = portsByPID[processID]
		key := processKey{pid: process.PID, startTicks: process.StartTicks}
		currentCPUTicks[key] = process.cpuTicks
		if previousTicks, seen := monitor.previousCPUTicks[key]; seen && elapsedSeconds > 0 && process.cpuTicks >= previousTicks {
			process.CPUPercent = roundToTenth(float64(process.cpuTicks-previousTicks) / clockTicksPerSecond / elapsedSeconds * 100)
		}
		process.User = monitor.userName(process.userID)
		processes = append(processes, process)
	}
	system := monitor.readSystemSummary(now)
	monitor.previousCPUTicks = currentCPUTicks
	monitor.previousSampleAt = now

	monitor.mutex.Lock()
	monitor.latest = Snapshot{System: system, Processes: processes}
	monitor.mutex.Unlock()
}

func (monitor *ProcessMonitor) readProcess(processID int) (Process, error) {
	procDirectory := fmt.Sprintf("/proc/%d", processID)
	statContents, err := os.ReadFile(procDirectory + "/stat")
	if err != nil {
		return Process{}, err
	}
	statText := string(statContents)
	nameStart := strings.IndexByte(statText, '(')
	nameEnd := strings.LastIndexByte(statText, ')')
	if nameStart < 0 || nameEnd < nameStart {
		return Process{}, errors.New("malformed stat")
	}
	commandName := statText[nameStart+1 : nameEnd]
	fields := strings.Fields(statText[nameEnd+1:])
	if len(fields) < 22 {
		return Process{}, errors.New("malformed stat")
	}
	parentPID, _ := strconv.Atoi(fields[1])
	userTicks, _ := strconv.ParseUint(fields[11], 10, 64)
	systemTicks, _ := strconv.ParseUint(fields[12], 10, 64)
	threads, _ := strconv.Atoi(fields[17])
	startTicks, _ := strconv.ParseUint(fields[19], 10, 64)
	residentPages, _ := strconv.ParseUint(fields[21], 10, 64)

	info, err := os.Stat(procDirectory)
	if err != nil {
		return Process{}, err
	}
	var userID uint32
	if status, ok := info.Sys().(*syscall.Stat_t); ok {
		userID = status.Uid
	}

	commandLine, _ := os.ReadFile(procDirectory + "/cmdline")
	arguments := strings.Split(strings.TrimRight(string(commandLine), "\x00"), "\x00")
	command := strings.TrimSpace(strings.Join(arguments, " "))
	displayName := commandName
	executable, _ := os.Readlink(procDirectory + "/exe")
	if executable == "" && strings.ContainsRune(arguments[0], '/') {
		executable = arguments[0]
	}
	if command == "" {
		command = "[" + commandName + "]"
	} else if invokedAs := arguments[0]; !strings.ContainsRune(invokedAs, ' ') {
		if base := filepath.Base(invokedAs); len(base) > len(commandName) && strings.HasPrefix(base, commandName) {
			displayName = base
		}
	}
	if len(command) > 600 {
		command = strings.ToValidUTF8(command[:600], "") + "…"
	}

	process := Process{
		PID:         processID,
		ParentPID:   parentPID,
		Name:        displayName,
		Command:     command,
		Executable:  executable,
		State:       fields[0],
		MemoryBytes: residentPages * monitor.pageSize,
		Threads:     threads,
		StartTicks:  startTicks,
		StartedAt:   monitor.bootTime.Add(time.Duration(startTicks) * time.Second / clockTicksPerSecond).UnixMilli(),
		commandName: commandName,
		userID:      userID,
		cpuTicks:    userTicks + systemTicks,
	}
	process.Protected = monitor.protectionReason(process)
	return process, nil
}

var ssPidPattern = regexp.MustCompile(`pid=(\d+)`)

// listeningPorts maps process IDs to the TCP/UDP ports they listen on. It
// shells out to `sudo ss` because an unprivileged process can't read the
// sockets of other users; without the sudo rule it quietly returns nothing.
func (monitor *ProcessMonitor) listeningPorts() map[int][]int {
	output, err := exec.Command("sudo", "-n", "/usr/bin/ss", "-tulpnH").Output()
	if err != nil {
		return map[int][]int{}
	}
	return parseListeningPorts(string(output))
}

func parseListeningPorts(output string) map[int][]int {
	portsByPID := map[int][]int{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		localAddress := fields[4]
		colon := strings.LastIndexByte(localAddress, ':')
		if colon < 0 {
			continue
		}
		port, err := strconv.Atoi(localAddress[colon+1:])
		if err != nil || port <= 0 {
			continue
		}
		for _, match := range ssPidPattern.FindAllStringSubmatch(line, -1) {
			processID, err := strconv.Atoi(match[1])
			if err != nil {
				continue
			}
			if slices.Contains(portsByPID[processID], port) {
				continue
			}
			portsByPID[processID] = append(portsByPID[processID], port)
		}
	}
	for processID := range portsByPID {
		slices.Sort(portsByPID[processID])
	}
	return portsByPID
}

func (monitor *ProcessMonitor) protectionReason(process Process) string {

	switch {
	case process.PID == 1:
		return "Stopping init would bring the whole server down."
	case process.PID == monitor.ownPID:
		return "It runs this panel."
	case process.PID == 2 || process.ParentPID == 2:
		return "It's a kernel thread."
	case strings.HasPrefix(process.commandName, "systemd"):
		return "It's a core systemd service."
	}
	return protectedCommandNames[process.commandName]
}

func (monitor *ProcessMonitor) userName(userID uint32) string {
	if name, ok := monitor.userNames[userID]; ok {
		return name
	}
	name := strconv.FormatUint(uint64(userID), 10)
	if account, err := user.LookupId(name); err == nil {
		name = account.Username
	}
	monitor.userNames[userID] = name
	return name
}

func (monitor *ProcessMonitor) readSystemSummary(now time.Time) SystemSummary {
	summary := SystemSummary{Cores: runtime.NumCPU(), SampledAt: now.UnixMilli()}
	summary.Hostname, _ = os.Hostname()

	if statContents, err := os.ReadFile("/proc/stat"); err == nil {
		firstLine, _, _ := strings.Cut(string(statContents), "\n")
		fields := strings.Fields(firstLine)
		if len(fields) >= 9 {
			var totalTicks uint64
			values := make([]uint64, 8)
			for index := range values {
				values[index], _ = strconv.ParseUint(fields[index+1], 10, 64)
				totalTicks += values[index]
			}
			idleTicks := values[3] + values[4]
			if totalTicks > monitor.previousTotalTicks && monitor.previousTotalTicks > 0 {
				busy := 1 - float64(idleTicks-monitor.previousIdleTicks)/float64(totalTicks-monitor.previousTotalTicks)
				summary.CPUPercent = roundToTenth(math.Max(0, busy) * 100)
			}
			monitor.previousTotalTicks = totalTicks
			monitor.previousIdleTicks = idleTicks
		}
	}

	if memoryContents, err := os.ReadFile("/proc/meminfo"); err == nil {
		var availableKilobytes, swapFreeKilobytes uint64
		for _, line := range strings.Split(string(memoryContents), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			value, _ := strconv.ParseUint(fields[1], 10, 64)
			switch fields[0] {
			case "MemTotal:":
				summary.MemoryTotal = value * 1024
			case "MemAvailable:":
				availableKilobytes = value
			case "SwapTotal:":
				summary.SwapTotal = value * 1024
			case "SwapFree:":
				swapFreeKilobytes = value
			}
		}
		summary.MemoryUsed = summary.MemoryTotal - availableKilobytes*1024
		summary.SwapUsed = summary.SwapTotal - swapFreeKilobytes*1024
	}

	var filesystemStats syscall.Statfs_t
	if err := syscall.Statfs("/", &filesystemStats); err == nil {
		blockSize := uint64(filesystemStats.Bsize)
		summary.DiskTotal = filesystemStats.Blocks * blockSize
		summary.DiskUsed = (filesystemStats.Blocks - filesystemStats.Bfree) * blockSize
		summary.DiskAvailable = filesystemStats.Bavail * blockSize
	}

	if loadContents, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(loadContents))
		for index := 0; index < 3 && index < len(fields); index++ {
			summary.Load[index], _ = strconv.ParseFloat(fields[index], 64)
		}
	}

	if uptimeContents, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(uptimeContents))
		if len(fields) > 0 {
			seconds, _ := strconv.ParseFloat(fields[0], 64)
			summary.UptimeSeconds = int64(seconds)
		}
	}
	return summary
}

func (monitor *ProcessMonitor) sendSignal(processID int, startTicks uint64, signalName string) (Process, error) {
	target, err := monitor.readProcess(processID)
	if err != nil || target.StartTicks != startTicks {
		return Process{}, errProcessGone
	}
	if target.Protected != "" {
		return target, protectedProcessError{reason: target.Protected}
	}
	output, err := exec.Command("sudo", "-n", "/usr/bin/kill", "-"+signalName, strconv.Itoa(processID)).CombinedOutput()
	if err != nil {
		return target, fmt.Errorf("kill failed: %s", strings.TrimSpace(string(output)))
	}
	return target, nil
}

func roundToTenth(value float64) float64 {
	return math.Round(value*10) / 10
}
