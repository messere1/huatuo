// Copyright 2026 The HuaTuo Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package events

import (
	"encoding/binary"
	"os"
	"testing"

	"huatuo-bamai/internal/bpf"
	"huatuo-bamai/internal/pod"
)

// TestOOMPerfEventDataSize pins the Go-side event layout to struct oom_info
// in bpf/oom.c (2x16 comm + 2x4 pid + 4x8 u64). A mismatch means fields
// added on one side were not mirrored on the other and would be silently
// dropped or misparsed by binary.Read.
func TestOOMPerfEventDataSize(t *testing.T) {
	const oomInfoSize = 2*bpf.TaskCommLen + 2*4 + 4*8
	if got := binary.Size(perfEventData{}); got != oomInfoSize {
		t.Fatalf("perfEventData size = %d, want %d (struct oom_info in bpf/oom.c)", got, oomInfoSize)
	}
}

func TestBuildTracingDataCgroupMemory(t *testing.T) {
	var triggerComm, victimComm [bpf.TaskCommLen]byte
	copy(triggerComm[:], "stress")
	copy(victimComm[:], "java")

	data := perfEventData{
		TriggerComm:   triggerComm,
		VictimComm:    victimComm,
		TriggerPid:    101,
		VictimPid:     202,
		MemLimitPages: 262144,
		MemUsagePages: 262000,
	}

	got := buildTracingData(data, map[string]*pod.Container{}, nil)

	if got.Trigger.Pid != 101 || got.Trigger.Comm != "stress" {
		t.Errorf("trigger = {pid: %d, comm: %q}, want {pid: 101, comm: \"stress\"}", got.Trigger.Pid, got.Trigger.Comm)
	}
	if got.Victim.Pid != 202 || got.Victim.Comm != "java" {
		t.Errorf("victim = {pid: %d, comm: %q}, want {pid: 202, comm: \"java\"}", got.Victim.Pid, got.Victim.Comm)
	}

	pageSize := uint64(os.Getpagesize())
	if want := data.MemLimitPages * pageSize; got.CgroupMemoryLimit != want {
		t.Errorf("CgroupMemoryLimit = %d, want %d", got.CgroupMemoryLimit, want)
	}
	if want := data.MemUsagePages * pageSize; got.CgroupMemoryUsage != want {
		t.Errorf("CgroupMemoryUsage = %d, want %d", got.CgroupMemoryUsage, want)
	}
}
