// Copyright 2026 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package events

import (
	"bytes"
	"encoding/binary"
	"testing"

	"huatuo-bamai/internal/utils/bytesutil"
)

// TestNetRcvPerfEventParse decodes a perf sample laid out exactly like struct
// perf_event_t in bpf/net_rx_latency.c and checks that every field lands where
// the kernel wrote it. It fails if the Go mirror drifts from the C layout, e.g.
// the missing alignment hole that shifted net_cookie by 4 bytes.
func TestNetRcvPerfEventParse(t *testing.T) {
	const (
		wantComm                 = "nginx-worker"
		wantLatency       uint64 = 12_345_678
		wantTgidPid       uint64 = uint64(4321)<<32 | 8765
		wantPktLen        uint64 = 1500
		wantTCPSport      uint16 = 0x1f90
		wantTCPDport      uint16 = 0xd431
		wantTCPSaddr      uint32 = 0x0a00_0001
		wantTCPDaddr      uint32 = 0x0a00_0002
		wantTCPSeq        uint32 = 0x1234_5678
		wantTCPAckSeq     uint32 = 0x8765_4321
		wantTCPState      uint8  = 1
		wantLatStage      uint8  = 2
		wantNetdevName           = "eth0"
		wantNetnsInode    uint32 = 0xf000_0000
		wantNetnsCookie   uint64 = 0x0123_4567_89ab_cdef
		perfEventTotalLen        = 96
	)

	buf := make([]byte, perfEventTotalLen)

	native := binary.NativeEndian
	copy(buf[0:], wantComm)                     // comm[16]
	native.PutUint64(buf[16:], wantLatency)     // latency
	native.PutUint64(buf[24:], wantTgidPid)     // tgid_pid
	native.PutUint64(buf[32:], wantPktLen)      // pkt_len
	native.PutUint16(buf[40:], wantTCPSport)    // tcp_sport
	native.PutUint16(buf[42:], wantTCPDport)    // tcp_dport
	native.PutUint32(buf[44:], wantTCPSaddr)    // tcp_saddr
	native.PutUint32(buf[48:], wantTCPDaddr)    // tcp_daddr
	native.PutUint32(buf[52:], wantTCPSeq)      // tcp_seq
	native.PutUint32(buf[56:], wantTCPAckSeq)   // tcp_ack_seq
	buf[60] = wantTCPState                      // tcp_state
	buf[61] = wantLatStage                      // lat_stage
	copy(buf[64:], wantNetdevName)              // netdev_name[16]
	native.PutUint32(buf[80:], wantNetnsInode)  // netns_inum
	native.PutUint64(buf[88:], wantNetnsCookie) // net_cookie
	// buf[62:64] and buf[84:88] are C padding, left zero.

	var pd netRcvPerfEvent
	if err := binary.Read(bytes.NewReader(buf), binary.NativeEndian, &pd); err != nil {
		t.Fatalf("binary.Read: %v", err)
	}

	if pd.NetNamespaceInode != wantNetnsInode {
		t.Errorf("NetNamespaceInode = %#x, want %#x", pd.NetNamespaceInode, wantNetnsInode)
	}
	if pd.NetNamespaceCookie != wantNetnsCookie {
		t.Errorf("NetNamespaceCookie = %#x, want %#x", pd.NetNamespaceCookie, wantNetnsCookie)
	}
	if got := bytesutil.ToStr(pd.Comm[:]); got != wantComm {
		t.Errorf("Comm = %q, want %q", got, wantComm)
	}
	if got := bytesutil.ToStr(pd.NetdevName[:]); got != wantNetdevName {
		t.Errorf("NetdevName = %q, want %q", got, wantNetdevName)
	}
	if pd.Latency != wantLatency || pd.TgidPid != wantTgidPid || pd.PktLen != wantPktLen {
		t.Errorf("u64 header fields misparsed: %+v", pd)
	}
	if pd.TCPSport != wantTCPSport || pd.TCPDport != wantTCPDport ||
		pd.TCPSaddr != wantTCPSaddr || pd.TCPDaddr != wantTCPDaddr ||
		pd.TCPSeq != wantTCPSeq || pd.TCPAckSeq != wantTCPAckSeq {
		t.Errorf("tcp fields misparsed: %+v", pd)
	}
	if pd.TCPState != wantTCPState || pd.LatStage != wantLatStage {
		t.Errorf("TCPState/LatStage misparsed: %+v", pd)
	}
}
