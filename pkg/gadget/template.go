package gadget

const gadgetTemplate = `
// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 CHANGEME-Authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct event {
  gadget_timestamp timestamp;
  gadget_mntns_id mntns_id;
  __u32 pid;
  __u8 comm[TASK_COMM_LEN];
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER({{.Name}}_tracer, events, event);

{{range .Syscalls}}
SEC("tracepoint/syscalls/sys_enter_{{.}}")
int tracepoint__sys_enter_{{.}}(struct trace_event_raw_sys_enter *ctx) {
  struct event *event;
  __u64 pid_tgid = bpf_get_current_pid_tgid();

  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return 0;

  /* event data */
  event->timestamp = bpf_ktime_get_boot_ns();
  event->mntns_id = gadget_get_mntns_id();
  event->pid = pid_tgid >> 32;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  /* emit event */
  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  return 0;
}
{{end}}

char LICENSE[] SEC("license") = "GPL";		
`
