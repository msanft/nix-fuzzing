// strcpy_trace.bpf.c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/types.h>

struct event {
    u32 pid;
    u32 uid;
    char comm[16];
    int stack_id;  // Changed to int as that's what bcc_get_stackid returns
};

BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE_BUILDID(stack_traces, 10000);  // Using the BUILDID version for better symbol resolution

int trace_strcpy_return(struct pt_regs *ctx) {
    struct event event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    event.pid = pid_tgid >> 32;
    event.uid = uid_gid >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Get stack trace
    event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}
