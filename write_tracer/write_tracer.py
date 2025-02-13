#!/usr/bin/env python3
from bcc import BPF
import ctypes as ct
import os

# Define size_t for the event structure
class WriteEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("timestamp", ct.c_uint64),
        ("comm", ct.c_char * 16),      # TASK_COMM_LEN is usually 16
        ("fname", ct.c_char * 255),     # NAME_MAX is usually 255
        ("count", ct.c_uint64)          # size_t as uint64
    ]

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/stat.h>

// Define the data structure to store write information
struct write_event_t {
    u32 pid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
    u64 count;
};

BPF_PERF_OUTPUT(write_events);
BPF_ARRAY(write_count, u64, 1);

// Store our own PID to filter it out
BPF_HASH(my_pid, u32, u32);

int trace_write_entry(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count)
{
    int zero = 0;
    u64 *counter = write_count.lookup(&zero);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
    
    // Get current PID
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Check if this is our own PID
    if (my_pid.lookup(&pid))
        return 0;

    // Filter out stdin/stdout/stderr by checking if the file has an inode number <= 2
    unsigned long inode_nr;
    bpf_probe_read_kernel(&inode_nr, sizeof(inode_nr), &file->f_inode->i_ino);
    if (inode_nr <= 2)
        return 0;

    unsigned short mode;
    bpf_probe_read_kernel(&mode, sizeof(mode), &file->f_inode->i_mode);
    if ((mode & S_IFMT) != S_IFREG)  // S_IFMT = 0170000, S_IFREG = 0100000
        return 0;

    struct write_event_t event = {};

    // Get process information
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Get file name
    struct dentry *dentry = file->f_path.dentry;
    bpf_probe_read_kernel(&event.fname, sizeof(event.fname), dentry->d_name.name);

    // Store write size
    event.count = count;

    // Submit event
    write_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_text)

# Attach kprobe to write syscall
b.attach_kprobe(event="vfs_write", fn_name="trace_write_entry")

# Process events
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(WriteEvent)).contents
    print(f"PID: {event.pid:<6} COMM: {event.comm.decode('utf-8', 'replace'):<16} "
          f"File: {event.fname.decode('utf-8', 'replace'):<20} Size: {str(event.count) + "b":<16} "
          f"Time: {event.timestamp}")

def print_count():
    counts = b["write_count"]
    print(f"\nTotal vfs_write calls: {counts[0].value}")

# Store our PID in the BPF hash
pid = os.getpid()
pid_key = ct.c_uint32(pid)
pid_value = ct.c_uint32(1)
b["my_pid"][pid_key] = pid_value

# Loop with callback to print_event
b["write_events"].open_perf_buffer(print_event)
print("Tracing write operations... Ctrl+C to end")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print_count()
    print("\nTracing completed.")
