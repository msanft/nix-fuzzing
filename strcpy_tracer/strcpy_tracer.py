#!/usr/bin/env python3

from bcc import BPF
import time
from datetime import datetime
import os

current_file_dir = os.path.dirname(os.path.abspath(__file__))
with open(f"{current_file_dir}/../share/strcpy_tracer.bpf.c", "r") as f:
    bpf_text = f.read()

b = BPF(text=bpf_text)

b.attach_uretprobe(name="/nix/store/81mi7m3k3wsiz9rrrg636sx21psj20hc-glibc-2.40-66/lib/libc.so.6", sym="strcpy", fn_name="trace_strcpy_return")

def print_stack(stack_id, pid):
    if stack_id < 0:
        print("  [Failed to get stack trace]")
        return

    stack = b.get_table("stack_traces").walk(stack_id)
    for addr in stack:
        # Get symbol name if available, using the PID from the event
        sym_name = b.sym(addr, pid, show_module=True, show_offset=True)
        print(f"  {sym_name}")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"\n{datetime.now()}: PID {event.pid} ({event.comm.decode('utf-8', 'replace')}) called strcpy")
    print("Call stack:")
    print_stack(event.stack_id, event.pid)  # Changed from user_stack_id to stack_id

b["events"].open_perf_buffer(print_event)
print("Tracing strcpy calls... Press Ctrl+C to exit")
print("Output includes user-space call stacks with symbols when available")

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
