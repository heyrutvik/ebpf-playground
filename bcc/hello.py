#!/usr/bin/python
from bcc import BPF

program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello World!");
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
print(f"syscall: {syscall}")
b.attach_kprobe(event=syscall, fn_name="hello")

b.trace_print(fmt="pid {1}, msg = {5}")
