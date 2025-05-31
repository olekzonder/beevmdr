#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_BUF_DIM 8192*1024
#define MAX_FILE_SIZE 255
#define MAX_PIDS 1024
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, MAX_BUF_DIM);
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_PIDS);
  __type(key, u32);
	__type(value, u8);
} filter_pids SEC(".maps");

struct output{
  long ts;
  pid_t pid;
  char comm[16];
  char filename[MAX_FILE_SIZE];
};

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  pid_t pid = pid_tgid;
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct output *out = bpf_ringbuf_reserve(&rb,sizeof(struct output),0);
  if(!out)
    return 0;
  out->ts = bpf_ktime_get_tai_ns();
  out->pid = pid_tgid;
  unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
  char *filename = (char *) ctx + fname_off;
  bpf_get_current_comm(&out->comm, sizeof(out->comm));
  bpf_probe_read(&out->filename,sizeof(out->filename),filename);
  bpf_ringbuf_submit(out,0);
  return 0;
}

SEC("raw_tracepoint/sys_enter")
int kill_proc(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t pid = pid_tgid;
    u8 *res = (u8*)bpf_map_lookup_elem(&filter_pids, &pid);
    if(res == NULL){
      return 0;
    }
    bpf_printk("SENDING SIGNAL!");
    bpf_send_signal(9); //SIGKILL
    return 0;
}

char LICENSE[] SEC("license") = "GPL";