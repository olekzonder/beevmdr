#include "beevmdr.skel.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    return vfprintf(stderr, format, args);
  return 0;
}

static volatile sig_atomic_t stop;

#define MAX_FILE_SIZE 255
struct output{
  long ts;
  pid_t pid;
  char comm[16];
  char filename[MAX_FILE_SIZE];
};


static int handle_event(void *ctx, void *data, size_t data_sz) {
  struct output *out = (struct output *) data;
  printf("%s\n",out->filename);
  return 0;
}

static void sig_int(int signo) { stop = 1; }

int main(int argc, char **argv) {
  struct ring_buffer *rb = NULL;
  struct beevmdr_bpf *skel;
  int err;

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Open load and verify BPF application */
  skel = beevmdr_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }
  /* Attach tracepoint handler */
  err = beevmdr_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  if (signal(SIGINT, sig_int) == SIG_ERR) {
    fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
    goto cleanup;
  }

  while (!stop) {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("Error polling perf buffer: %d\n", err);
      break;
    }
  }

cleanup:
  beevmdr_bpf__destroy(skel);
  return -err;
}