#ifdef CORE
  #include "vmlinux.h"
#else
  #include <linux/bpf.h>
  #include <linux/types.h>
  #include <linux/in.h>
  #include <linux/in6.h>
#endif

#include "bpf/bpf_endian.h"
#include "bpf/bpf_tracing.h"
#include "defines.h"
#include "events.h"
#include "maps.h"
#include "parse_h2_frame.h"

typedef struct func_args
{
  char * buf;
  uint64_t ptr;
  uint32_t len;
}func_args_t;

#define PRISM_LEN 24
#define READ      0
#define WRITE     1

/* h2_grpc_pid_filter is a map of pids that the probe is supposed to trace */ 
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u8));
  __uint(max_entries, MAX_PID_TRACED);
} openssl_pid_filter SEC(".maps");

/* openssl_connections stores the connections that are to be traced. i.e. if it is a
h2 connection*/ 
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(__u8));
  __uint(max_entries, MAX_H2_CONN_TRACED);
} openssl_connections SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(func_args_t));
  __uint(max_entries, 16);
} h2_read_args_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(func_args_t));
  __uint(max_entries, 16);
} h2_write_args_heap SEC(".maps");

static __always_inline uint32_t get_curr_pid() {
  uint32_t ppid = (bpf_get_current_pid_tgid() >> 32);
  uint8_t* trace_pid = bpf_map_lookup_elem(&openssl_pid_filter, &ppid);
  if (unlikely(trace_pid == NULL)) {
    return 0;
  }
  return ppid;
}

static __always_inline ec_ebpf_events_t * get_event(uint32_t pid){
  const int kZero = 0;
  ec_ebpf_events_t * event = bpf_map_lookup_elem(&h2_event_heap, &kZero);
  if (unlikely(event == NULL)){
    return event;
  }
  event->mdata.event_category = EC_CAT_HTTP2;
  event->mdata.pid = pid;
  event->mdata.timestamp = bpf_ktime_get_ns();
  return event;
}

static __inline uint8_t check_prism (const char * buf, uint32_t len) {
  if (len < 10) {
    return 0;
  }
  if ((buf[0] == 0x50 ) && (buf[1] == 0x52 ) &&(buf[2] == 0x49 ) &&(buf[3] == 0x20 ) &&(buf[4] == 0x2a ) &&(buf[5] == 0x20 ) &&(buf[6] == 0x48 ) &&(buf[7] == 0x54 ) &&(buf[8] == 0x54 ) &&(buf[9] == 0x50 ) &&(buf[10] == 0x2f) /*&&(buf[11] == 0x32 ) &&(buf[12] == 0x2e ) 
  &&(buf[13] == 0x30 ) &&(buf[14] == 0x0d ) &&(buf[15] == 0x0a ) &&(buf[16] == 0x0d ) &&(buf[17] == 0x0a ) &&(buf[18] == 0x53 ) &&(buf[19] == 0x4d ) &&(buf[20] == 0x0d ) &&(buf[21] == 0x0a ) &&(buf[22] == 0x0d ) && (buf[23] == 0x0a)*/) {
    return 1;
  }
  return 0;
}

static __always_inline uint32_t process_data(void * ctx, uint32_t pid, uint8_t rw, uint64_t ssl_ptr,
                                             char * buf, uint32_t data_len ) {
  uint8_t* trace_conn = bpf_map_lookup_elem(&openssl_connections, &ssl_ptr);
  uint8_t trace;
  if (trace_conn == NULL) {
    trace = check_prism(buf, data_len);
    bpf_map_update_elem(&openssl_connections, &ssl_ptr, &trace, BPF_EXIST);
  } else {
    trace = *trace_conn;
  }
   
  if (trace == 0){
      return 0;
  }

  ec_ebpf_events_t * event = get_event(pid);
  if (unlikely(event == NULL)){
    return -1;
  }
  event->mdata.connection_id = ssl_ptr;
  event->mdata.sent_recv = rw;
  uint32_t curr_loc = 0;
  for (int i = 0; i < 5; i ++){
    
    if (curr_loc >= data_len && curr_loc + FRAME_HEADER_SIZE >= data_len){
      //There isn't data enough for another frame
      //TODO Take care of the case where the first byte of buf is not start of frame
      break;
    }

    int size = parse_h2_frame(ctx, &buf[curr_loc], data_len - curr_loc, event, rw);
    if (size < 0){
      return 0;
    }

    curr_loc = curr_loc + size;
  }
  return 0;
}

// Function signature being probed:
// int SSL_write(SSL *ssl, const void *buf, int num);
int probe_entry_SSL_write(struct pt_regs* ctx) {
  uint32_t pid = get_curr_pid();
  if (pid == 0){
    return 0;
  }

  uint64_t ssl_ptr = (uint64_t) PT_REGS_PARM1(ctx);

  uint8_t* trace_conn = bpf_map_lookup_elem(&openssl_connections, &ssl_ptr);
  if (trace_conn != NULL && trace_conn == 0) {
    return 0;
  }

  func_args_t* args = bpf_map_lookup_elem(&h2_write_args_heap, &pid);
  if (unlikely(args == NULL)) {
    return 0;
  }

  args->ptr = ssl_ptr;
  args->buf = (char*)PT_REGS_PARM2(ctx);
  args->len = (uint32_t)PT_REGS_PARM3(ctx);

  return 0;
}

int probe_ret_SSL_write(struct pt_regs* ctx) {
  uint32_t pid = get_curr_pid();
  if (pid == 0){
    return 0;
  }

  func_args_t* args = bpf_map_lookup_elem(&h2_write_args_heap, &pid);
  if (args != NULL) {
    uint8_t* trace_conn = bpf_map_lookup_elem(&openssl_connections, &args->ptr);
    if (trace_conn != NULL && trace_conn == 0) {
      return 0;
    }
    
    if (args->buf != NULL) {
      process_data(ctx, pid, WRITE, args->ptr, args->buf, args->len);
    }
  } 
  return 0;
}

// Function signature being probed:
// int SSL_read(SSL *s, void *buf, int num)
int probe_entry_SSL_read(struct pt_regs* ctx) {
  uint32_t pid = get_curr_pid();
  if (pid == 0){
    return 0;
  }

  uint64_t ssl_ptr = (uint64_t) PT_REGS_PARM1(ctx);

  uint8_t* trace_conn = bpf_map_lookup_elem(&openssl_connections, &ssl_ptr);
  if (trace_conn != NULL && trace_conn == 0) {
    return 0;
  }

  func_args_t* args = bpf_map_lookup_elem(&h2_read_args_heap, &pid);
  if (unlikely(args == NULL)) {
    return 0;
  }

  args->ptr = (uint64_t) PT_REGS_PARM1(ctx);
  args->buf = (char*)PT_REGS_PARM2(ctx);
  args->len = (uint32_t)PT_REGS_PARM3(ctx);

  return 0;
}

int probe_ret_SSL_read(struct pt_regs* ctx) {
  uint32_t pid = get_curr_pid();
  if (pid == 0){
    return 0;
  }

  func_args_t* args = bpf_map_lookup_elem(&h2_write_args_heap, &pid);
  if (args != NULL) {
    uint8_t* trace_conn = bpf_map_lookup_elem(&openssl_connections, &args->ptr);
    if (trace_conn != NULL && trace_conn == 0) {
      return 0;
    }

    if (args->buf != NULL) {
      process_data(ctx, pid, READ, args->ptr, args->buf, args->len);
    }
  } 
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
