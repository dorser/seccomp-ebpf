#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <gadget/types.h>
#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>

#ifndef EPERM
#define EPERM 1
#endif

#ifndef SIGKILL
#define SIGKILL 9
#endif

#ifndef SIGSYS
#define SIGSYS 12
#endif

const uint SCMP_ACT_UNDEFINED = 0;
const uint SCMP_ACT_KILL = 1;
const uint SCMP_ACT_KILL_THREAD = 1;
const uint SCMP_ACT_KILL_PROCESS = 2;
const uint SCMP_ACT_TRAP = 3;
const uint SCMP_ACT_TRACE = 4;
const uint SCMP_ACT_LOG = 4;
const uint SCMP_ACT_NOTIFY = 4;
const uint SCMP_ACT_ALLOW = 5;
const uint SCMP_ACT_ERRNO = 6;

struct event {
  gadget_mntns_id mntns_id;
  gadget_syscall syscall_raw;
  uint action;
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(event_actions, events, event);

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, u64);
  __type(value, uint);
} actions SEC(".maps");

#define FOR_EACH_CAPABILITY(F)  \
	F(CAP_CHOWN)            \
	F(CAP_DAC_OVERRIDE)     \
	F(CAP_DAC_READ_SEARCH)  \
	F(CAP_FOWNER)           \
	F(CAP_FSETID)           \
	F(CAP_KILL)             \
	F(CAP_SETGID)           \
	F(CAP_SETUID)           \
	F(CAP_SETPCAP)          \
	F(CAP_LINUX_IMMUTABLE)  \
	F(CAP_NET_BIND_SERVICE) \
	F(CAP_NET_BROADCAST)    \
	F(CAP_NET_ADMIN)        \
	F(CAP_NET_RAW)          \
	F(CAP_IPC_LOCK)         \
	F(CAP_IPC_OWNER)        \
	F(CAP_SYS_MODULE)       \
	F(CAP_SYS_RAWIO)        \
	F(CAP_SYS_CHROOT)       \
	F(CAP_SYS_PTRACE)       \
	F(CAP_SYS_PACCT)        \
	F(CAP_SYS_ADMIN)        \
	F(CAP_SYS_BOOT)         \
	F(CAP_SYS_NICE)         \
	F(CAP_SYS_RESOURCE)     \
	F(CAP_SYS_TIME)         \
	F(CAP_SYS_TTY_CONFIG)   \
	F(CAP_MKNOD)            \
	F(CAP_LEASE)            \
	F(CAP_AUDIT_WRITE)      \
	F(CAP_AUDIT_CONTROL)    \
	F(CAP_SETFCAP)          \
	F(CAP_MAC_OVERRIDE)     \
	F(CAP_MAC_ADMIN)        \
	F(CAP_SYSLOG)           \
	F(CAP_WAKE_ALARM)       \
	F(CAP_BLOCK_SUSPEND)    \
	F(CAP_AUDIT_READ)       \
	F(CAP_PERFMON)          \
	F(CAP_BPF)              \
	F(CAP_CHECKPOINT_RESTORE)

enum capability {
#define LIST_CAPABILITY(CAP) CAP,
	FOR_EACH_CAPABILITY(LIST_CAPABILITY)
};

/* Since LSM hooks may change with different kernel versions, here we only list the common ones.
 * TODO: Implement best-effort mechanism and add the remaining ones,
 * this requires an upstream support: https://github.com/cilium/ebpf/discussions/1470
 * https://github.com/inspektor-gadget/inspektor-gadget/blob/main/gadgets/trace_lsm/program.bpf.c#L12
 */
#define FOR_EACH_LSM_HOOK(F)        \
	F(binder_set_context_mgr)   \
	F(binder_transaction)       \
	F(binder_transfer_binder)   \
	F(binder_transfer_file)     \
	F(ptrace_access_check)      \
	F(ptrace_traceme)           \
	F(capget)                   \
	F(capset)                   \
	F(capable)                  \
	F(quotactl)                 \
	F(quota_on)                 \
	F(syslog)                   \
	F(settime)                  \
	F(vm_enough_memory)         \
	F(bprm_creds_for_exec)      \
	F(bprm_creds_from_file)     \
	F(bprm_check_security)      \
	F(bprm_committing_creds)    \
	F(bprm_committed_creds)     \
	F(fs_context_dup)           \
	F(fs_context_parse_param)   \
	F(sb_alloc_security)        \
	F(sb_delete)                \
	F(sb_free_security)         \
	F(sb_free_mnt_opts)         \
	F(sb_eat_lsm_opts)          \
	F(sb_mnt_opts_compat)       \
	F(sb_remount)               \
	F(sb_kern_mount)            \
	F(sb_show_options)          \
	F(sb_statfs)                \
	F(sb_mount)                 \
	F(sb_umount)                \
	F(sb_pivotroot)             \
	F(sb_set_mnt_opts)          \
	F(sb_clone_mnt_opts)        \
	F(move_mount)               \
	F(dentry_init_security)     \
	F(dentry_create_files_as)   \
	F(path_notify)              \
	F(inode_alloc_security)     \
	F(inode_free_security)      \
	F(inode_init_security)      \
	F(inode_init_security_anon) \
	F(inode_create)             \
	F(inode_link)               \
	F(inode_unlink)             \
	F(inode_symlink)            \
	F(inode_mkdir)              \
	F(inode_rmdir)              \
	F(inode_mknod)              \
	F(inode_rename)             \
	F(inode_readlink)           \
	F(inode_follow_link)        \
	F(inode_permission)         \
	F(inode_setattr)            \
	F(inode_getattr)            \
	F(inode_setxattr)           \
	F(inode_post_setxattr)      \
	F(inode_getxattr)           \
	F(inode_listxattr)          \
	F(inode_removexattr)        \
	F(inode_need_killpriv)      \
	F(inode_killpriv)           \
	F(inode_getsecurity)        \
	F(inode_setsecurity)        \
	F(inode_listsecurity)       \
	F(inode_copy_up)            \
	F(inode_copy_up_xattr)      \
	F(kernfs_init_security)     \
	F(file_permission)          \
	F(file_alloc_security)      \
	F(file_free_security)       \
	F(file_ioctl)               \
	F(mmap_addr)                \
	F(mmap_file)                \
	F(file_mprotect)            \
	F(file_lock)                \
	F(file_fcntl)               \
	F(file_set_fowner)          \
	F(file_send_sigiotask)      \
	F(file_receive)             \
	F(file_open)                \
	F(task_alloc)               \
	F(task_free)                \
	F(cred_alloc_blank)         \
	F(cred_free)                \
	F(cred_prepare)             \
	F(cred_transfer)            \
	F(cred_getsecid)            \
	F(kernel_act_as)            \
	F(kernel_create_files_as)   \
	F(kernel_module_request)    \
	F(kernel_load_data)         \
	F(kernel_post_load_data)    \
	F(kernel_read_file)         \
	F(kernel_post_read_file)    \
	F(task_fix_setuid)          \
	F(task_fix_setgid)          \
	F(task_setpgid)             \
	F(task_getpgid)             \
	F(task_getsid)              \
	F(task_setnice)             \
	F(task_setioprio)           \
	F(task_getioprio)           \
	F(task_prlimit)             \
	F(task_setrlimit)           \
	F(task_setscheduler)        \
	F(task_getscheduler)        \
	F(task_movememory)          \
	F(task_kill)                \
	F(task_prctl)               \
	F(task_to_inode)            \
	F(ipc_permission)           \
	F(msg_msg_alloc_security)   \
	F(msg_msg_free_security)    \
	F(msg_queue_alloc_security) \
	F(msg_queue_free_security)  \
	F(msg_queue_associate)      \
	F(msg_queue_msgctl)         \
	F(msg_queue_msgsnd)         \
	F(msg_queue_msgrcv)         \
	F(shm_alloc_security)       \
	F(shm_free_security)        \
	F(shm_associate)            \
	F(shm_shmctl)               \
	F(shm_shmat)                \
	F(sem_alloc_security)       \
	F(sem_free_security)        \
	F(sem_associate)            \
	F(sem_semctl)               \
	F(sem_semop)                \
	F(netlink_send)             \
	F(d_instantiate)            \
	F(getprocattr)              \
	F(setprocattr)              \
	F(ismaclabel)               \
	F(secid_to_secctx)          \
	F(secctx_to_secid)          \
	F(release_secctx)           \
	F(inode_invalidate_secctx)  \
	F(inode_notifysecctx)       \
	F(inode_setsecctx)          \
	F(inode_getsecctx)

#define ENUM_ITEM(name) name,\

enum lsm_tracepoint { FOR_EACH_LSM_HOOK(ENUM_ITEM) };

#define TRACE_LSM(name)                                                    \
	SEC("lsm/" #name)                                                        \
	int trace_lsm_##name()                                                   \
	{                                                                        \
    u64 pid_tgid = bpf_get_current_pid_tgid();                             \
    uint *action = bpf_map_lookup_elem(&actions, &pid_tgid);               \
    if (action) {                                                          \
      bpf_map_delete_elem(&actions, &pid_tgid);                            \
      return -EPERM;                                                       \
    }                                                                      \
		return 0;                                                              \
	}

FOR_EACH_LSM_HOOK(TRACE_LSM)
