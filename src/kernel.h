#ifndef __NR_landlock_create_ruleset
#  if defined(__x86_64__)
#    define __NR_landlock_create_ruleset 444
#  elif defined(__i386__)
#    define __NR_landlock_create_ruleset 444
#  elif defined(__s390__) || defined(__s390x__)
#    define __NR_landlock_create_ruleset 444
#  elif defined(__aarch64__)
#    define __NR_landlock_create_ruleset 444
#  elif defined(__arm__)
#    define __NR_landlock_create_ruleset 444
#  elif defined(__powerpc__)
#    define __NR_landlock_create_ruleset 444
#  elif defined(__riscv)
#    define __NR_landlock_create_ruleset 444
#  elif defined(__mips64__)
#    define __NR_landlock_create_ruleset 5444
#  elif defined(__mips__)
#    define __NR_landlock_create_ruleset 4444
#  else
#    error "Unsupported architecture"
#  endif
#endif /* __NR_landlock_create_ruleset */

#ifndef __NR_landlock_add_rule
#  if defined(__x86_64__)
#    define __NR_landlock_add_rule 445
#  elif defined(__i386__)
#    define __NR_landlock_add_rule 445
#  elif defined(__s390__) || defined(__s390x__)
#    define __NR_landlock_add_rule 445
#  elif defined(__aarch64__)
#    define __NR_landlock_add_rule 445
#  elif defined(__arm__)
#    define __NR_landlock_add_rule 445
#  elif defined(__powerpc__)
#    define __NR_landlock_add_rule 445
#  elif defined(__riscv)
#    define __NR_landlock_add_rule 445
#  elif defined(__mips64__)
#    define __NR_landlock_add_rule 5445
#  elif defined(__mips__)
#    define __NR_landlock_add_rule 4445
#  else
#    error "Unsupported architecture"
#  endif
#endif /* __NR_landlock_add_rule */

#ifndef __NR_landlock_restrict_self
#  if defined(__x86_64__)
#    define __NR_landlock_restrict_self 446
#  elif defined(__i386__)
#    define __NR_landlock_restrict_self 446
#  elif defined(__s390__) || defined(__s390x__)
#    define __NR_landlock_restrict_self 446
#  elif defined(__aarch64__)
#    define __NR_landlock_restrict_self 446
#  elif defined(__arm__)
#    define __NR_landlock_restrict_self 446
#  elif defined(__powerpc__)
#    define __NR_landlock_restrict_self 446
#  elif defined(__riscv)
#    define __NR_landlock_restrict_self 446
#  elif defined(__mips64__)
#    define __NR_landlock_restrict_self 5446
#  elif defined(__mips__)
#    define __NR_landlock_restrict_self 4446
#  else
#    error "Unsupported architecture"
#  endif
#endif /* __NR_landlock_restrict_self */

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#  define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif
#ifndef LANDLOCK_CREATE_RULESET_ERRATA
#  define LANDLOCK_CREATE_RULESET_ERRATA (1U << 1)
#endif

#ifndef LANDLOCK_ACCESS_FS_EXECUTE
#  define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#endif
#ifndef LANDLOCK_ACCESS_FS_WRITE_FILE
#  define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#endif
#ifndef LANDLOCK_ACCESS_FS_READ_FILE
#  define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
#endif
#ifndef LANDLOCK_ACCESS_FS_READ_DIR
#  define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
#endif
#ifndef LANDLOCK_ACCESS_FS_REMOVE_DIR
#  define LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
#endif
#ifndef LANDLOCK_ACCESS_FS_REMOVE_FILE
#  define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_CHAR
#  define LANDLOCK_ACCESS_FS_MAKE_CHAR (1ULL << 6)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_DIR
#  define LANDLOCK_ACCESS_FS_MAKE_DIR (1ULL << 7)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_REG
#  define LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_SOCK
#  define LANDLOCK_ACCESS_FS_MAKE_SOCK (1ULL << 9)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_FIFO
#  define LANDLOCK_ACCESS_FS_MAKE_FIFO (1ULL << 10)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_BLOCK
#  define LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
#endif
#ifndef LANDLOCK_ACCESS_FS_MAKE_SYM
#  define LANDLOCK_ACCESS_FS_MAKE_SYM (1ULL << 12)
#endif
#ifndef LANDLOCK_ACCESS_FS_REFER
#  define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#  define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL
#  define LANDLOCK_ACCESS_FS_IOCTL (1ULL << 15)
#endif

#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#  define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#endif
#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#  define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

#ifndef LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
#  define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#endif
#ifndef LANDLOCK_SCOPE_SIGNAL
#  define LANDLOCK_SCOPE_SIGNAL (1ULL << 1)
#endif

#ifndef LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF
#  define LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF (1U << 0)
#endif
#ifndef LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON
#  define LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON (1U << 1)
#endif
#ifndef LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF
#  define LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF (1U << 2)
#endif

struct linux_landlock_ruleset_attr {
	__u64 handled_access_fs;
	__u64 handled_access_net;
	__u64 scoped;
};

enum linux_landlock_rule_type {
  LINUX_LANDLOCK_RULE_PATH_BENEATH = 1,
  LINUX_LANDLOCK_RULE_NET_PORT,
};

struct linux_landlock_path_beneath_attr {
  __u64 allowed_access;
  __s32 parent_fd;
} __attribute__((packed));

struct linux_landlock_net_port_attr {
  __u64 allowed_access;
  __u64 port;
};

static inline long
linux_landlock_create_ruleset(
    const struct linux_landlock_ruleset_attr* const attr,
    const size_t size,
    const __u32 flags) {
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static inline long
linux_landlock_add_rule(const int ruleset_fd,
                        const enum linux_landlock_rule_type rule_type,
                        const void* const rule_attr,
                        const __u32 flags) {
	return syscall(
    __NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags
  );
}

static inline long linux_landlock_restrict_self(const int ruleset_fd,
                                                const __u32 flags) {
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
