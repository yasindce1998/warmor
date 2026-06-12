#ifndef __VMLINUX_MINIMAL_H
#define __VMLINUX_MINIMAL_H

/*
 * Minimal kernel struct definitions for BPF CO-RE.
 * Only fields accessed by our LSM programs are declared.
 * CO-RE relocations handle correct offsets at load time.
 *
 * These kernel-internal structs are not in userspace headers.
 * At runtime, cilium/ebpf uses BTF from the running kernel
 * to relocate field accesses to correct offsets.
 */

struct linux_binprm {
	const char *filename;
} __attribute__((preserve_access_index));

struct qstr {
	const unsigned char *name;
} __attribute__((preserve_access_index));

struct dentry {
	struct qstr d_name;
} __attribute__((preserve_access_index));

struct path {
	struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
} __attribute__((preserve_access_index));

struct socket {
	short type;
} __attribute__((preserve_access_index));

struct sockaddr {
	unsigned short sa_family;
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_MINIMAL_H */
