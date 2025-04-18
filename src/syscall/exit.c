/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2015 STMicroelectronics
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <errno.h>       /* errno(3), E* */
#include <sys/utsname.h> /* struct utsname, */
#include <linux/net.h>   /* SYS_*, */
#include <string.h>      /* strlen(3), */

#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/socket.h"
#include "syscall/chain.h"
#include "syscall/heap.h"
#include "syscall/rlimit.h"
#include "execve/execve.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "path/path.h"
#include "ptrace/ptrace.h"
#include "ptrace/wait.h"
#include "extension/extension.h"
#include "arch.h"

// char* resovle_path(Tracee *tracee, word_t sysnum) {
// 	char *path = NULL;
// 	if (sysnum == PR_fchownat || sysnum == PR_fstatat64 || sysnum == PR_newfstatat || sysnum == PR_statx) {
// 		Reg dirfd_sysarg;
// 		Reg pathname_sysarg;
// 		dirfd_sysarg = SYSARG_1;
// 		pathname_sysarg = SYSARG_2;
// 		int dirfd = peek_reg(tracee, ORIGINAL, dirfd_sysarg);
// 		char rel_path[PATH_MAX];
// 		int status = get_sysarg_path(tracee, rel_path, pathname_sysarg);
// 		if (status < 0) {
// 			return NULL;
// 		}
// 		if (dirfd == AT_FDCWD) {
// 			path = strdup(rel_path);
// 		}else {
// 			// 获取 dirfd 对应的目录路径
// 			char dir_path[PATH_MAX];
// 			snprintf(dir_path, sizeof(dir_path), "/proc/self/fd/%d", dirfd);
			
// 			char *dir_real_path = (char *)malloc(PATH_MAX);
// 			if (readlink(dir_path, dir_real_path, PATH_MAX) == -1) {
// 				perror("readlink");
// 				free(dir_real_path);
// 				dir_real_path = NULL;
// 			} else {
// 				dir_real_path[PATH_MAX - 1] = '\0';
// 			}
			
// 			if (dir_real_path) {
// 				// 拼接目录路径和相对路径
// 				path = (char *)malloc(PATH_MAX);
// 				snprintf(path, PATH_MAX, "%s/%s", dir_real_path, rel_path);
// 				free(dir_real_path);
// 			}
// 		}
// 	}else if (sysnum == PR_fchown || sysnum == PR_fchown32 || sysnum == PR_fstat || sysnum == PR_fstat64) {
// 		Reg fd_sysarg;
// 		fd_sysarg = SYSARG_1;
// 		int fd = peek_reg(tracee, ORIGINAL, fd_sysarg);
// 		char proc_path[PATH_MAX];
//         snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
        
//         // 使用 readlink 获取文件路径
//         path = (char *)malloc(PATH_MAX);
//         if (readlink(proc_path, path, PATH_MAX) == -1) {
//             perror("readlink");
//             free(path);
//             path = NULL;
//         } else {
//             // 确保路径以 null 结尾
//             path[PATH_MAX - 1] = '\0';
//         }
// 	} else if(sysnum == PR_lchown || sysnum == PR_lchown32 || sysnum == PR_chown || sysnum == PR_chown32 ||
// 		sysnum == PR_stat || sysnum == PR_lstat || sysnum == PR_stat64 || sysnum == PR_lstat64	) {
// 		Reg path_sysarg;
// 		path_sysarg = SYSARG_1;
// 		char rel_path[PATH_MAX];
// 		int status = get_sysarg_path(tracee, rel_path, path_sysarg);
// 		if (status < 0) {
// 			return NULL;
// 		}
// 		path = strdup(rel_path);
// 	} 

// 	return path;
// }
// void record_file_state(Tracee *tracee, word_t sysnum) 
// {
// 	switch (sysnum)
// 	{
// 		case PR_chown:
// 		case PR_chown32:
// 		case PR_lchown:
// 		case PR_lchown32:
// 		case PR_fchown:
// 		case PR_fchown32:
// 		case PR_fchownat: {
// 			Reg uid_sysarg;
// 			Reg gid_sysarg;
// 			uid_t uid;
// 			gid_t gid;
// 			if (sysnum == PR_fchownat) {
// 				uid_sysarg = SYSARG_3;
// 				gid_sysarg = SYSARG_4;
// 			}
// 			else {
// 				uid_sysarg = SYSARG_2;
// 				gid_sysarg = SYSARG_3;
// 			}
	
// 			uid = peek_reg(tracee, ORIGINAL, uid_sysarg);
// 			gid = peek_reg(tracee, ORIGINAL, gid_sysarg);
// 			char* pathname = resovle_path(tracee, sysnum);
// 			char *root = get_binding(tracee, GUEST, "/");
// 			if (pathname && strncmp(pathname, root, strlen(root)) == 0) {
// 				struct fakestat fs{};
// 				fprintf(stderr, "action_enter:%s,pathname=%s, uid=%d, gid=%d\n", stringify_sysnum(sysnum),pathname,uid, gid);
// 			}
// 			if (pathname) {
// 				free(pathname);
// 			}
// 			break;
// 		}
// 	// case PR_fstatat64:
// 	// case PR_newfstatat:
// 	// case PR_stat64:
// 	// case PR_lstat64:
// 	// case PR_fstat64:
// 	// case PR_stat:
// 	// case PR_statx:
// 	// case PR_lstat:
// 	// case PR_fstat: {
// 	// 	char *pathname = resovle_path(tracee, sysnum);
// 	// 	if (pathname) {
// 	// 		fprintf(stderr, "action_enter:%s,pathname=%s, uid=%d, gid=%d\n", stringify_sysnum(sysnum),pathname);
// 	// 		free(pathname);
// 	// 	}
// 	// 	break;
// 	// }
// 	default:
// 		break;
// 	}

// }

/**
 * Translate the output arguments of the current @tracee's syscall in
 * the @tracee->pid process area. This function sets the result of
 * this syscall to @tracee->status if an error occured previously
 * during the translation, that is, if @tracee->status is less than 0.
 */
void translate_syscall_exit(Tracee *tracee)
{
	word_t syscall_number;
	word_t syscall_result;
	int status;

	status = notify_extensions(tracee, SYSCALL_EXIT_START, 0, 0);
	if (status < 0) {
		poke_reg(tracee, SYSARG_RESULT, (word_t) status);
		goto end;
	}
	if (status > 0)
		return;

	/* Set the tracee's errno if an error occured previously during
	 * the translation. */
	int tracee_status = tracee->status;
	if (tracee->status < 0) {
		poke_reg(tracee, SYSARG_RESULT, (word_t) tracee->status);
		goto end;
	}

	/* Translate output arguments:
	 * - break: update the syscall result register with "status"
	 * - goto end: nothing else to do.
	 */
	syscall_number = get_sysnum(tracee, ORIGINAL);
	syscall_result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	switch (syscall_number) {
	case PR_brk:
		translate_brk_exit(tracee);
		goto end;

	case PR_getcwd: {
		char path[PATH_MAX];
		size_t new_size;
		size_t size;
		word_t output;

		size = (size_t) peek_reg(tracee, ORIGINAL, SYSARG_2);
		if (size == 0) {
			status = -EINVAL;
			break;
		}

		/* Ensure cwd still exists.  */
		status = translate_path(tracee, path, AT_FDCWD, ".", false);
		if (status < 0)
			break;

		new_size = strlen(tracee->fs->cwd) + 1;
		if (size < new_size) {
			status = -ERANGE;
			break;
		}

		/* Overwrite the path.  */
		output = peek_reg(tracee, ORIGINAL, SYSARG_1);
		status = write_data(tracee, output, tracee->fs->cwd, new_size);
		if (status < 0)
			break;

		/* The value of "status" is used to update the returned value
		 * in translate_syscall_exit().  */
		status = new_size;
		break;
	}

	case PR_accept:
	case PR_accept4:
		/* Nothing special to do if no sockaddr was specified.  */
		if (peek_reg(tracee, ORIGINAL, SYSARG_2) == 0)
			goto end;
		/* Fall through.  */
	case PR_getsockname:
	case PR_getpeername: {
		word_t sock_addr;
		word_t size_addr;
		word_t max_size;

		/* Error reported by the kernel.  */
		if ((int) syscall_result < 0)
			goto end;

		sock_addr = peek_reg(tracee, ORIGINAL, SYSARG_2);
		size_addr = peek_reg(tracee, MODIFIED, SYSARG_3);
		max_size  = peek_reg(tracee, MODIFIED, SYSARG_6);

		status = translate_socketcall_exit(tracee, sock_addr, size_addr, max_size);
		if (status < 0)
			break;

		/* Don't overwrite the syscall result.  */
		goto end;
	}

#define SYSARG_ADDR(n) (args_addr + ((n) - 1) * sizeof_word(tracee))

#define POKE_WORD(addr, value)			\
	poke_word(tracee, addr, value);		\
	if (errno != 0)	{			\
		status = -errno;		\
		break;				\
	}

#define PEEK_WORD(addr)				\
	peek_word(tracee, addr);		\
	if (errno != 0) {			\
		status = -errno;		\
		break;				\
	}

	case PR_socketcall: {
		word_t args_addr;
		word_t sock_addr;
		word_t size_addr;
		word_t max_size;

		args_addr = peek_reg(tracee, ORIGINAL, SYSARG_2);

		switch (peek_reg(tracee, ORIGINAL, SYSARG_1)) {
		case SYS_ACCEPT:
		case SYS_ACCEPT4:
			/* Nothing special to do if no sockaddr was specified.  */
			sock_addr = PEEK_WORD(SYSARG_ADDR(2));
			if (sock_addr == 0)
				goto end;
			/* Fall through.  */
		case SYS_GETSOCKNAME:
		case SYS_GETPEERNAME:
			/* Handle these cases below.  */
			status = 1;
			break;

		case SYS_BIND:
		case SYS_CONNECT:
			/* Restore the initial parameters: this memory was
			 * overwritten at the enter stage.  Remember: POKE_WORD
			 * puts -errno in status and breaks if an error
			 * occured.  */
			POKE_WORD(SYSARG_ADDR(2), peek_reg(tracee, MODIFIED, SYSARG_5));
			POKE_WORD(SYSARG_ADDR(3), peek_reg(tracee, MODIFIED, SYSARG_6));

			status = 0;
			break;

		default:
			status = 0;
			break;
		}

		/* Error reported by the kernel or there's nothing else to do.  */
		if ((int) syscall_result < 0 || status == 0)
			goto end;

		/* An error occured in SYS_BIND or SYS_CONNECT.  */
		if (status < 0)
			break;

		/* Remember: PEEK_WORD puts -errno in status and breaks if an
		 * error occured.  */
		sock_addr = PEEK_WORD(SYSARG_ADDR(2));
		size_addr = PEEK_WORD(SYSARG_ADDR(3));
		max_size  = peek_reg(tracee, MODIFIED, SYSARG_6);

		status = translate_socketcall_exit(tracee, sock_addr, size_addr, max_size);
		if (status < 0)
			break;

		/* Don't overwrite the syscall result.  */
		goto end;
	}

#undef SYSARG_ADDR
#undef PEEK_WORD
#undef POKE_WORD

	case PR_fchdir:
	case PR_chdir:
		/* These syscalls are fully emulated, see enter.c for details
		 * (like errors).  */
		status = 0;
		break;

	case PR_rename:
	case PR_renameat:
	case PR_renameat2: {
		char old_path[PATH_MAX];
		char new_path[PATH_MAX];
		ssize_t old_length;
		ssize_t new_length;
		Comparison comparison;
		Reg old_reg;
		Reg new_reg;
		char *tmp;

		/* Error reported by the kernel.  */
		if ((int) syscall_result < 0)
			goto end;

		if (syscall_number == PR_rename) {
			old_reg = SYSARG_1;
			new_reg = SYSARG_2;
		}
		else {
			old_reg = SYSARG_2;
			new_reg = SYSARG_4;
		}

		/* Get the old path, then convert it to the same
		 * "point-of-view" as tracee->fs->cwd (guest).  */
		status = read_path(tracee, old_path, peek_reg(tracee, MODIFIED, old_reg));
		if (status < 0)
			break;

		status = detranslate_path(tracee, old_path, NULL);
		if (status < 0)
			break;
		old_length = (status > 0 ? status - 1 : (ssize_t) strlen(old_path));

		/* Nothing special to do if the moved path is not the
		 * current working directory.  */
		comparison = compare_paths(old_path, tracee->fs->cwd);
		if (comparison != PATH1_IS_PREFIX && comparison != PATHS_ARE_EQUAL) {
			status = 0;
			break;
		}

		/* Get the new path, then convert it to the same
		 * "point-of-view" as tracee->fs->cwd (guest).  */
		status = read_path(tracee, new_path, peek_reg(tracee, MODIFIED, new_reg));
		if (status < 0)
			break;

		status = detranslate_path(tracee, new_path, NULL);
		if (status < 0)
			break;
		new_length = (status > 0 ? status - 1 : (ssize_t) strlen(new_path));

		/* Sanity check.  */
		if (strlen(tracee->fs->cwd) >= PATH_MAX) {
			status = 0;
			break;
		}
		strcpy(old_path, tracee->fs->cwd);

		/* Update the virtual current working directory.  */
		substitute_path_prefix(old_path, old_length, new_path, new_length);

		tmp = talloc_strdup(tracee->fs, old_path);
		if (tmp == NULL) {
			status = -ENOMEM;
			break;
		}

		TALLOC_FREE(tracee->fs->cwd);
		tracee->fs->cwd = tmp;

		status = 0;
		break;
	}

	case PR_readlink:
	case PR_readlinkat: {
		char referee[PATH_MAX];
		char referer[PATH_MAX];
		size_t old_size;
		size_t new_size;
		size_t max_size;
		word_t input;
		word_t output;

		/* Error reported by the kernel.  */
		if ((int) syscall_result < 0)
			goto end;

		old_size = syscall_result;

		if (syscall_number == PR_readlink) {
			output   = peek_reg(tracee, ORIGINAL, SYSARG_2);
			max_size = peek_reg(tracee, ORIGINAL, SYSARG_3);
			input    = peek_reg(tracee, MODIFIED, SYSARG_1);
		}
		else {
			output   = peek_reg(tracee, ORIGINAL,  SYSARG_3);
			max_size = peek_reg(tracee, ORIGINAL, SYSARG_4);
			input    = peek_reg(tracee, MODIFIED, SYSARG_2);
		}

		if (max_size > PATH_MAX)
			max_size = PATH_MAX;

		if (max_size == 0) {
			status = -EINVAL;
			break;
		}

		/* The kernel does NOT put the NULL terminating byte for
		 * readlink(2).  */
		status = read_data(tracee, referee, output, old_size);
		if (status < 0)
			break;
		referee[old_size] = '\0';

		/* Not optimal but safe (path is fully translated).  */
		status = read_path(tracee, referer, input);
		if (status < 0)
			break;

		if (status >= PATH_MAX) {
			status = -ENAMETOOLONG;
			break;
		}

		status = detranslate_path(tracee, referee, referer);
		if (status < 0)
			break;

		/* The original path doesn't require any transformation, i.e
		 * it is a symetric binding.  */
		if (status == 0)
			goto end;

		/* Overwrite the path.  Note: the output buffer might be
		 * initialized with zeros but it was updated with the kernel
		 * result, and then with the detranslated result.  This later
		 * might be shorter than the former, so it's safier to add a
		 * NULL terminating byte when possible.  This problem was
		 * exposed by IDA Demo 6.3.  */
		if ((size_t) status < max_size) {
			new_size = status - 1;
			status = write_data(tracee, output, referee, status);
		}
		else {
			new_size = max_size;
			status = write_data(tracee, output, referee, max_size);
		}
		if (status < 0)
			break;

		/* The value of "status" is used to update the returned value
		 * in translate_syscall_exit().  */
		status = new_size;
		break;
	}

#if defined(ARCH_X86_64)
	case PR_uname: {
		struct utsname utsname;
		word_t address;
		size_t size;

		if (get_abi(tracee) != ABI_2)
			goto end;

		/* Error reported by the kernel.  */
		if ((int) syscall_result < 0)
			goto end;

		address = peek_reg(tracee, ORIGINAL, SYSARG_1);

		status = read_data(tracee, &utsname, address, sizeof(utsname));
		if (status < 0)
			break;

		/* Some 32-bit programs like package managers can be
		 * confused when the kernel reports "x86_64".  */
		size = sizeof(utsname.machine);
		strncpy(utsname.machine, "i686", size);
		utsname.machine[size - 1] = '\0';

		status = write_data(tracee, address, &utsname, sizeof(utsname));
		if (status < 0)
			break;

		status = 0;
		break;
	}
#endif

	case PR_execve:
		translate_execve_exit(tracee);
		goto end;

	case PR_ptrace:
		status = translate_ptrace_exit(tracee);
		break;

	case PR_wait4:
	case PR_waitpid: {
		bool set_result = true;
		if (tracee->as_ptracer.waits_in != WAITS_IN_PROOT)
			goto end;

		status = translate_wait_exit(tracee, &set_result);
		if (!set_result)
			goto end;
		break;
	}

	case PR_setrlimit:
	case PR_prlimit64:
		/* Error reported by the kernel.  */
		if ((int) syscall_result < 0)
			goto end;

		status = translate_setrlimit_exit(tracee, syscall_number == PR_prlimit64);
		if (status < 0)
			break;

		/* Don't overwrite the syscall result.  */
		goto end;

	default:
		goto end;
	}

	poke_reg(tracee, SYSARG_RESULT, (word_t) status);
	//if (status == 0)
	//	record_file_state(tracee, syscall_number);;
end:
	status = notify_extensions(tracee, SYSCALL_EXIT_END, 0, 0);
	if (status < 0)
		poke_reg(tracee, SYSARG_RESULT, (word_t) status);
	// if (tracee_status != 0  && status == 0)
	// 	record_file_state(tracee, syscall_number);;
}
