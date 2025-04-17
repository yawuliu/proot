#include <stdio.h>
#include <stdint.h>
#include <sqlite3.h>
#include "fake_id0.h"
#include <sys/stat.h>
#include <sys/xattr.h>
#include <linux/capability.h>
#include "tracee/tracee.h"
#include "extension/extension.h"

static sqlite3 *state_db = NULL;
#define sqlite3_column_raw_uint64(stmt, columnindex) *(uint64_t *)(sqlite3_column_blob((sqlite3_stmt *)(stmt),(columnindex)))
//==============================
// 全局哈希表
static file_hash_entry_t *map_hash = NULL;

bool load_map(char* state_file)
{
    int rc;
    if (state_db != NULL) {
        fprintf(stderr, "database already opened: %s\n", state_file);
        return false;
    }
    // 打开 SQLite 数据库
    rc = sqlite3_open(state_file, &state_db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(state_db));
        return false;
    }
     // 启用 WAL 模式
    char *errMsg = 0;
    rc = sqlite3_exec(state_db, "PRAGMA journal_mode=WAL;", 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
        return 1;
    }
    // 检查表是否存在，如果不存在则创建
    const char *sql = "CREATE TABLE IF NOT EXISTS fakedb (" 
                      "path TEXT NOT NULL,"
                      "dev INTEGER NOT NULL, "
                      "ino INTEGER NOT NULL, "
                      "mode INTEGER NOT NULL, "
                      "uid INTEGER NOT NULL, "
                      "gid INTEGER NOT NULL, "
                      "rdev INTEGER NOT NULL, "
                      "nlink INTEGER NOT NULL, "
                      "caps TEXT NOT NULL,"
                      "UNIQUE (dev, ino) ON CONFLICT REPLACE);";

    rc = sqlite3_exec(state_db, sql, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
        sqlite3_close(state_db);
        state_db = NULL;
        return false;
    }
    //
    sql = "SELECT path, dev, ino, mode, uid, gid, rdev, nlink, caps FROM fakedb;";
    sqlite3_stmt *stmt;

    rc = sqlite3_prepare_v2(state_db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(state_db));
        return false;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        stat_override_t override={0};
        const char* pp = sqlite3_column_text(stmt, 0);
        if (pp!=NULL) {
            strncpy(override.path, pp, strlen(pp));
        }
        override.dev = sqlite3_column_int(stmt, 1);
        override.inode = sqlite3_column_int(stmt, 2);
        override.mode = sqlite3_column_int(stmt, 3);
        override.uid = sqlite3_column_int(stmt, 4);
        override.gid = sqlite3_column_int(stmt, 5);
        override.dev_id = sqlite3_column_int(stmt, 6);
        override.nlink = sqlite3_column_int(stmt, 7);
        pp = sqlite3_column_text(stmt, 8);
        if (pp!=NULL) {
            strncpy(override.caps, pp, strlen(pp));
        }
        set_map( &override );
    }

    sqlite3_finalize(stmt);
    return true;
}

bool save_map()
{
    const char *sql = "DELETE FROM fakedb;";
    char *errMsg = 0;
    int rc = sqlite3_exec(state_db, sql, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
        sqlite3_close(state_db);
        state_db = NULL;
        return false;
    } else {
        printf("Table 'fakedb' cleared successfully.\n");
    }
    //
    sql = "INSERT INTO fakedb (path, dev, ino, mode, uid, gid, rdev, nlink, caps) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(state_db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(state_db));
        return false;
    }
    file_hash_entry_t *current_entry = NULL, *tmp = NULL;
    HASH_ITER(hh, map_hash, current_entry, tmp) {
        const stat_override_t *override = &current_entry->value;
        // fprintf(stderr,"override->dev=%d,override->inode=%d,override->transient=%d\n",
        //  override->dev, override->inode, override->transient);
        if (!override->transient) {
            sqlite3_bind_text(stmt, 1, override->path, -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 2, override->dev);
            sqlite3_bind_int(stmt, 3, override->inode);
            sqlite3_bind_int(stmt, 4, override->mode);
            sqlite3_bind_int(stmt, 5, override->uid);
            sqlite3_bind_int(stmt, 6, override->gid);
            sqlite3_bind_int(stmt, 7, override->dev_id);
            sqlite3_bind_int(stmt, 8, override->nlink);
            sqlite3_bind_text(stmt, 9, override->caps, -1, SQLITE_STATIC);

            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE) {
                fprintf(stderr, "SQL step error: %s\n", sqlite3_errmsg(state_db));
                sqlite3_finalize(stmt);
                return false;
            }
            sqlite3_reset(stmt);
            //sqlite3_clear_bindings(stmt);
        }
        HASH_DEL(map_hash, current_entry);
        free(current_entry);
    }
    sqlite3_finalize(stmt);
    return true;
}

// 插入或更新数据
// int insert_or_update_file_state(const struct fakestat *fs) {
//     if (!fs || !fs->path) {
//         fprintf(stderr, "Invalid input\n");
//         return 1;
//     }

//     const char *sql = "INSERT OR REPLACE INTO file_state (path, uid, gid, mode) VALUES (?, ?, ?, ?);";
//     sqlite3_stmt *stmt;

//     int rc = sqlite3_prepare_v2(state_db, sql, -1, &stmt, 0);
//     if (rc != SQLITE_OK) {
//         fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(state_db));
//         return 1;
//     }

//     sqlite3_bind_text(stmt, 1, fs->path, -1, SQLITE_STATIC);
//     sqlite3_bind_int(stmt, 2, fs->uid);
//     sqlite3_bind_int(stmt, 3, fs->gid);
//     sqlite3_bind_int(stmt, 4, fs->mode);

//     rc = sqlite3_step(stmt);
//     if (rc != SQLITE_DONE) {
//         fprintf(stderr, "SQL step error: %s\n", sqlite3_errmsg(state_db));
//         sqlite3_finalize(stmt);
//         return 1;
//     }

//     sqlite3_finalize(stmt);
//     return 0;
// }


// 查询数据
// int query_file_state(const char *path, struct fakestat *fs) {
//     if (!path || !fs) {
//         fprintf(stderr, "Invalid input\n");
//         return 1;
//     }

//     const char *sql = "SELECT path, uid, gid, mode FROM file_state WHERE path = ?;";
//     sqlite3_stmt *stmt;

//     int rc = sqlite3_prepare_v2(state_db, sql, -1, &stmt, 0);
//     if (rc != SQLITE_OK) {
//         fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(state_db));
//         return 1;
//     }

//     sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);

//     if (sqlite3_step(stmt) == SQLITE_ROW) {
//         const char* path = (const char *)sqlite3_column_text(stmt, 0);
//         strncpy(fs->path, path, strlen(path));
//         fs->uid = sqlite3_column_int(stmt, 1);
//         fs->gid = sqlite3_column_int(stmt, 2);
//         fs->mode = sqlite3_column_int(stmt, 3);
//         rc = 0;
//     } else {
//         rc = 1;
//     }

//     sqlite3_finalize(stmt);
//     return rc;
// }

// void record_file_stat(const char *path, int uid, int gid, int mode, int sysnum) {
//     struct fakestat fs = {.path={},.uid = uid,.gid = gid,.mode = -1};
//     strncpy(fs.path, path, strlen(path));
//     struct fakestat fs1;
//     int exist = query_file_state(path, &fs1);
//     struct stat stat_info;
//     int status = stat(fs.path, &stat_info);
//     if (status != 0) {
//         perror("stat");
//         return;
//     }
//     if (mode == -1) {
//         if (0 == exist) {
//             fs.mode = fs1.mode & 0777;
//         } else {
//             fs.mode = stat_info.st_mode & 0777;
//         }
//     } else {
//         fs.mode = mode & 0777;
//     }
//     if (uid == -1) {
//         if (0 == exist) {
// 			fs.uid = fs1.uid;
// 			fs.gid = fs1.gid;
// 		} else {
//             fs.uid = stat_info.st_uid;
// 			fs.gid = stat_info.st_gid;
//         }
//     }
//     insert_or_update_file_state(&fs);
// }



char *fd_to_path(pid_t pid, int fd) {
    char proc_path[PATH_MAX];
    char symlink_path[PATH_MAX];
    char *real_path = NULL;

    // 构造 /proc/self/fd/[fd] 的路径
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd/%d", pid, fd);

  // 读取符号链接的目标路径
    if (readlink(proc_path, symlink_path, sizeof(symlink_path) - 1) != -1) {
        symlink_path[sizeof(symlink_path) - 1] = '\0';
        real_path = realpath(symlink_path, NULL);
    }
    return real_path;
}

// // 哈希函数
// unsigned int hash_key(const override_key_t *key) {
//     // 简单的哈希函数，结合 dev 和 inode
//     return (unsigned int)(key->dev) ^ (unsigned int)(key->inode);
// }
// // 比较函数
// int compare_keys(const override_key_t *a, const override_key_t *b) {
//     return (a->dev == b->dev) && (a->inode == b->inode);
// }

// 查找函数
bool get_map(dev_t dev, unsigned long inode, stat_override_t* stat) {
    override_key_t key = {dev, inode};
    file_hash_entry_t *entry = NULL;
    HASH_FIND(hh, map_hash, &key, sizeof(override_key_t), entry);
    if (entry) {
        memcpy(stat, &entry->value, sizeof(stat_override_t));
        return true;
    }
    return false;
}

// 设置函数
void set_map(const stat_override_t *stat) {
    file_hash_entry_t tmp, *entry;
    tmp.key.dev = stat->dev;
    tmp.key.inode = stat->inode;
    HASH_FIND(hh, map_hash, &tmp.key, sizeof(override_key_t), entry);
    if (stat->uid == 5) {
        int nn=0;
        nn++;
    }
    if (entry != NULL) {
        // 如果键已存在，更新值
        memcpy(&entry->value, stat, sizeof(stat_override_t));
    } else {
        // 如果键不存在，创建新条目
        entry = (file_hash_entry_t *)malloc(sizeof(file_hash_entry_t));
        if (!entry) {
            perror("malloc failed");
            return;
        }
        memset(entry, 0, sizeof(file_hash_entry_t));
        entry->key.dev = stat->dev;
        entry->key.inode = stat->inode;
        memcpy(&entry->value, stat, sizeof(stat_override_t));
        HASH_ADD(hh, map_hash, key, sizeof(override_key_t), entry);
    }
}
// Helper function - fill in an override structure from a stat structure
static void stat_override_copy( const struct stat *stat, const char* path, stat_override_t *override )
{
    override->dev=stat->st_dev;
    override->inode=stat->st_ino;
    override->uid=stat->st_uid;
    override->gid=stat->st_gid;
    override->dev_id=stat->st_rdev;
    override->mode=stat->st_mode;
    override->nlink= stat->st_nlink;
    memset(override->caps,0, PATH_MAX);
    if (path!=NULL) {
        strncpy(override->path, path, strlen(path));
    }
}

int fstat_proc_pid_fd(pid_t pid, int fd, struct stat* st) {
    char link[32]; /* 32 > sizeof("/proc//cwd") + sizeof(#ULONG_MAX) */
	int status;
	/* Format the path to the "virtual" link. */
	status = snprintf(link, sizeof(link), "/proc/%d/fd/%d",	pid, fd);
    if (status < 0)
		return -1;
    return stat(link, st);
}

bool real_open(Tracee *tracee, Config *config, const char* fullpath, int mode_argnum) {
	word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 打开失败了
		return;
	}
	mode_t mode = peek_reg(tracee, ORIGINAL, mode_argnum);
	int fd = (int)result;
	struct stat stat;
	int status = fstat_proc_pid_fd(tracee->pid, fd, &stat);
	if (status < 0) {
        perror("fstat");
		return 0;
    }
	stat_override_t override = {0};
	if(!get_map(stat.st_dev, stat.st_ino, &override) || override.transient) {
 		// If the map already exists, assume we did not create a new file and don't touch the owners
		stat_override_copy(&stat, fullpath, &override);

		override.uid=config->suid; //getuid();
		override.gid=config->sgid; //getgid();
		override.mode&=~07600;
		override.mode|= mode&07600;
		// XXX We are ignoring the umask here!

		set_map( &override );
	}
}
/*
int sys_open(const char *path, int flags, mode_t mode)
*/
bool sys_open(Tracee *tracee, Config *config) {
	word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 打开失败了
		return;
	}
    char filename[PATH_MAX];
    int status = get_sysarg_path(tracee, filename, SYSARG_1);
    if (status < 0) {
        return false;
    }
    //fprintf(stderr, "open(%s)\n", filename);
	return real_open(tracee, config, filename, SYSARG_3);
}
/*
int sys_openat(int dirfd, const char *path, int flags, mode_t mode)
*/
bool sys_openat(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 打开失败了
		return;
	}
    int dirfd = peek_reg(tracee, ORIGINAL, SYSARG_1);
    char path[PATH_MAX];
    int status = get_sysarg_path(tracee, path, SYSARG_2);
     if (status < 0) {
        return false;
    }
    char pathname[PATH_MAX] = {0};
    if (dirfd == AT_FDCWD) {
		strncpy(pathname, path, strlen(path));
	} else {
        // 获取 dirfd 对应的目录路径
        char dir_path[PATH_MAX];
        status = readlink_proc_pid_fd(tracee->pid, dirfd, dir_path);
        if (status < 0) {
            return false;
        }
        if (dir_path[0] != 0) {
            // 拼接目录路径和相对路径
            snprintf(pathname, PATH_MAX, "%s/%s", dir_path, path);
        }
    }
    //fprintf(stderr, "openat(%s)\n", pathname);
    if (NULL!=strstr(pathname, "etc/bash.bashrc")) {
        int n=0;
        n++;
    }
	return real_open(tracee, config, pathname, SYSARG_4);
}

/*
int creat(const char *pathname, mode_t mode);
*/
bool sys_creat(Tracee *tracee, Config *config) {
	word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 失败了
		return false;
	}
    char pathname[PATH_MAX];
    int status = get_sysarg_path(tracee, pathname, SYSARG_1);
    if (status < 0) {
        return false;
    }
	mode_t mode = peek_reg(tracee, ORIGINAL, SYSARG_2);
	int fd = (int)result;
	struct stat stat;
	status = fstat_proc_pid_fd(tracee->pid, fd, &stat);
	if (status < 0) {
        perror("fstat");
		return 0;
    }
	stat_override_t override = {0};
	if(!get_map(stat.st_dev, stat.st_ino, &override) || override.transient) {
 		// If the map already exists, assume we did not create a new file and don't touch the owners
		stat_override_copy(&stat, pathname, &override);

		override.uid=config->suid; //getuid();
		override.gid=config->sgid; //getgid();
		override.mode&=~07600;
		override.mode|= mode&07600;
		// XXX We are ignoring the umask here!

		set_map( &override );
	}
}


#ifndef S_IFMT
/* VisualAge C/C++ Failed to Define MountType Field in sys/stat.h */
#define S_IFMT 0170000
#endif

bool real_mknod(Tracee *tracee, Config *config, const char* fullpath, int mode_offset, struct stat* stat1, int extra_flags/*= -1*/) {
	stat_override_t override = {0};
	if(!get_map(stat1->st_dev, stat1->st_ino, &override) || override.transient) {
 		// If the map already exists, assume we did not create a new file and don't touch the owners
		stat_override_copy(stat1, fullpath, &override);

		mode_t mode = (mode_t)peek_reg(tracee, ORIGINAL, mode_offset);
		if( S_ISCHR(mode) || S_ISBLK(mode) || (mode&07000)!=0) {
			override.mode=(override.mode&~(S_IFMT|07000)) | (mode&(S_IFMT|07000));
			override.dev_id=(dev_t)peek_reg(tracee, ORIGINAL, mode_offset+1);
		}
		// use the user read+write from the original, not the actual file
		// XXX This code disregards the umask
		override.mode&=~00600;
		override.mode|= mode&00600;

		set_map( &override );
	}
}
/*
long sys_mknod(const char *path, mode_t mode, dev_t dev)
*/
bool sys_mknod(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 修改失败
		return false;
	}
    char filename[PATH_MAX];
    int status = get_sysarg_path(tracee, filename, SYSARG_1);
    if (status < 0) {
        return false;
    }
    struct stat stat1;
    status = stat(filename, &stat1);
    if (status < 0) {
        perror("stat");
        return false;
    }
	return real_mknod(tracee, config, filename, SYSARG_2, &stat1, -1);
}
/*
long sys_mknodat(int dfd, const char __user * filename, umode_t mode, unsigned dev);
*/
bool sys_mknodat(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 修改失败
		return false;
	}
    int dfd = peek_reg(tracee, ORIGINAL, SYSARG_1);
    char filename[PATH_MAX];
	int status = get_sysarg_path(tracee, filename, SYSARG_2);
    if (status < 0) {
        return false;
    }
    struct stat stat1;
    status = fstatat(dfd, filename, &stat1, 0);
    if (status < 0) {
        perror("fstatat");
        return false;
    }
    //
    char pathname[PATH_MAX] = {0};
    if (dfd == AT_FDCWD) {
		strncpy(pathname, filename, strlen(filename));
	} else {
        // 获取 dirfd 对应的目录路径
        char dir_path[PATH_MAX];
        status = readlink_proc_pid_fd(tracee->pid, dfd, dir_path);
        if (status < 0) {
            return false;
        }
        if (dir_path[0] != 0) {
            // 拼接目录路径和相对路径
            snprintf(pathname, PATH_MAX, "%s/%s", dir_path, filename);
        }
    }
	return real_mknod(tracee, config, pathname, SYSARG_3, &stat1, 0);
}

bool real_chmod(Tracee *tracee, Config *config, const char* fullpath, int mode_offset, struct stat* stat1, int extra_flags/*=-1*/) {
    // if (x == 0){
        // Our stat succeeded
        stat_override_t override = {0};
        // Modify the chmod mode
        mode_t mode= peek_reg(tracee, ORIGINAL, mode_offset);

        mode&=~07000; // Clear the SUID etc. bits
        if(S_ISDIR(stat1->st_mode)) {
            // The node in question is a directory
            mode|=00700; // Make sure we have read, write and execute permission
        } else {
            // Node is not a directory
            mode|=00600; // Set read and write for owner
        }
        // If we don't already have an entry for this file in the lies database, we will not have
        // the complete stat struct later on to create it.
        if( !get_map(stat1->st_dev, stat1->st_ino, &override ) ) {
            // Create a lie that is identical to the actual file
            stat_override_copy(stat1, fullpath, &override );
            set_map( &override );
        }
     //} else if (x == 1) {
       // The chmod call succeeded - update the lies database
       memset(&override,0, sizeof(override));
       // mode_t mode= peek_reg(tracee, ORIGINAL, mode_offset);
        if( !get_map(stat1->st_dev, stat1->st_ino, &override ) ) {
            // We explicitly created this map not so long ago - something is wrong
            // XXX What can we do except hope these are reasonable values
            override.dev=stat1->st_dev;
            override.inode=stat1->st_ino;
            override.uid=0;
            override.gid=0;
            override.dev_id=0;
            override.transient=true;
        }
        override.mode=(override.mode&~07777)|(mode&07777);
        set_map( &override );
    // }
}

/*
int sys_chmod(const char *path, mode_t mode)
*/
bool sys_chmod(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 修改失败
		return false;
	}
    char filename[PATH_MAX];
    int status = get_sysarg_path(tracee, filename, SYSARG_1);
    if (status < 0) {
        return false;
    }
    struct stat stat1;
    status = stat(filename, &stat1);
    if (status < 0) {
        perror("stat");
        return false;
    }
	return real_chmod(tracee, config, filename, SYSARG_2, &stat1, -1);
}
/*
long sys_fchmod(unsigned int fd, umode_t mode);
*/
bool sys_fchmod(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 修改失败
		return false;
	}
    int fd = peek_reg(tracee, ORIGINAL, SYSARG_1);
    struct stat stat1;
    int status = fstat_proc_pid_fd(tracee->pid, fd, &stat1);
    if (status < 0) {
        perror("fstat");
        return false;
    }
    char* filepath = fd_to_path(tracee->pid, fd);
	return real_chmod(tracee, config, filepath, SYSARG_2, &stat1, -1);
}
/*
long sys_fchmodat(int dfd, const char __user *filename,
			     umode_t mode);
*/
bool sys_fchmodat(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 修改失败
		return false;
	}
    int dfd = peek_reg(tracee, ORIGINAL, SYSARG_1);
    char filename[PATH_MAX];
	int status = get_sysarg_path(tracee, filename, SYSARG_2);
    if (status < 0) {
        return false;
    }
    struct stat stat1;
    status = fstatat(dfd, filename, &stat1, 0);
    if (status < 0) {
        perror("fstatat");
        return false;
    }
    //
    char pathname[PATH_MAX] = {0};
    if (dfd == AT_FDCWD) {
		strncpy(pathname, filename, strlen(filename));
	} else {
        // 获取 dfd 对应的目录路径
        char dir_path[PATH_MAX];
        status = readlink_proc_pid_fd(tracee->pid, dfd, dir_path);
        if (status < 0) {
            return false;
        }
        if (dir_path[0] != 0) {
            // 拼接目录路径和相对路径
            snprintf(pathname, PATH_MAX, "%s/%s", dir_path, filename);
        }
    }
	return real_chmod(tracee, config, pathname, SYSARG_3, &stat1, 0);
}
/*
long sys_fchmodat2(int dfd, const char __user *filename,
			     umode_t mode, unsigned int flags);
*/

bool real_chown(Tracee *tracee, Config *config, const char* fullpath, int own_offset, struct stat* stat1, int extra_flags/*=-1*/) {
    stat_override_t override = {0};
    if( !get_map( stat1->st_dev, stat1->st_ino, &override ) ) {
        stat_override_copy(stat1, fullpath, &override);
    }

    int uid = peek_reg(tracee, ORIGINAL, own_offset);
    int gid = peek_reg(tracee, ORIGINAL, own_offset+1);
    if( uid != -1 )
        override.uid = uid;
    if( gid != -1 )
        override.gid = gid;
  
    set_map( &override );
}
/*
sys_chown(const char __user *filename,
				uid_t user, gid_t group);
*/
bool sys_chown(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 修改失败
		return false;
	}
    char filename[PATH_MAX];
    int status = get_sysarg_path(tracee, filename, SYSARG_1);
    if (status < 0) {
        return false;
    }
    struct stat stat1;
    status = stat(filename, &stat1);
    if (status < 0) {
        perror("stat");
        return false;
    }
	return real_chown(tracee, config, filename, SYSARG_2, &stat1, -1);
}

/*
long sys_fchown(unsigned int fd, uid_t user, gid_t group);
*/
bool sys_fchown(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 修改失败
		return false;
	}
    int fd = peek_reg(tracee, ORIGINAL, SYSARG_1);
    struct stat stat1;
    int status = fstat_proc_pid_fd(tracee->pid, fd, &stat1);
    if (status < 0) {
        perror("fstat");
        return false;
    }
    //
    char* filepath = fd_to_path(tracee->pid, fd);
	return real_chown(tracee, config, filepath, SYSARG_2, &stat1, -1);
}
/*
long sys_lchown(const char __user *filename,
				uid_t user, gid_t group);
*/
bool sys_lchown(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 修改失败
		return false;
	}
    char filename[PATH_MAX];
    int status = get_sysarg_path(tracee, filename, SYSARG_1);
    if (status < 0) {
        return false;
    }
    struct stat stat1;
    status = lstat(filename, &stat1);
    if (status < 0) {
        perror("lstat");
        return false;
    }
	return real_chown(tracee, config, filename, SYSARG_2, &stat1, -1);
}
/*
long sys_fchownat(int dfd, const char __user *filename, uid_t user,
			     gid_t group, int flag);
*/
bool sys_fchownat(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 修改失败
		return false;
	}
    int dfd = peek_reg(tracee, ORIGINAL, SYSARG_1);
    char filename[PATH_MAX];
	int status = get_sysarg_path(tracee, filename, SYSARG_2);
    if (status < 0) {
        return false;
    }
    int flag = peek_reg(tracee, ORIGINAL, SYSARG_5);
    struct stat stat1;
    status = fstatat(dfd, filename, &stat1, flag);
    if (status < 0) {
        perror("fstatat");
        return false;
    }
    //
    char pathname[PATH_MAX] = {0};
    if (dfd == AT_FDCWD) {
		strncpy(pathname, filename, strlen(filename));
	} else {
        // 获取 dfd 对应的目录路径
        char dir_path[PATH_MAX];
        status = readlink_proc_pid_fd(tracee->pid, dfd, dir_path);
        if (status < 0) {
            return false;
        }
        if (dir_path[0] != 0) {
            // 拼接目录路径和相对路径
            snprintf(pathname, PATH_MAX, "%s/%s", dir_path, filename);
        }
    }
	return real_chown(tracee, config, pathname, SYSARG_3, &stat1, flag);
}
bool real_mkdir(Tracee *tracee, Config *config, const char* fullpath, int mode_offset,  struct stat* stat1, int extra_flags/*=-1*/) {
    mode_t mode = peek_reg(tracee, ORIGINAL, mode_offset);
    stat_override_t override = {0};
    // Since mkdir fails if the directory already exists, there is no point to check whether the override already exists
    stat_override_copy(stat1, fullpath, &override);
    override.uid=config->suid;
    override.gid=config->sgid;

    override.mode&=~00700;
    override.mode|= mode&00700;
    // XXX This code does not take the umask into account

    set_map( &override );
}
/*
long sys_mkdir(const char __user *pathname, umode_t mode);
*/
bool sys_mkdir(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 创建失败
		return false;
	}
    char newname[PATH_MAX];
	int status = get_sysarg_path(tracee, newname, SYSARG_1);
    if (status < 0) {
        return false;
    }
    struct stat stat1;
    status = stat(newname, &stat1);
    if (status < 0) {
        perror("stat");
        return false;
    }
	return real_mkdir(tracee, config, newname, SYSARG_2, &stat1, -1);
}
/*
long sys_mkdirat(int dfd, const char __user * pathname, umode_t mode);
*/
bool sys_mkdirat(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 创建失败
		return false;
	}
    int dirfd = peek_reg(tracee, ORIGINAL, SYSARG_1);
    char filename[PATH_MAX];
	int status = get_sysarg_path(tracee, filename, SYSARG_2);
    if (status < 0) {
        return false;
    }
    struct stat stat1;
    status = fstatat(dirfd, filename, &stat1, 0);
    if (status < 0) {
        perror("fstatat");
        return false;
    }
    //
    char pathname[PATH_MAX] = {0};
    if (dirfd == AT_FDCWD) {
		strncpy(pathname, filename, strlen(filename));
	} else {
        // 获取 dirfd 对应的目录路径
        char dir_path[PATH_MAX];
        status = readlink_proc_pid_fd(tracee->pid, dirfd, dir_path);
        if (status < 0) {
            return false;
        }
        if (dir_path[0] != 0) {
            // 拼接目录路径和相对路径
            snprintf(pathname, PATH_MAX, "%s/%s", dir_path, filename);
        }
    }
	return real_mkdir(tracee, config, pathname, SYSARG_3, &stat1, 0);
}
bool real_symlink(Tracee *tracee, Config *config, const char* fullpath, int mode_offset, struct stat* stat1, int extra_flags /*= -1*/) {
    stat_override_t override = {0};
    if(S_ISLNK(stat1->st_mode)) {
        // No need to check the DB as we just created the file
        stat_override_copy(stat1, fullpath, &override);

        override.uid=config->suid;
        override.gid=config->sgid;

        set_map( &override );
    }
    return true;
}
/*
long sys_symlink(const char __user *old, const char __user *newname);
*/
bool sys_symlink(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 删除失败
		return false;
	}
    char newname[PATH_MAX];
	int status = get_sysarg_path(tracee, newname, SYSARG_2);
    if (status < 0) {
        return false;
    }
    struct stat stat1;
    status = lstat(newname, &stat1);
    if (status < 0) {
        perror("lstat");
        return false;
    }
	return real_symlink(tracee, config, newname, SYSARG_2, &stat1, -1);
}
/*
long sys_symlinkat(const char __user * oldname,
			      int newdfd, const char __user * newname);
*/
bool sys_symlinkat(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 删除失败
		return false;
	}
    int newdfd = peek_reg(tracee, ORIGINAL, SYSARG_2);
    char newname[PATH_MAX];
	int status = get_sysarg_path(tracee, newname, SYSARG_3);
    if (status < 0) {
        return false;
    }
    struct stat stat1;
    status = fstatat(newdfd, newname, &stat1, AT_SYMLINK_NOFOLLOW);
    if (status < 0) {
        perror("fstatat");
        return false;
    }
    //
    char pathname[PATH_MAX] = {0};
    if (newdfd == AT_FDCWD) {
		strncpy(pathname, newname, strlen(newname));
	} else {
        // 获取 dirfd 对应的目录路径
        char dir_path[PATH_MAX];
        status = readlink_proc_pid_fd(tracee->pid, newdfd, dir_path);
        if (status < 0) {
            return false;
        }
        if (dir_path[0] != 0) {
            // 拼接目录路径和相对路径
            snprintf(pathname, PATH_MAX, "%s/%s", dir_path, newname);
        }
    }
	return real_symlink(tracee, config, pathname, SYSARG_2, &stat1, AT_SYMLINK_NOFOLLOW);
}
/*
long sys_unlink(const char __user *pathname);
*/
bool sys_unlink(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 删除失败
		return;
	}
    char rel_path[PATH_MAX];
	int status = get_sysarg_path(tracee, rel_path, SYSARG_1);
    if (status < 0) {
        return false;
    }
    struct stat stat1;
	status = stat(rel_path, &stat1);
	if (status < 0) {
        perror("stat");
        return false;
    }
    // Need to erase the override from our database
    override_key_t key;
    key.dev=stat1.st_dev;
    key.inode=stat1.st_ino;
    stat_override_t map = {0};

    if( get_map( key.dev, key.inode, &map ) ) {
        map.transient=true;
        set_map( &map );
    }
}

/* long sys_unlinkat(int dfd, const char __user * pathname, int flag); */
bool sys_unlinkat(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 删除失败
		return false;
	}
    int dirfd = peek_reg(tracee, ORIGINAL, SYSARG_1);
    char rel_path[PATH_MAX];
	int status = get_sysarg_path(tracee, rel_path, SYSARG_2);
    if (status < 0) {
        return false;
    }
    char pathname[PATH_MAX] = {0};
    if (dirfd == AT_FDCWD) {
		strncpy(pathname, rel_path, strlen(rel_path));
	} else {
        // 获取 dirfd 对应的目录路径
        char dir_path[PATH_MAX];
        status = readlink_proc_pid_fd(tracee->pid, dirfd, dir_path);
        if (status < 0) {
            return false;
        }
        if (dir_path[0] != 0) {
            // 拼接目录路径和相对路径
            snprintf(pathname, PATH_MAX, "%s/%s", dir_path, rel_path);
        }
    }
    struct stat stat1;
	status = stat(pathname, &stat1);
	if (status < 0) {
        perror("stat");
        return false;
    }
    // Need to erase the override from our database
    override_key_t key;
    key.dev=stat1.st_dev;
    key.inode=stat1.st_ino;
    stat_override_t map = {0};
    if( get_map( key.dev, key.inode, &map ) ) {
        map.transient=true;
        set_map( &map );
    }
    return true;
}
/* 
long sys_rmdir(const char __user *pathname);
*/
bool sys_rmdir(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 删除失败
		return false;
	}
    char rel_path[PATH_MAX];
	int status = get_sysarg_path(tracee, rel_path, SYSARG_1);
    if (status < 0) {
        return false;
    }
    struct stat stat1;
	status = stat(rel_path, &stat1);
	if (status < 0) {
        perror("stat");
        return false;
    }
    override_key_t key;
    key.dev=stat1.st_dev;
    key.inode=stat1.st_ino;
    stat_override_t map;
    if(get_map( key.dev, key.inode, &map ) ) {
        map.transient=true;
        set_map( &map );
    }  
}



static uint64_t capabilities_from_cap_data(const struct vfs_cap_data *cap_data) {
    uint64_t capabilities = 0;

    // 检查 vfs_cap_data 的版本
    if ((cap_data->magic_etc & VFS_CAP_REVISION_MASK) == VFS_CAP_REVISION_3) {
        // VFS_CAP_REVISION_3 支持 64 位的能力
        capabilities = (uint64_t)cap_data->data[0].permitted |
                       ((uint64_t)cap_data->data[1].permitted << 32);
    } else if ((cap_data->magic_etc & VFS_CAP_REVISION_MASK) == VFS_CAP_REVISION_2) {
        // VFS_CAP_REVISION_2 支持 32 位的能力
        capabilities = (uint64_t)cap_data->data[0].permitted;
    }

    return capabilities;
}

bool real_setxattr(Tracee *tracee, Config *config, const char* fullpath, int name_offset){
    char name[PATH_MAX] = {0};
    int status = get_sysarg_path(tracee, name, name_offset);
    if (status < 0) {
        return false;
    }
    size_t size = peek_reg(tracee, ORIGINAL, name_offset+2);
    if (0 == strncmp(name,"security.capability",strlen("security.capability"))) {
        if (sizeof(struct vfs_cap_data) != size) {
            fprintf(stderr, "security.capability caps wrong length.\n");
            return false;
        }
        word_t src = peek_reg(tracee, CURRENT, name_offset+1);
        if (src == 0) {
            fprintf(stderr, "security.capability caps wrong value.\n");
            return false;
        }
        struct vfs_cap_data cap_data = {0};
        int rt = read_data(tracee, &cap_data, src, sizeof(struct vfs_cap_data));
        if (rt < 0) {
            fprintf(stderr, "security.capability caps wrong value.\n");
            return false;
        }
        uint64_t capabilities = capabilities_from_cap_data(&cap_data);
        struct stat stat1;
        status = stat(fullpath, &stat1);
        if (status < 0) {
            return false;
        }
        stat_override_t override = {0};
        if( !get_map( stat1.st_dev, stat1.st_ino, &override ) ) {
            stat_override_copy(&stat1, fullpath, &override);
        }
        sprintf(override.caps,"%u", capabilities);
        set_map(&override);
    }
}


/*
int setxattr(const char *path, const char *name,
                     const void *value, size_t size, int flags);
*/
bool sys_setxattr(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {
		return false;
	}
    char path[PATH_MAX] = {0};
	int status = get_sysarg_path(tracee, path, SYSARG_1);
    if (status < 0) {
        return false;
    }
    return real_setxattr(tracee, config, path, SYSARG_2);
}

/*
int lsetxattr(const char *path, const char *name,
                     const void *value, size_t size, int flags);
*/
bool sys_lsetxattr(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {
		return false;
	}
    char path[PATH_MAX] = {0};
	int status = get_sysarg_path(tracee, path, SYSARG_1);
    if (status < 0) {
        return false;
    }
    return real_setxattr(tracee, config, path, SYSARG_2);
}



/*
int fsetxattr(int fd, const char *name,
                     const void *value, size_t size, int flags);
*/
bool sys_fsetxattr(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {
		return false;
	}
    int fd = peek_reg(tracee, ORIGINAL, SYSARG_1);
    struct stat stat1;
    int status = fstat_proc_pid_fd(tracee->pid, fd, &stat1);
      if (status < 0) {
        perror("fstat");
        return false;
    }
    //
    char* filepath = fd_to_path(tracee->pid, fd);
    return real_setxattr(tracee, config, filepath, SYSARG_2);
}
/*
int rename(const char *oldpath, const char *newpath);
*/
bool sys_rename(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {
		return false;
	}
    char newpath[PATH_MAX];
	int status = get_sysarg_path(tracee, newpath, SYSARG_2);
    if (status < 0) {
        return false;
    }
    struct stat stat1;
    status = stat(newpath, &stat1);
    if (status < 0) {
        perror("stat");
        return false;
    }
    override_key_t key;
    key.dev=stat1.st_dev;
    key.inode=stat1.st_ino;
    stat_override_t map;
    if(get_map(key.dev, key.inode, &map )) {// 应该是存在的
        stat_override_t override = {0};
        stat_override_copy(&stat1, newpath, &override);
        set_map( &map );
    }
}
/*
int renameat(int olddirfd, const char *oldpath,
                    int newdirfd, const char *newpath);
int renameat2(int olddirfd, const char *oldpath,
                     int newdirfd, const char *newpath, unsigned int flags);
*/
bool sys_renameat(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 删除失败
		return false;
	}
    int newdirfd = peek_reg(tracee, ORIGINAL, SYSARG_3);
    char newpath[PATH_MAX];
	int status = get_sysarg_path(tracee, newpath, SYSARG_4);
    if (status < 0) {
        return false;
    }
    char pathname[PATH_MAX] = {0};
    if (newdirfd == AT_FDCWD) {
		strncpy(pathname, newpath, strlen(newpath));
	} else {
        // 获取 dirfd 对应的目录路径
        char dir_path[PATH_MAX];
        status = readlink_proc_pid_fd(tracee->pid, newdirfd, dir_path);
        if (status < 0) {
            return false;
        }
        if (dir_path[0] != 0) {
            // 拼接目录路径和相对路径
            snprintf(pathname, PATH_MAX, "%s/%s", dir_path, newpath);
        }
    }
    struct stat stat1;
    status = stat(pathname, &stat1);
    if (status < 0) {
        perror("stat");
        return false;
    }
    override_key_t key;
    key.dev=stat1.st_dev;
    key.inode=stat1.st_ino;
    stat_override_t map;
    if(get_map(key.dev, key.inode, &map )) {// 应该是存在的
        stat_override_t override = {0};
        stat_override_copy(&stat1, pathname, &override);
        set_map( &map );
    }
}

bool lie_database(Tracee *tracee, Config *config, word_t sysnum) {
	switch (sysnum) {
        case PR_creat:
            return sys_creat(tracee, config);
		case PR_open:
			return sys_open(tracee, config);
		case PR_openat:
			return sys_openat(tracee, config);
		case PR_mknod:
			return sys_mknod(tracee, config);
		case PR_mknodat:
			return sys_mknodat(tracee, config);
		case PR_chmod:
			return sys_chmod(tracee, config);
		case PR_fchmod:
			return sys_fchmod(tracee, config);
		case PR_fchmodat:
			return sys_fchmodat(tracee, config);
		case PR_chown:
        case PR_chown32:
			return sys_chown(tracee, config);
		case PR_fchown:
        case PR_fchown32:
			return sys_fchown(tracee, config);
		case PR_lchown:
        case PR_lchown32:
			return sys_lchown(tracee, config);
		case PR_fchownat:
			return sys_fchownat(tracee, config);
		case PR_mkdir:
			return sys_mkdir(tracee, config);
		case PR_mkdirat:
			return sys_mkdirat(tracee, config);
		case PR_symlink:
			return sys_symlink(tracee, config);
		case PR_symlinkat:
			return sys_symlinkat(tracee, config);
		case PR_unlink:
			return sys_unlink(tracee, config);
		case PR_unlinkat:
			return sys_unlinkat(tracee, config);
		case PR_rmdir: 
			return sys_rmdir(tracee, config);
        case PR_setxattr:
            return sys_setxattr(tracee, config);
        case PR_lsetxattr:
            return sys_lsetxattr(tracee, config);
        case PR_fsetxattr:
            return sys_fsetxattr(tracee, config);
        case PR_renameat: // data fakeroot不处理是因为记录的inode数据
            return sys_renameat(tracee, config);
        case PR_rename:
            return sys_rename(tracee, config);
        default:
            break;
	}
    return true;
		// case PR_link: // 不产生lie data
		// case PR_linkat:  // 不产生lie data
}
		// {
		//     // if (tracee->state_file != NULL) {
		// 	// 	char* pathname = resovle_path(tracee, sysnum);
		// 	// 	if (pathname && config) {
		// 	// 		//if (strncmp(pathname, config->root_path, strlen(config->root_path)) == 0 ){
		// 	// 			record_file_stat(pathname, -1, -1, 0777, sysnum);
		// 	// 		//}
		// 	// 	}
		// 	// }
		// 	// return 0;
		// }
	/*
	///////////////////
		if (tracee->status != 0 && tracee->state_file != NULL) {
			char* pathname = resovle_path(tracee, sysnum);
			if (pathname && config) {
				//if (strncmp(pathname, config->root_path, strlen(config->root_path)) == 0 ){
					Reg mode_sysarg;
					mode_t st_mode;
					if (sysnum == PR_chmod || sysnum == PR_fchmod) {
						mode_sysarg = SYSARG_2;
					} else {
						mode_sysarg = SYSARG_3;
					}
					st_mode = peek_reg(tracee, ORIGINAL, mode_sysarg);
					record_file_stat(pathname, -1, -1, st_mode, sysnum);
				//}
			}
		}
	*/

	/*
	if (tracee->status != 0 && tracee->state_file != NULL) {
			char* pathname = resovle_path(tracee, sysnum);
			if (pathname && config) {
				//if (strncmp(pathname, config->root_path, strlen(config->root_path)) == 0 ){
					Reg uid_sysarg;
					Reg gid_sysarg;
					uid_t uid;
					gid_t gid;
					if (sysnum == PR_fchownat) {
						uid_sysarg = SYSARG_3;
						gid_sysarg = SYSARG_4;
					}
					else {
						uid_sysarg = SYSARG_2;
						gid_sysarg = SYSARG_3;
					}
		
					uid = peek_reg(tracee, ORIGINAL, uid_sysarg);
					gid = peek_reg(tracee, ORIGINAL, gid_sysarg);
					record_file_stat(pathname, uid,  gid, -1, sysnum);
				//}
				free(pathname);	
			}
		}
	*/



/*
struct fakestat fs = {.path={},.uid = -1,.gid = -1,.mode = -1};
					strncpy(fs.path, pathname, strlen(pathname));
					fs.mode = st_mode & 0777;
					struct fakestat fs1;
					if (0 == exist) {
						fs.uid = fs1.uid;
						fs.gid = fs1.gid;
					} else {
						struct stat mode;
						stat(pathname, &mode);
						fs.uid = mode.st_uid;
						fs.gid = mode.st_gid;
					}		
					if (0 == insert_or_update_file_state(&fs) ){
						fprintf(stderr, "chmod_enter:%s,pathname=%s, uid=%d, gid=%d, mode=0%o\n", 
						stringify_sysnum(sysnum),pathname,fs.uid,fs.gid,fs.mode);
					} else {
						fprintf(stderr, "!chmod_enter:%s,pathname=%s\n", stringify_sysnum(sysnum),pathname);
					}

*/


// 删除数据
// int delete_file_state(const char *path) {
//     if (!path) {
//         fprintf(stderr, "Invalid input\n");
//         return 1;
//     }

//     const char *sql = "DELETE FROM file_state WHERE path = ?;";
//     sqlite3_stmt *stmt;

//     int rc = sqlite3_prepare_v2(state_db, sql, -1, &stmt, 0);
//     if (rc != SQLITE_OK) {
//         fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(state_db));
//         return 1;
//     }

//     sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);

//     rc = sqlite3_step(stmt);
//     if (rc != SQLITE_DONE) {
//         fprintf(stderr, "SQL step error: %s\n", sqlite3_errmsg(state_db));
//         sqlite3_finalize(stmt);
//         return 1;
//     }

//     sqlite3_finalize(stmt);
//     return 0;
// }

// 查询所有数据
// int query_all_file_states(struct fakestat **fs_list, int *count) {
//     if (!fs_list || !count) {
//         fprintf(stderr, "Invalid input\n");
//         return 1;
//     }

//     *count = 0;
//     *fs_list = NULL;

//     const char *sql = "SELECT path, uid, gid, mode FROM file_state;";
//     sqlite3_stmt *stmt;

//     int rc = sqlite3_prepare_v2(state_db, sql, -1, &stmt, 0);
//     if (rc != SQLITE_OK) {
//         fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(state_db));
//         return 1;
//     }

//     while (sqlite3_step(stmt) == SQLITE_ROW) {
//         struct fakestat *temp = realloc(*fs_list, (*count + 1) * sizeof(struct fakestat));
//         if (!temp) {
//             fprintf(stderr, "Memory allocation failed\n");
//             sqlite3_finalize(stmt);
//             free(*fs_list);
//             *fs_list = NULL;
//             *count = 0;
//             return 1;
//         }

//         *fs_list = temp;
//         const char* path = (const char *)sqlite3_column_text(stmt, 0);
//         strncpy((*fs_list)[*count].path, path, strlen(path));
//         (*fs_list)[*count].uid = sqlite3_column_int(stmt, 1);
//         (*fs_list)[*count].gid = sqlite3_column_int(stmt, 2);
//         (*fs_list)[*count].mode = sqlite3_column_int(stmt, 3);
//         (*count)++;
//     }

//     sqlite3_finalize(stmt);
//     return 0;
// }

// int close_database() {
//     if (state_db) {
//         sqlite3_close(state_db);
//         state_db = NULL;
//     }
// }


 // // 准备查询语句
    // sqlite3_stmt *stmt;
    // const char *sql = "SELECT dev, ino, mode, uid, gid, nlink, rdev FROM file_state;";

    // rc = sqlite3_prepare_v2(state_db, sql, -1, &stmt, 0);
    // if (rc != SQLITE_OK) {
    //     fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(state_db));
    //     sqlite3_close(state_db);
    //     return 1;
    // }

    // // 执行查询并读取结果
    // while (sqlite3_step(stmt) == SQLITE_ROW) {
    //     struct fakestat st;

    //     st.dev = sqlite3_column_int64(stmt, 0);
    //     st.ino = sqlite3_column_int64(stmt, 1);
    //     st.mode = sqlite3_column_int(stmt, 2);
    //     st.uid = sqlite3_column_int(stmt, 3);
    //     st.gid = sqlite3_column_int(stmt, 4);
    //     st.nlink = sqlite3_column_int(stmt, 5);
    //     st.rdev = sqlite3_column_int64(stmt, 6);

    //     // 将读取的文件状态插入到数据结构中
    //     data_insert(&st, remote);
    // }

    // // 释放资源
    // sqlite3_finalize(stmt);
    // sqlite3_close(state_db);


    // int save_database(const uint32_t remote) {
//     int rc;
//     // 准备插入语句
//     const char *sql = "INSERT OR REPLACE INTO file_state (dev, ino, mode, uid, gid, nlink, rdev) VALUES (?, ?, ?, ?, ?, ?, ?);";
//     sqlite3_stmt *stmt;

//     rc = sqlite3_prepare_v2(state_db, sql, -1, &stmt, 0);
//     if (rc != SQLITE_OK) {
//         fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(state_db));
//         sqlite3_close(state_db);
//         return 1;
//     }

//     // 遍历数据并插入到数据库
//     data_node_t *i;
//     for (i = data_begin(); i != data_end(); i = data_node_next(i)) {
//         if (i->remote != remote)
//             continue;

//         sqlite3_reset(stmt);
//         sqlite3_bind_int64(stmt, 1, i->buf.dev);
//         sqlite3_bind_int64(stmt, 2, i->buf.ino);
//         sqlite3_bind_int(stmt, 3, i->buf.mode);
//         sqlite3_bind_int(stmt, 4, i->buf.uid);
//         sqlite3_bind_int(stmt, 5, i->buf.gid);
//         sqlite3_bind_int(stmt, 6, i->buf.nlink);
//         sqlite3_bind_int64(stmt, 7, i->buf.rdev);

//         rc = sqlite3_step(stmt);
//         if (rc != SQLITE_DONE) {
//             fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
//             sqlite3_finalize(stmt);
//             sqlite3_close(db);
//             return 1;
//         }
//     }

//     // 释放资源
//     sqlite3_finalize(stmt);
//     return 0;
// }