#include <stdio.h>
#include <stdint.h>
#include <sqlite3.h>
#include "fake_id0.h"
#include <sys/stat.h>
#include <errno.h>
#include <sys/xattr.h>
#include <linux/capability.h>
#include "tracee/tracee.h"
#include "extension/extension.h"

extern int errno;
static sqlite3 *state_db = NULL;
static char s_fsconfig_outpath[PATH_MAX] = {0};
static char s_fsconfig_rootdir[PATH_MAX] = {0};

bool set_fsconfig_out(const char* fsconfig_outpath) {
    if (strlen(fsconfig_outpath) == 0) {
        return true;
    }
    if (NULL == strstr(fsconfig_outpath,",")) {
        strncpy(s_fsconfig_outpath, fsconfig_outpath, strlen(fsconfig_outpath));
    } else {
        char *temp = strtok(fsconfig_outpath, ",");
        strncpy(s_fsconfig_outpath, temp, strlen(temp));
        temp = strtok(NULL, ",");
        strncpy(s_fsconfig_rootdir, temp, strlen(temp));
    }
}

//==============================
// 全局哈希表
static file_hash_entry_t *map_hash = NULL;

bool load_map(const char* state_file)
{
    int rc;
    if (state_db != NULL) {
        fprintf(stderr, "database already opened: %s\n", state_file);
        return false;
    }
    // 打开 SQLite 数据库
    int retry_count = 60; // 尝试打开数据库的次数
    int retry_interval = 1000; // 两次尝试之间的间隔（毫秒）
    for (int i = 0; i < retry_count; i++) {
        rc = sqlite3_open_v2(state_file, &state_db,  SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
        if (rc == SQLITE_OK) {
            printf("成功打开数据库\n");
            break;
        } else if (rc == SQLITE_BUSY) {
            printf("数据库正忙，尝试次数：%d\n", i + 1);
            usleep(retry_interval * 1000); // 毫秒转微秒
        } else {
            fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(state_db));
            return false;
        }
    }
     // 启用 WAL 模式
    char *errMsg = 0;
    // rc = sqlite3_exec(state_db, "PRAGMA journal_mode=WAL;", 0, 0, &errMsg);
    // if (rc != SQLITE_OK) {
    //     fprintf(stderr, "SQL error: %s\n", errMsg);
    //     sqlite3_free(errMsg);
    //     return 1;
    // }
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
                      "caps TEXT NOT NULL);"; // UNIQUE (dev, ino) ON CONFLICT REPLACE)

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

#define CAP_MASK_LONG(cap_name) (1ULL << (cap_name))
bool save_fsconfig() {
    if (strlen(s_fsconfig_outpath) == 0) {
        return true;
    }
    char sql[PATH_MAX] = {0};
    if (strlen(s_fsconfig_rootdir) == 0) {
        snprintf(sql, sizeof(sql),"SELECT path, dev, ino, mode, uid, gid, rdev, nlink, caps FROM fakedb ORDER BY path;");
    } else {
        snprintf(sql, sizeof(sql),"SELECT path, dev, ino, mode, uid, gid, rdev, nlink, caps FROM fakedb WHERE path like '%s%%' \
ORDER BY path;", s_fsconfig_rootdir);
    }
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(state_db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(state_db));
        return false;
    }
    FILE* fp = fopen(s_fsconfig_outpath, "w");
     if (fp == NULL) {
        fprintf(stderr, "open fsconfig output %s error\n", s_fsconfig_outpath);
        return false;
    }
    char *tmp = NULL;
    size_t s_fsconfig_rootdir_len = strlen(s_fsconfig_rootdir);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        stat_override_t override={0};
        const char* pp = sqlite3_column_text(stmt, 0);
        if (pp!=NULL) {
            strncpy(override.path, pp, strlen(pp));
        }
        override.dev = sqlite3_column_int(stmt, 1);
        override.inode = sqlite3_column_int(stmt, 2);
        override.mode = sqlite3_column_int(stmt, 3);
        if(!S_ISREG(override.mode) && !S_ISDIR(override.mode) && !S_ISLNK(override.mode)){
            continue;
        }
        override.uid = sqlite3_column_int(stmt, 4);
        override.gid = sqlite3_column_int(stmt, 5);
        override.dev_id = sqlite3_column_int(stmt, 6);
        if (override.dev_id != 0) {// 特殊文件
            continue;
        }
        override.nlink = sqlite3_column_int(stmt, 7);
        pp = sqlite3_column_text(stmt, 8);
        if (pp!=NULL) {
            strncpy(override.caps, pp, strlen(pp));
        }
        if (s_fsconfig_rootdir_len > 0)
            tmp = strstr(override.path, s_fsconfig_rootdir);
            if (tmp) {
                tmp = override.path + s_fsconfig_rootdir_len;
            }
        else
            tmp = override.path;

        uint64_t capabilities = 0;
        if (override.mode&S_ISUID) {
            capabilities |= CAP_MASK_LONG(CAP_SETUID);
        }
        if(override.mode&S_ISGID) {
            capabilities |= CAP_MASK_LONG(CAP_SETGID);
        }

        if (tmp)
            fprintf(fp,"%s %d %d %o capabilities=0x%x\n", tmp, override.uid, override.gid, override.mode&0777, 0);
    }
    fclose(fp);
    sqlite3_finalize(stmt);
    return true;
}

bool save_map()
{
    if (state_db == NULL) {
        return true;
    }
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
        if (strstr(override->path, "usr/bin/systemd-cat")) {
            int nn =0;
            nn++;
            fprintf(stderr, "save_map %s\n", override->path);
        }
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
    //
    bool rt = save_fsconfig();
    if (!rt) {
        fprintf(stderr, "save fsconfig error\n");
        return false;
    }
    //
    sqlite3_close(state_db);
    state_db = NULL;
    return true;
}

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

bool get_map_with_path(const char* path, stat_override_t* stat) {
    file_hash_entry_t *current_entry = NULL, *tmp = NULL;
    HASH_ITER(hh, map_hash, current_entry, tmp) {
        const stat_override_t *override = &current_entry->value;
        if (0==strcmp(override->path,path)) {
            memcpy(stat, override, sizeof(stat_override_t));
            return true;
        }
    }
    return false;
}

// 设置函数
void set_map(const stat_override_t *stat1) {
    // if (strstr(stat1->path,"usr/bin/systemd-cat")) {
    //     fprintf(stderr, "set_map %s\n", stat1->path);
    // }
    file_hash_entry_t tmp, *entry, *entry1;
    tmp.key.dev = stat1->dev;
    tmp.key.inode = stat1->inode;
    HASH_FIND(hh, map_hash, &tmp.key, sizeof(override_key_t), entry);
    if (entry != NULL) {
        // 如果键已存在，更新值
        if (strstr(entry->value.path,"usr/bin/systemd-cat")) {
            fprintf(stderr, "%s->%s\n", entry->value.path, stat1->path);
            if (strstr(stat1->path,"systemd-cgls")) {
                int nn =0;
                nn++;
            }
        }
        memcpy(&entry->value, stat1, sizeof(stat_override_t));
        // if (strstr(stat1->path,"usr/bin/systemd-cat")) {
        //     HASH_FIND(hh, map_hash, &tmp.key, sizeof(override_key_t), entry1);
        //     fprintf(stderr, "after: %s\n", entry1->value.path);
        // }
    } else {
        // 如果键不存在，创建新条目
        entry = (file_hash_entry_t *)malloc(sizeof(file_hash_entry_t));
        if (!entry) {
            perror("malloc failed");
            return;
        }
        memset(entry, 0, sizeof(file_hash_entry_t));
        entry->key.dev = stat1->dev;
        entry->key.inode = stat1->inode;
        memcpy(&entry->value, stat1, sizeof(stat_override_t));
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

bool getcwd_pid(pid_t pid, char dir_path[PATH_MAX]) {
    char cwd_path[PATH_MAX] = {0};
    snprintf(cwd_path, sizeof(cwd_path), "/proc/%d/cwd",  pid);
    char symlink_path[PATH_MAX] = {0};
    char *real_path = NULL;

  // 读取符号链接的目标路径
    if (readlink(cwd_path, symlink_path, sizeof(symlink_path) - 1) != -1) {
        symlink_path[sizeof(symlink_path) - 1] = '\0';
        real_path = realpath(symlink_path, NULL);
        strncpy(dir_path, real_path, strlen(real_path));
        return true;
    }
    return false;
}

bool get_fullpath(pid_t pid, char result[PATH_MAX], int dirfd, const char *user_path) {
    if (user_path[0] == '/') {
		strncpy(result, user_path, strlen(user_path));
	} else {
        char dir_path[PATH_MAX] = {0};
        int status = 0;
        if (dirfd == AT_FDCWD) {
            status = getcwd_pid(pid, dir_path);
        } else {
            status = readlink_proc_pid_fd(pid, dirfd, dir_path);
        }
        if (status < 0) {
            fprintf(stderr, "get_fullpath failed.\n");
            return false;
        }
        if (dir_path[0] != 0) {
            snprintf(result, PATH_MAX, "%s/%s", dir_path, user_path);
        } else {
            snprintf(result, PATH_MAX, "%s", user_path);
        }
    }
    return true;
}

int fstatat_proc_pid_fd(pid_t pid, int dfd, const char* filename, struct stat* st, int flag) {
    // if (strlen(filename) == 0 ) {
    //     fprintf(stderr, "fstatat_proc_pid_fd filename is empty.\n");
    //     return -1;
    // }
    //
    char dir_path[PATH_MAX] = {0};
    int status = 0;
    if (dfd == AT_FDCWD) {
        status = getcwd_pid(pid, dir_path);
    } else {
        status = readlink_proc_pid_fd(pid, dfd, dir_path);
    }
    if (status < 0 || strlen(dir_path) == 0) {
        fprintf(stderr, "get_fullpath dfd: %d, filename: %s failed.\n", dfd, filename);
        return -1;
    }
    int pfd = open(dir_path, O_RDONLY);
    if (pfd == -1) {
        fprintf(stderr, "get_fullpath open dir %s failed.\n", dir_path);
        return -1;
    }
    int ret = fstatat(pfd, filename, &st, flag);
    // char fullname[PATH_MAX] = {0};
    // bool rt = get_fullpath(pid, fullname, dfd, filename);
    // if (!rt) {
    //     fprintf(stderr, "get_fullpath failed.\n");
    //     return false;
    // }
    if (ret < 0) {        
        fprintf(stderr, "fstatat pfd: %d, filename: %s error: %s.\n", pfd, filename, strerror(errno));
        close(pfd);
        return ret;
    }
    close(pfd);
    // if (NULL != strstr(filename, "etc/alternatives/which")) {
    //     int nn = 0;
    //     nn++;
    // }
    return ret;
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
    return true;
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
        fprintf(stderr, "get_sysarg_path failed.\n");
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
    char path[PATH_MAX] = {0};
    int status = get_sysarg_path(tracee, path, SYSARG_2);
     if (status < 0) {
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    char pathname[PATH_MAX] = {0};
    bool flag = get_fullpath(tracee->pid, pathname, dirfd, path);
    if (!flag) {
        fprintf(stderr, "get_fullpath failed.\n");
        return false;
    }
    //fprintf(stderr, "openat(%s)\n", pathname);
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
        fprintf(stderr, "get_sysarg_path failed.\n");
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
    return true;
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
    return true;
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
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    struct stat stat1;
    status = stat(filename, &stat1);
    if (status < 0) {
        fprintf(stderr, "sys_mknod, stat %s err: %s.\n", filename, strerror(errno));
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
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    struct stat stat1;
    status = fstatat_proc_pid_fd(tracee->pid, dfd, filename, &stat1, 0);
    if (status < 0) {
        fprintf(stderr, "sys_mknodat err\n");
        return false;
    }
    //
    char pathname[PATH_MAX] = {0};
    bool flag = get_fullpath(tracee->pid, pathname, dfd, filename);
    if (!flag) {
        fprintf(stderr, "get_fullpath failed.\n");
        return false;
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
    return true;
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
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    struct stat stat1;
    status = stat(filename, &stat1);
    if (status < 0) {
        fprintf(stderr, "sys_chmod, stat %s err: %s.\n", filename, strerror(errno));
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
        fprintf(stderr, "sys_fchmod, fstat_proc_pid_fd error.");
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
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    struct stat stat1;
    status = fstatat_proc_pid_fd(tracee->pid, dfd, filename, &stat1, 0);
    if (status < 0) {
        fprintf(stderr, "sys_fchmodat err\n");
        return false;
    }
    //
    char pathname[PATH_MAX] = {0};
    bool flag = get_fullpath(tracee->pid, pathname, dfd, filename);
    if (!flag) {
        fprintf(stderr, "get_fullpath failed.\n");
        return false;
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
    return true;
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
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    struct stat stat1;
    status = stat(filename, &stat1);
    if (status < 0) {
        fprintf(stderr, "sys_chown, stat %s err: %s.\n", filename, strerror(errno));
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
        fprintf(stderr, "sys_fchown, fstat_proc_pid_fd error.");
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
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    struct stat stat1;
    status = lstat(filename, &stat1);
    if (status < 0) {
        fprintf(stderr, "sys_lchown, lstat %s err: %s.", filename, strerror(errno));
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
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    int flag = peek_reg(tracee, ORIGINAL, SYSARG_5);
    struct stat stat1;
    status = fstatat_proc_pid_fd(tracee->pid, dfd, filename, &stat1, flag);
    if (status < 0) {
        fprintf(stderr, "sys_fchownat err\n");
        return false;
    }
    //
    char pathname[PATH_MAX] = {0};
    bool rt = get_fullpath(tracee->pid, pathname, dfd, filename);
    if (!rt) {
        fprintf(stderr, "get_fullpath failed.\n");
        return false;
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
    return true;
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
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    struct stat stat1;
    status = stat(newname, &stat1);
    if (status < 0) {
        fprintf(stderr, "sys_mkdir, stat %s err: %s.\n", newname, strerror(errno));
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
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    struct stat stat1;
    status = fstatat_proc_pid_fd(tracee->pid, dirfd, filename, &stat1, 0);
    if (status < 0) {
        fprintf(stderr, "sys_mkdirat err\n");
        return false;
    }
    //
    char pathname[PATH_MAX] = {0};
    bool flag = get_fullpath(tracee->pid, pathname, dirfd, filename);
    if (!flag) {
        fprintf(stderr, "get_fullpath failed.\n");
        return false;
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
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    struct stat stat1;
    status = lstat(newname, &stat1);
    if (status < 0) {
        fprintf(stderr, "sys_symlink, lstat %s err: %s.", newname, strerror(errno));
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
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    struct stat stat1;
    status = fstatat_proc_pid_fd(tracee->pid, newdfd, newname, &stat1, AT_SYMLINK_NOFOLLOW );
    if (status < 0) {
        fprintf(stderr, "sys_symlinkat err\n");
        return false;
    }
    //
    char pathname[PATH_MAX] = {0};
    bool flag = get_fullpath(tracee->pid, pathname, newdfd, newname);
    if (!flag) {
        fprintf(stderr, "get_fullpath failed.\n");
        return false;
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
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    // struct stat stat1;
	// status = stat(rel_path, &stat1);
	// if (status < 0) {
    //     fprintf(stderr, "sys_unlink, stat %s err: %s.\n", rel_path, strerror(errno));
    //     return false;
    // }
    // Need to erase the override from our database
    // override_key_t key;
    // key.dev=stat1.st_dev;
    // key.inode=stat1.st_ino;
    stat_override_t map = {0};
    if( get_map_with_path( rel_path, &map ) ) {
        map.transient=true;
        set_map( &map );
    }
    return true;
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
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    //
    char pathname[PATH_MAX] = {0};
    bool flag = get_fullpath(tracee->pid, pathname, dirfd, rel_path);
    if (!flag) {
        fprintf(stderr, "get_fullpath failed.\n");
        return false;
    }
    // struct stat stat1;
    // status = fstatat_proc_pid_fd(tracee->pid, dirfd, rel_path, &stat1, 0);
	// // status = stat(pathname, &stat1);
	// if (status < 0) {
    //     fprintf(stderr, "sys_unlinkat, stat %s err: %s.\n", rel_path, strerror(errno));
    //     return false;
    // }
    // // Need to erase the override from our database
    // override_key_t key;
    // key.dev=stat1.st_dev;
    // key.inode=stat1.st_ino;
    stat_override_t map = {0};
    if( get_map_with_path(pathname, &map ) ) {
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
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    // struct stat stat1;
	// status = stat(rel_path, &stat1);
	// if (status < 0) {
    //     fprintf(stderr, "sys_rmdir, stat %s err: %s.\n", rel_path, strerror(errno));
    //     return false;
    // }
    // override_key_t key;
    // key.dev=stat1.st_dev;
    // key.inode=stat1.st_ino;
    stat_override_t map;
    if(get_map_with_path( rel_path, &map ) ) {
        map.transient=true;
        set_map( &map );
    } 
    return true;
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
        fprintf(stderr, "get_sysarg_path failed.\n");
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
        sprintf(override.caps, "%lu", capabilities);
        set_map(&override);
    }
    return true;
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
        fprintf(stderr, "get_sysarg_path failed.\n");
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
        fprintf(stderr, "get_sysarg_path failed.\n");
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
        fprintf(stderr, "sys_fsetxattr, fstat_proc_pid_fd error.\n");
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
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    struct stat stat1;
    status = stat(newpath, &stat1);
    if (status < 0) {
        fprintf(stderr, "sys_rename, stat %s err: %s.\n", newpath, strerror(errno));
        return false;
    }
    override_key_t key;
    key.dev=stat1.st_dev;
    key.inode=stat1.st_ino;
    //stat_override_t map;
    //if(!get_map(key.dev, key.inode, &map )) {// 应该是存在的
    stat_override_t override = {0};
    stat_override_copy(&stat1, newpath, &override);
    set_map( &override );
    //}
    return true;
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
    char newpath[PATH_MAX] = {0};
	int status = get_sysarg_path(tracee, newpath, SYSARG_4);
    if (status < 0) {
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    //uint32_t flags = peek_reg(tracee, ORIGINAL, SYSARG_5);
    //
    struct stat stat1;
	status = fstatat_proc_pid_fd(tracee->pid, newdirfd, newpath, &stat1, 0);
	if (status < 0) {
        fprintf(stderr, "sys_renameat, fstatat_proc_pid_fd %s err.\n", newpath);
		return 0;
    }
    //
    char pathname[PATH_MAX] = {0};
    bool flag = get_fullpath(tracee->pid, pathname, newdirfd, newpath);
    // if (!flag) {
    //     fprintf(stderr, "get_fullpath failed.\n");
    //     return false;
    // }
    // struct stat stat1;
    // status = stat(pathname, &stat1);
    // if (status < 0) {
    //     perror("stat");
    //     fprintf(stderr, "sys_renameat, stat %s error.\n", pathname);
    //     return false;
    // }
    override_key_t key;
    key.dev=stat1.st_dev;
    key.inode=stat1.st_ino;
    //stat_override_t map;
    //if(get_map(key.dev, key.inode, &map )) {// 应该是存在的
    stat_override_t override = {0};
    stat_override_copy(&stat1, pathname, &override);
    //}
    set_map( &override );
    return true;
}

/*
int link(const char *oldpath, const char *newpath);
*/
bool sys_link(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {
		return false;
	}
    char newpath[PATH_MAX];
	int status = get_sysarg_path(tracee, newpath, SYSARG_2);
    if (status < 0) {
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    struct stat stat1;
    status = stat(newpath, &stat1);
    if (status < 0) {
        fprintf(stderr, "sys_link, stat %s err: %s.\n", newpath, strerror(errno));
        return false;
    }
    override_key_t key;
    key.dev=stat1.st_dev;
    key.inode=stat1.st_ino;
    //stat_override_t map;
    //if(get_map(key.dev, key.inode, &map )) {// 应该是存在的
    stat_override_t override = {0};
    stat_override_copy(&stat1, newpath, &override);
    set_map( &override );
    //}
    return true;
}
/*
int linkat(int olddirfd, const char *oldpath,
                  int newdirfd, const char *newpath, int flags);
*/
bool sys_linkat(Tracee *tracee, Config *config) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {// 删除失败
		return false;
	}
    int newdirfd = peek_reg(tracee, ORIGINAL, SYSARG_3);
    char newpath[PATH_MAX] = {0};
	int status = get_sysarg_path(tracee, newpath, SYSARG_4);
    if (status < 0) {
        fprintf(stderr, "get_sysarg_path failed.\n");
        return false;
    }
    //
    char pathname[PATH_MAX] = {0};
    bool flag = get_fullpath(tracee->pid, pathname, newdirfd, newpath);
    if (!flag) {
        fprintf(stderr, "get_fullpath failed.\n");
        return false;
    }
    struct stat stat1;
    status = stat(pathname, &stat1);
    if (status < 0) {
        fprintf(stderr, "sys_linkat, stat %s err: %s.\n", pathname, strerror(errno));
        return false;
    }
    override_key_t key;
    key.dev=stat1.st_dev;
    key.inode=stat1.st_ino;
    stat_override_t map;
    //if(get_map(key.dev, key.inode, &map )) {// 应该是存在的
    stat_override_t override = {0};
    stat_override_copy(&stat1, pathname, &override);
    set_map( &override );
    //}
    return true;
}

bool lie_database(Tracee *tracee, Config *config, word_t sysnum) {
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int) result < 0) {
		return true;
	}
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
        case PR_link:
            return sys_link(tracee, config);
        case PR_linkat:
            return sys_linkat(tracee, config);
        default:
            break;
	}
    return true;
}




