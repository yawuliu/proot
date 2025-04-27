#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/capability.h>
#include <sqlite3.h>

#define CAP_MASK_LONG(cap_name) (1ULL << (cap_name))
typedef struct {
    char path[PATH_MAX];
    dev_t dev;
    unsigned long inode; // 注意：C 中没有 ptlib_inode_t，这里假设它是 unsigned long
    mode_t mode;
    uid_t uid;
    gid_t gid;
    dev_t dev_id;
    nlink_t nlink;
    char caps[PATH_MAX];
    int transient; // C 中没有 bool，用 int 表示
} stat_override_t;

int main(int argc, char *argv[]) {
    char state_file[PATH_MAX] = {0};
    char fsconfig_output[PATH_MAX]= {0};
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--state_file=", strlen("--state_file=")) == 0) {
            // 提取 state_file 的值
            strncpy(state_file, argv[i] + strlen("--state_file="), sizeof(state_file) - 1);
            state_file[sizeof(state_file) - 1] = '\0';
        } else if (strncmp(argv[i], "--fsconfig_output=", strlen("--fsconfig_output=")) == 0) {
            // 提取 fsconfig_output 的值
            strncpy(fsconfig_output, argv[i] + strlen("--fsconfig_output="), sizeof(fsconfig_output) - 1);
            fsconfig_output[sizeof(fsconfig_output) - 1] = '\0';
        }
    }
    // 打印提取的值，方便调试
    printf("state_file: %s\n", state_file);
    printf("fsconfig_output: %s\n", fsconfig_output);
    char s_fsconfig_outpath[PATH_MAX] = {0};
    char s_fsconfig_rootdir[PATH_MAX] = {0};
     if (NULL == strstr(fsconfig_output,",")) {
        strncpy(s_fsconfig_outpath, fsconfig_output, strlen(fsconfig_output));
    } else {
        char *temp = strtok(fsconfig_output, ",");
        strncpy(s_fsconfig_outpath, temp, strlen(temp));
        temp = strtok(NULL, ",");
        strncpy(s_fsconfig_rootdir, temp, strlen(temp));
    }
    if (strlen(s_fsconfig_outpath) == 0) {
        fprintf(stderr, "invalid fsconfig_output\n");
        return 1;
    }
    sqlite3 *state_db = NULL;
    int rc;
    // 打开 SQLite 数据库
    rc = sqlite3_open(state_file, &state_db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(state_db));
        return 1;
    }
    //
    char sql[PATH_MAX] = {0};
    if (strlen(s_fsconfig_rootdir) == 0) {
        snprintf(sql, sizeof(sql), "SELECT path, dev, ino, mode, uid, gid, rdev, nlink, caps FROM fakedb ORDER BY path;");
    } else {
        snprintf(sql, sizeof(sql), "SELECT path, dev, ino, mode, uid, gid, rdev, nlink, caps FROM fakedb WHERE path like '%s%%' \
ORDER BY path;", s_fsconfig_rootdir);
    }
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(state_db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(state_db));
        sqlite3_close(state_db);
        state_db = NULL;
        return 1;
    }
    FILE* fp = fopen(s_fsconfig_outpath, "w");
     if (fp == NULL) {
        fprintf(stderr, "open fsconfig output %s error\n", s_fsconfig_outpath);
        sqlite3_close(state_db);
        state_db = NULL;
        return 1;
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
        // if(!S_ISREG(override.mode) && !S_ISDIR(override.mode) && !S_ISLNK(override.mode)){
        //     continue;
        // }
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
            fprintf(fp,"%s %d %d %o capabilities=0x%lx\n", tmp, override.uid, override.gid, override.mode&0777, capabilities);
    }
    fclose(fp);
    sqlite3_finalize(stmt);
    sqlite3_close(state_db);
    state_db = NULL;
    return 0;
}