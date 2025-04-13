#include<stdio.h>
#include <stdint.h>
#include <sqlite3.h>
#include "extension/extension.h"

static sqlite3 *state_db = NULL;

int load_database(char* state_file, const uint32_t remote) {
    int rc;
    if (state_db != NULL) {
        fprintf(stderr, "database already opened: %s\n", state_file);
        return 1;
    }
    // 打开 SQLite 数据库
    rc = sqlite3_open(state_file, &state_db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(state_db));
        return 1;
    }
    // 检查表是否存在，如果不存在则创建
    const char *sql = "CREATE TABLE IF NOT EXISTS file_state ("
                      "path TEXT  PRIMARY KEY, "
                      "uid INTEGER, "
                      "gid INTEGER, "
                      "mode INTEGER);";

    char *errMsg = 0;
    rc = sqlite3_exec(state_db, sql, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
        sqlite3_close(state_db);
        state_db = NULL;
        return 1;
    }
    return 0;
}

// 插入或更新数据
int insert_or_update_file_state(const struct fakestat *fs) {
    if (!fs || !fs->path) {
        fprintf(stderr, "Invalid input\n");
        return 1;
    }

    const char *sql = "INSERT OR REPLACE INTO file_state (path, uid, gid, mode) VALUES (?, ?, ?, ?);";
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(state_db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(state_db));
        return 1;
    }

    sqlite3_bind_text(stmt, 1, fs->path, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, fs->uid);
    sqlite3_bind_int(stmt, 3, fs->gid);
    sqlite3_bind_int(stmt, 4, fs->mode);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL step error: %s\n", sqlite3_errmsg(state_db));
        sqlite3_finalize(stmt);
        return 1;
    }

    sqlite3_finalize(stmt);
    return 0;
}


// 删除数据
int delete_file_state(const char *path) {
    if (!path) {
        fprintf(stderr, "Invalid input\n");
        return 1;
    }

    const char *sql = "DELETE FROM file_state WHERE path = ?;";
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(state_db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(state_db));
        return 1;
    }

    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL step error: %s\n", sqlite3_errmsg(state_db));
        sqlite3_finalize(stmt);
        return 1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

// 查询数据
int query_file_state(const char *path, struct fakestat *fs) {
    if (!path || !fs) {
        fprintf(stderr, "Invalid input\n");
        return 1;
    }

    const char *sql = "SELECT path, uid, gid, mode FROM file_state WHERE path = ?;";
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(state_db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(state_db));
        return 1;
    }

    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* path = (const char *)sqlite3_column_text(stmt, 0);
        strncpy(fs->path, path, strlen(path));
        fs->uid = sqlite3_column_int(stmt, 1);
        fs->gid = sqlite3_column_int(stmt, 2);
        fs->mode = sqlite3_column_int(stmt, 3);
        rc = 0;
    } else {
        rc = 1;
    }

    sqlite3_finalize(stmt);
    return rc;
}

// 查询所有数据
int query_all_file_states(struct fakestat **fs_list, int *count) {
    if (!fs_list || !count) {
        fprintf(stderr, "Invalid input\n");
        return 1;
    }

    *count = 0;
    *fs_list = NULL;

    const char *sql = "SELECT path, uid, gid, mode FROM file_state;";
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(state_db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error: %s\n", sqlite3_errmsg(state_db));
        return 1;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        struct fakestat *temp = realloc(*fs_list, (*count + 1) * sizeof(struct fakestat));
        if (!temp) {
            fprintf(stderr, "Memory allocation failed\n");
            sqlite3_finalize(stmt);
            free(*fs_list);
            *fs_list = NULL;
            *count = 0;
            return 1;
        }

        *fs_list = temp;
        const char* path = (const char *)sqlite3_column_text(stmt, 0);
        strncpy((*fs_list)[*count].path, path, strlen(path));
        (*fs_list)[*count].uid = sqlite3_column_int(stmt, 1);
        (*fs_list)[*count].gid = sqlite3_column_int(stmt, 2);
        (*fs_list)[*count].mode = sqlite3_column_int(stmt, 3);
        (*count)++;
    }

    sqlite3_finalize(stmt);
    return 0;
}

int close_database() {
    if (state_db) {
        sqlite3_close(state_db);
        state_db = NULL;
    }
}


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