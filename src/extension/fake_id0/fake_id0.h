#include <sys/types.h>
#include <stdbool.h>
#include <linux/limits.h>
#include "uthash.h" 

typedef struct {
	uid_t ruid;
	uid_t euid;
	uid_t suid;
	uid_t fsuid;

	gid_t rgid;
	gid_t egid;
	gid_t sgid;
	gid_t fsgid;

	char root_path[PATH_MAX];
} Config;


// 定义 stat_override 结构体
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

// 定义 override_key 结构体
typedef struct  {
    dev_t dev;
    unsigned long inode; // 同样假设 ptlib_inode_t 是 unsigned long
} override_key_t;

// 定义哈希表的键值对结构体
typedef struct  {
    override_key_t key;
    stat_override_t value;
    UT_hash_handle hh; // uthash 需要的哈希表句柄
} file_hash_entry_t;

