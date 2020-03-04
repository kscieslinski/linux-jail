#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <string.h>
#include <linux/limits.h>
#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <grp.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <ctype.h>
#include <fcntl.h>
#include <seccomp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stddef.h>
#include <time.h>
#include <sys/mman.h>
#include <json-c/json.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <openssl/sha.h>
#include <errno.h>

/******************************************************************************
 **** Notes 
 ******************************************************************************
 *   Compile with:
 *   gcc sandbox.c -o sandbox -lseccomp -lcap -ljson-c -lcrypto
 * 
******************************************************************************/

#define STACK_SIZE (0x1000 * 0x10)

/* Used for mapping uids and guids in new user namespace. It is immportant that
host doesn't have any user with such uid. */
#define USER_NS_OFST 10000

/* Container name is in form: sandbox-<unique string>, where unique string length is 
defined by CONTAINER_NAME_SUFIX_LEN. */
#define CONTAINER_NAME_SUFIX_LEN 8
#define CONTAINER_NAME_PREFIX "sandbox-"

#define UNBLOCK_MSG "unblock parent msg"

typedef struct sandbox
{
    /* Unique container identifier. */
    char *container_name;

    /* Root of sandboxed process system file. */
    char *mnt_root;

    /* uid of user within container. */
    int run_as_user;

    /* Command line arguments for sandboxed binary. */
    char **argv;

    /* Script which copies necesary libraries/binaries .*/
    char *pre_script;

    /* Seccomp. */
    char **whitelisted_syscalls;
    size_t nwhitelisted_syscalls;

    /* Capabilities. */
    char **whitelisted_capabilities;
    size_t nwhitelisted_capabilities;

    /* Control Groups. */
    int cap_last_cap;
    int cgroup_memory_limit_in_bytes;
    int cgroup_cpu_shares;
    int cgroup_pids_max;

    /* Parent – child communication. */
    int fd_pc[2];
    int fd_cp[2];
} sandbox;

/* Functions signatures.*/
char *generate_container_name();
int parse_profile(sandbox *ctx, char *profile_path);
int map_sandboxed_process_ids(pid_t pid, sandbox *ctx);
int prep_unique_tmp_dir(sandbox *ctx);
int create_cgroup(sandbox *ctx, pid_t sandboxed_process_pid);
int set_sandbox(sandbox *ctx);
int write_file(char *path, char *content, int mode);
int mkdir_if_not_exists(char *path, mode_t mode);
int read_cap_last_cap();
int unblock(int fd);
int wait_for_unblock(int fd);
int enter_sandbox(void *arg);
int sandboxed_process_change_id(sandbox *ctx);
int sandboxed_process_drop_capabilities(sandbox *ctx);
int sandboxed_process_change_sysfs_root(sandbox *ctx);
int sandboxed_process_change_hostname(sandbox *ctx);
int sandboxed_process_set_seccomp(sandbox *ctx);
int sandboxed_process_run_pre_script(sandbox *ctx);

/******************************************************************************
 **** Sandboxed process 
 ******************************************************************************
 * Before calling execve on a sandboxed binary, sandboxed process has to:
 * i) change its filesystem root,
 * ii) update the hostname,
 * iii) set resuid/resguid,
 * iv) drop capabilities,
 * v) set seccomp rules.
 *****************************************************************************/
int enter_sandbox(void *arg)
{
    sandbox *ctx;
    ctx = (sandbox *)arg;

    /* Child won't read from fd_cp and won't write to fd_pc – therefore just close them. */
    close(ctx->fd_cp[0]);
    close(ctx->fd_pc[1]);

    if (sandboxed_process_run_pre_script(ctx) < 0)
        return -1;

    if (sandboxed_process_change_sysfs_root(ctx) < 0)
        return -1;

    if (sandboxed_process_change_hostname(ctx) < 0)
        return -1;

    if (sandboxed_process_change_id(ctx) < 0)
        return -1;

    if (unshare(CLONE_NEWNET))
    {
        perror("[!] unshare failed");
        return -1;
    }

    /* We don't need to communicate with parent anymore. Close rest of descriptors. */
    close(ctx->fd_cp[1]);
    close(ctx->fd_pc[0]);

    if (sandboxed_process_drop_capabilities(ctx) < 0)
        return -1;

    if (sandboxed_process_set_seccomp(ctx) < 0)
        return -1;

    /* With no_new_privs set, execve promises not to grant the privilege to do 
    anything that could not have been done without the execve call.  
    For example, the setuid and setgid bits will no longer change the uid or
    gid; file capabilities will not add to the permitted set, and LSMs will
    not relax constraints afterexecve. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
    {
        perror("[!] prctl failed");
        return -1;
    }

    if (execve(ctx->argv[0], ctx->argv, NULL) == -1)
    {
        perror("[!] execve failed");
        return -1;
    }

    return 0;
}

int sandboxed_process_change_id(sandbox *ctx)
{
    gid_t groups = {ctx->run_as_user};

    if (unshare(CLONE_NEWUSER))
    {
        perror("[!] unshare failed");
        return -1;
    }

    /* Unblock parent and wait till it finishes setting uid/gui mappings. */
    if (unblock(ctx->fd_cp[1]) || wait_for_unblock(ctx->fd_pc[0]))
        return -1;

    if (setresuid(ctx->run_as_user, ctx->run_as_user, ctx->run_as_user) != 0)
    {
        perror("[!] setresuid failed");
        return -1;
    }
    if (setresgid(ctx->run_as_user, ctx->run_as_user, ctx->run_as_user) != 0)
    {
        perror("[!] setresgid failed");
        return -1;
    }

    if (setgroups(1, &groups) != 0)
    {
        perror("[!] setgroups failed");
        return -1;
    }

    return 0;
}

int sandboxed_process_drop_capabilities(sandbox *ctx)
{
    cap_t caps;
    cap_value_t cap_v;
    int allowed_caps_mask;
    int is_whitelisted;

    caps = cap_get_proc();
    if (!caps)
    {
        perror("[!] cap_get_proc failed\n");
        return -1;
    }

    if (cap_clear(caps))
    {
        perror("[!] cap_clear failed\n");
        return -1;
    }

    allowed_caps_mask = 0;
    for (int i = 0; i < ctx->nwhitelisted_capabilities; i++)
    {
        if (cap_from_name(ctx->whitelisted_capabilities[i], &cap_v))
        {
            fprintf(stderr, "[!] cap_from_name failed\n");
            return -1;
        }
        allowed_caps_mask |= (1 << cap_v);
    }

    for (cap_value_t cap_nr = 0; cap_nr < ctx->cap_last_cap; cap_nr++)
    {
        is_whitelisted = (allowed_caps_mask >> cap_nr) & 1;
        if (is_whitelisted)
        {
            if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap_nr, CAP_SET) ||
                cap_set_flag(caps, CAP_PERMITTED, 1, &cap_nr, CAP_SET) ||
                cap_set_flag(caps, CAP_INHERITABLE, 1, &cap_nr, CAP_SET))
            {
                perror("cap_set_flag failed");
                return -1;
            }
        }
        else if (cap_nr != CAP_SETFCAP)
        {
            if (prctl(PR_CAPBSET_DROP, cap_nr))
            {
                perror("[!] prctl failed");
                return -1;
            }
        }
    }

    if (cap_set_proc(caps))
    {
        perror("[!] cap_set_proc");
        return -1;
    }

    return 0;
}

int sandboxed_process_change_sysfs_root(sandbox *ctx)
{
    char new_root_path[PATH_MAX];
    char old_root_path[PATH_MAX];
    char tmp_path[PATH_MAX];

    /* First remount the whole filesystem to private – so that bind mount is invisible outside of our namespace. */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
    {
        perror("[!] mount failed");
        return -1;
    }

    /* Create two directories. One for new-root and the other one for old-root. */
    snprintf(new_root_path, PATH_MAX, "/tmp/sandbox/%s/new-root", ctx->container_name);
    if (mkdir(new_root_path, S_IRUSR | S_IWUSR | S_IXUSR))
    {
        perror("[!] mkdir failed");
        return -1;
    }

    if (mount(ctx->mnt_root, new_root_path, NULL, MS_BIND | MS_PRIVATE, NULL))
    {
        perror("[!] mount failed");
        return -1;
    }

    snprintf(old_root_path, PATH_MAX, "/tmp/sandbox/%s/new-root/old-root", ctx->container_name);
    if (mkdir(old_root_path, S_IRUSR | S_IWUSR | S_IXUSR))
    {
        perror("[!] mkdir failed");
        return -1;
    }

    /* Now we are ready to pivot_root. */
    if (syscall(__NR_pivot_root, new_root_path, old_root_path))
    {
        perror("[!] pivot_root failed");
        return -1;
    }

    /* Depending on the implementation of pivot_root, root and cwd of the caller may or may not change. */
    if (chdir("/"))
    {
        perror("[!] chdir failed\n");
        return -1;
    }

    /* And finally just unmount the old root. */
    if (umount2("old-root", MNT_DETACH))
    {
        perror("[!] umount failed");
        return -1;
    }

    /* We don't need an old-root folder. Get rid of it. */
    if (rmdir("old-root"))
    {
        perror("[!] rmdir failed\n");
        return -1;
    }

    return 0;
}

int sandboxed_process_change_hostname(sandbox *ctx)
{
    /* Simple as that. */
    if (sethostname(ctx->container_name, strlen(ctx->container_name)))
    {
        perror("[!] sethostname failed");
        return -1;
    }
    return 0;
}

int sandboxed_process_set_seccomp(sandbox *ctx)
{
    scmp_filter_ctx filter;

    filter = seccomp_init(SCMP_ACT_KILL);
    if (!filter)
    {
        perror("[!] seccomp_init failed");
        return -1;
    }

    /* Whitelist of allowed syscalls. Should contain only the syscalls that sandboxed process
    requires in order to minimalize process interaction with kernel. */
    seccomp_arch_add(filter, SCMP_ARCH_X86_64);
    for (size_t i = 0; i < ctx->nwhitelisted_syscalls; i++)
    {
        seccomp_rule_add(filter, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name(ctx->whitelisted_syscalls[i]), 0);
    }

    if (seccomp_load(filter))
    {
        perror("[!] seccomp_load failed");
        goto err;
    }

    seccomp_release(filter);

    return 0;

err_seccomp_rule_add:
    perror("[!] seccomp_rule_add failed");
err:
    seccomp_release(filter);
    return -1;
}

int sandboxed_process_run_pre_script(sandbox *ctx)
{
    /* Run pre_pre_script if specified by user. It should copy necessary libraries,
    binaries, etc. As an argument pass ctx->mnt_root. */
    char *argv[3];
    pid_t pre_script_executor_pid;
    int pre_script_executor_exit_status;

    /* If no script is specified, just proceed. */
    if (ctx->pre_script[0] == 0)
        return 0;

    argv[0] = ctx->pre_script;
    argv[1] = ctx->mnt_root;
    argv[2] = NULL;

    switch (pre_script_executor_pid = fork())
    {
    case 0:
        if (execve(argv[0], argv, NULL) == -1)
            perror("[!] execve script failed");
        exit(-1);

    default:
        waitpid(pre_script_executor_pid, &pre_script_executor_exit_status, 0);
        if (pre_script_executor_exit_status)
        {
            fprintf(stderr, "[!] pre_script failed\n");
            return -1;
        }
        return 0;
    }

    return -1;
}

/******************************************************************************
 **** Helper functions
 *****************************************************************************/
int write_file(char *path, char *content, int mode)
{
    int fd;

    fd = open(path, O_CREAT | O_RDWR, mode);
    if (fd < 0)
    {
        perror("[!] open failed");
        return -1;
    }

    if (write(fd, content, strlen(content)) != strlen(content))
    {
        perror("[!] write failed");
        close(fd);
        return -1;
    }

    if (close(fd))
    {
        perror("[!] close failed");
        return -1;
    }

    return 0;
}

struct json_object *json_tokener_parse_from_file(char *path)
{
    FILE *fp;
    size_t file_sz;
    char *buf;
    struct json_object *json_object;

    fp = fopen(path, "r");
    if (!fp)
    {
        perror("fopen failed");
        return NULL;
    }
    if (fseek(fp, 0L, SEEK_END))
    {
        perror("fseek failed");
        return NULL;
    }
    file_sz = ftell(fp);
    if (fseek(fp, 0, SEEK_SET))
    {
        perror("fseek failed");
        return NULL;
    }

    buf = malloc(file_sz + 1);
    if (!buf)
    {
        perror("malloc failed");
        return NULL;
    }
    if (fread(buf, 1, file_sz, fp) != file_sz)
    {
        perror("[!] fread failed");
        return NULL;
    }
    if (fclose(fp))
    {
        perror("[!} fclose failed");
        return NULL;
    }

    json_object = json_tokener_parse(buf);
    if (!json_object)
    {
        fprintf(stderr, "[!] json_tokener_parse failed\n");
        return NULL;
    }

    free(buf);
    return json_object;
}

int read_cap_last_cap()
{
    FILE *fp;
    int cap_last_cap;

    fp = fopen("/proc/sys/kernel/cap_last_cap", "r");
    if (!fp)
    {
        perror("[!] fopen failed");
        return -1;
    }

    fscanf(fp, "%d", &cap_last_cap);

    if (fclose(fp))
    {
        perror("[!] fclose failed");
        return -1;
    }
    return cap_last_cap;
}

int mkdir_if_not_exists(char *path, mode_t mode)
{
    if (mkdir(path, mode) == -1 && (errno != EEXIST))
    {
        perror("[!] mkdir failed");
        return -1;
    }
    return 0;
}

int wait_for_unblock(int fd)
{
    char msg[strlen(UNBLOCK_MSG) + 1];

    if (read(fd, msg, strlen(UNBLOCK_MSG)) != strlen(UNBLOCK_MSG))
    {
        perror("[!] read failed");
        return -1;
    }
    if (strncmp(msg, UNBLOCK_MSG, strlen(UNBLOCK_MSG)))
    {
        fprintf(stderr, "[!] strncmp\n");
        return -1;
    }

    return 0;
}

int unblock(int fd)
{
    char msg[strlen(UNBLOCK_MSG) + 1];
    if (write(fd, UNBLOCK_MSG, strlen(UNBLOCK_MSG)) != strlen(UNBLOCK_MSG))
    {
        perror("[!] write failed");
        return -1;
    }
    return 0;
}

/******************************************************************************
 **** Main Thread
 ******************************************************************************
 * Main thread is responsible for parsing all options from profile.json file,
 * creating cgroup and mapping the uid/gid files of child process.
 *****************************************************************************/
int main(int argc, char **argv)
{
    sandbox ctx = {0};

    printf("[i] *** Starting Sandbox ***\n");

    ctx.container_name = generate_container_name();
    if (!ctx.container_name)
        return -1;
    printf("[i] Sandboxed process container name: %s\n", ctx.container_name);

    if (prep_unique_tmp_dir(&ctx))
        return -1;

    /* Sandbox options are defined in profile.json file. 
    One can modify them at own risk. */
    if (argc < 3 || parse_profile(&ctx, argv[1]) < 0)
        goto usage;

    /* Arguments for execve. */
    ctx.argv = &argv[2];

    if (set_sandbox(&ctx) < 0)
        return -1;

    return 0;

usage:
    fprintf(stderr, "[!] Usage sudo ./sandbox <path to profile.json> <binary> [binary args]\n");
    fprintf(stderr, "[!] sudo ./sandbox default.json socat tcp4-listen:13370,fork,reuseaddr exec:./vuln \n");
    return -1;
}

int prep_unique_tmp_dir(sandbox *ctx)
{
    char path[PATH_MAX];

    umask(0);

    /* Don't clutter /tmp folder. Keep all tmp folders in /tmp/sandbox. */
    if (mkdir_if_not_exists("/tmp/sandbox/", 0700))
        return -1;

    /* Create unique tmp directory for our process. */
    snprintf(path, PATH_MAX, "/tmp/sandbox/%s", ctx->container_name);
    if (mkdir(path, 0700))
    {
        perror("[!] mkdir failed");
        return -1;
    }

    return 0;
}

int parse_profile(sandbox *ctx, char *profile_path)
{
    char path[PATH_MAX];
    struct json_object *json_profile, *json_whitelisted_syscalls,
        *json_whitelisted_syscall, *json_mnt_root, *json_run_as_user,
        *json_whitelisted_capabilities, *json_whitelisted_capability,
        *json_pre_script;

    json_profile = json_tokener_parse_from_file(profile_path);
    if (!json_profile)
        return -1;

    /* Load whitelisted syscalls. */
    if (!json_object_object_get_ex(json_profile, "whitelisted_syscalls", &json_whitelisted_syscalls))
    {
        fprintf(stderr, "[!] json_object_get_ex failed\n");
        return -1;
    }
    ctx->nwhitelisted_syscalls = json_object_array_length(json_whitelisted_syscalls);
    ctx->whitelisted_syscalls = (char **)malloc(sizeof(char *) * ctx->nwhitelisted_syscalls);
    if (!ctx->whitelisted_syscalls)
    {
        perror("[!] malloc failed");
        return -1;
    }
    for (size_t i = 0; i < ctx->nwhitelisted_syscalls; ++i)
    {
        json_whitelisted_syscall = json_object_array_get_idx(json_whitelisted_syscalls, i);
        ctx->whitelisted_syscalls[i] = strdup(json_object_get_string(json_whitelisted_syscall));
    }

    /* Load whitelisted capabilities. */
    if (!json_object_object_get_ex(json_profile, "whitelisted_capabilities", &json_whitelisted_capabilities))
    {
        fprintf(stderr, "[!] json_object_get_ex failed\n");
        return -1;
    }
    ctx->nwhitelisted_capabilities = json_object_array_length(json_whitelisted_capabilities);
    ctx->whitelisted_capabilities = (char **)malloc(sizeof(char *) * ctx->nwhitelisted_capabilities);
    if (!ctx->whitelisted_capabilities)
    {
        perror("[!] malloc failed");
        return -1;
    }
    for (size_t i = 0; i < ctx->nwhitelisted_capabilities; ++i)
    {
        json_whitelisted_capability = json_object_array_get_idx(json_whitelisted_capabilities, i);
        ctx->whitelisted_capabilities[i] = strdup(json_object_get_string(json_whitelisted_capability));
    }

    /* Load mount root. */
    if (!json_object_object_get_ex(json_profile, "mount_root", &json_mnt_root))
    {
        fprintf(stderr, "[!] json_object_get_ex failed\n");
        return -1;
    }
    ctx->mnt_root = strdup(json_object_get_string(json_mnt_root));
    /* If mount root is empty, mount at /tmp/sandbox/container_name. */
    if (ctx->mnt_root[0] == 0)
    {
        free(ctx->mnt_root);
        snprintf(path, PATH_MAX, "/tmp/sandbox/%s/root", ctx->container_name);
        ctx->mnt_root = strdup(path);
        if (mkdir(ctx->mnt_root, 01777))
        {
            perror("[!] mkdir failed");
            return -1;
        }
    }

    /* Load run_as_user. */
    if (!json_object_object_get_ex(json_profile, "run_as_user", &json_run_as_user))
    {
        fprintf(stderr, "[!] json_object_get_ex failed\n");
        return -1;
    }
    ctx->run_as_user = json_object_get_int(json_run_as_user);

    /* Load pre_script path. */
    if (!json_object_object_get_ex(json_profile, "pre_script", &json_pre_script))
    {
        fprintf(stderr, "[!] json_object_get_ex failed\n");
        return -1;
    }
    ctx->pre_script = strdup(json_object_get_string(json_pre_script));

    /* Load cgroup configuration. */
    json_object *json_cgroup, *json_cgroup_memory_limit_in_bytes, *json_cgroup_cpu_shares, *json_cgroup_pids_max;
    if (!json_object_object_get_ex(json_profile, "cgroup", &json_cgroup))
    {
        fprintf(stderr, "[!] json_object_get_ex failed\n");
        return -1;
    }
    if (!json_object_object_get_ex(json_cgroup, "memory_limit_in_bytes", &json_cgroup_memory_limit_in_bytes) ||
        !json_object_object_get_ex(json_cgroup, "cpu_shares", &json_cgroup_cpu_shares) ||
        !json_object_object_get_ex(json_cgroup, "pids_max", &json_cgroup_pids_max))
    {
        fprintf(stderr, "[!] json_object_get_ex failed\n");
        return -1;
    }
    ctx->cgroup_memory_limit_in_bytes = json_object_get_int(json_cgroup_memory_limit_in_bytes);
    ctx->cgroup_cpu_shares = json_object_get_int(json_cgroup_cpu_shares);
    ctx->cgroup_pids_max = json_object_get_int(json_cgroup_pids_max);

    return 0;
}

char *generate_container_name()
{
    char *container_name;
    char rand_buf[CONTAINER_NAME_SUFIX_LEN];
    unsigned char hash[SHA256_DIGEST_LENGTH];

    container_name = malloc(strlen(CONTAINER_NAME_PREFIX) + CONTAINER_NAME_SUFIX_LEN + 1);
    if (!container_name)
    {
        perror("[!] malloc failed");
        return NULL;
    }

    /* Leave prefix same for all containers. */
    strncpy(container_name, CONTAINER_NAME_PREFIX, strlen(CONTAINER_NAME_PREFIX));

    /* But make sure sufix gets randomized. */
    if (getrandom(rand_buf, CONTAINER_NAME_SUFIX_LEN, 0) != CONTAINER_NAME_SUFIX_LEN)
    {
        perror("[!] getrandom failed");
        return NULL;
    }

    /* Make sufix printable. */
    SHA256(rand_buf, CONTAINER_NAME_SUFIX_LEN, hash);
    for (int i = 0; i < CONTAINER_NAME_SUFIX_LEN / 2; i++)
    {
        snprintf(container_name + strlen(CONTAINER_NAME_PREFIX) + i * 2, 3, "%02x", hash[i]);
    }

    return container_name;
}

int map_sandboxed_process_ids(pid_t pid, sandbox *ctx)
{
    char path[PATH_MAX];
    char value[PATH_MAX];

    snprintf(path, PATH_MAX, "/proc/%d/uid_map", pid);
    snprintf(value, PATH_MAX, "%d %d 1\n", ctx->run_as_user, USER_NS_OFST);
    if (write_file(path, value, 0) < 0)
        return -1;

    snprintf(path, PATH_MAX, "/proc/%d/gid_map", pid);
    snprintf(value, PATH_MAX, "%d %d 1\n", ctx->run_as_user, USER_NS_OFST);
    if (write_file(path, value, 0) < 0)
        return -1;

    return 0;
}

int create_cgroup(sandbox *ctx, pid_t sandboxed_process_pid)
{
    char path[PATH_MAX];
    char value[PATH_MAX];
    char *subsystems[] = {"memory", "cpu", "pids"};

    /* Limit memory. Disable swappiness. */
    snprintf(path, PATH_MAX, "/sys/fs/cgroup/memory/%s", ctx->container_name);
    mkdir(path, 0700);
    snprintf(path, PATH_MAX, "/sys/fs/cgroup/memory/%s/memory.limit_in_bytes", ctx->container_name);
    snprintf(value, PATH_MAX, "%d", ctx->cgroup_memory_limit_in_bytes);
    if (write_file(path, value, 0) < 0)
        return -1;
    snprintf(path, PATH_MAX, "/sys/fs/cgroup/memory/%s/memory.swappiness", ctx->container_name);
    snprintf(value, PATH_MAX, "%d", 0);
    if (write_file(path, value, 0) < 0)
        return -1;

    /* Limit cpu. */
    snprintf(path, PATH_MAX, "/sys/fs/cgroup/cpu/%s", ctx->container_name);
    mkdir(path, 0700);
    snprintf(path, PATH_MAX, "/sys/fs/cgroup/cpu/%s/cpu.shares", ctx->container_name);
    snprintf(value, PATH_MAX, "%d", ctx->cgroup_cpu_shares);
    if (write_file(path, value, 0) < 0)
        return -1;

    /* Limit pids. */
    snprintf(path, PATH_MAX, "/sys/fs/cgroup/pids/%s", ctx->container_name);
    mkdir(path, 0700);
    snprintf(path, PATH_MAX, "/sys/fs/cgroup/pids/%s/pids.max", ctx->container_name);
    snprintf(value, PATH_MAX, "%d", ctx->cgroup_pids_max);
    if (write_file(path, value, 0) < 0)
        return -1;

    /* Add self to newly created cgroup. */
    snprintf(value, PATH_MAX, "%d", sandboxed_process_pid);
    for (int i = 0; i < sizeof(subsystems) / sizeof(subsystems[0]); i++)
    {
        snprintf(path, PATH_MAX, "/sys/fs/cgroup/%s/%s/tasks", subsystems[i], ctx->container_name);
        if (write_file(path, value, 0) < 0)
            return -1;
    }

    /* Register cleanup function. Must enable notify_on_release. */
    for (int i = 0; i < sizeof(subsystems) / sizeof(subsystems[0]); i++)
    {
        snprintf(path, PATH_MAX, "/sys/fs/cgroup/%s/%s/notify_on_release", subsystems[i], ctx->container_name);
        snprintf(value, PATH_MAX, "%d", 1);
        if (write_file(path, value, 0) < 0)
            return -1;

        snprintf(path, PATH_MAX, "/tmp/sandbox/cgroup_release_%s.sh", subsystems[i]);
        snprintf(value, PATH_MAX, "#!/bin/bash\nrmdir /sys/fs/cgroup/%s/$1", subsystems[i]);
        if (write_file(path, value, 0700) < 0)
            return -1;

        snprintf(path, PATH_MAX, "/sys/fs/cgroup/%s/release_agent", subsystems[i]);
        snprintf(value, PATH_MAX, "/tmp/sandbox/cgroup_release_%s.sh", subsystems[i]);
        if (write_file(path, value, 0) < 0)
            return -1;
    }

    return 0;
}

int setup_communication_with_sandboxed_process(sandbox *ctx)
{
    if (pipe(ctx->fd_pc) || pipe(ctx->fd_cp))
    {
        perror("[!] pipe failed");
        return -1;
    }
}

int set_sandbox(sandbox *ctx)
{
    pid_t sandboxed_process_pid;
    char *sandboxed_process_stack;
    int res = 0;

    /* Read it here, as sandboxed process won't have access to /proc. */
    ctx->cap_last_cap = read_cap_last_cap();
    if (ctx->cap_last_cap < 0)
        return -1;

    if (setup_communication_with_sandboxed_process(ctx) < 0)
        return -1;

    sandboxed_process_stack = mmap(NULL,
                                   STACK_SIZE, PROT_READ | PROT_WRITE, MAP_GROWSDOWN | MAP_PRIVATE | MAP_ANONYMOUS,
                                   -1, 0);
    if (sandboxed_process_stack == MAP_FAILED)
    {
        perror("[!] malloc failed");
        return -1;
    }

    /* Cannot set CLONE_NEWUSER flag here as we won't be able to mount PRIVATE on pivot_root. 
    We have to unshare(CLONE_NEWUSER) later on instead. */
    sandboxed_process_pid = clone(enter_sandbox, sandboxed_process_stack + STACK_SIZE,
                                  SIGCHLD | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNS |
                                      CLONE_NEWPID | CLONE_NEWCGROUP,
                                  ctx);
    if (sandboxed_process_pid == -1)
    {
        perror("[!] clone failed");
        return -1;
    }
    printf("[i] Sandboxed process id: %d\n", sandboxed_process_pid);

    /* Parent won't read from fd_pc and won't write to fd_cp – therefore just close them. */
    close(ctx->fd_pc[0]);
    close(ctx->fd_cp[1]);

    /* Give sandboxed process some time to perform root opeartions. */
    if (wait_for_unblock(ctx->fd_cp[0]) ||
        create_cgroup(ctx, sandboxed_process_pid) ||
        map_sandboxed_process_ids(sandboxed_process_pid, ctx) ||
        unblock(ctx->fd_pc[1]))
    {
        kill(sandboxed_process_pid, SIGKILL);
        res = -1;
        goto cleanup;
    }

cleanup:
    /* We don't need to communicate with sandboxed process anymore. Close rest of descriptors. */
    close(ctx->fd_pc[1]);
    close(ctx->fd_cp[0]);

    waitpid(sandboxed_process_pid, NULL, 0);

    return res;
}