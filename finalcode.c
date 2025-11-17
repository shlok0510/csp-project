#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dirent.h>
#include <time.h>
#include <linux/limits.h>
#include <signal.h>
#include <fcntl.h>
#include <stdarg.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))
#define MSG_BUF (PATH_MAX + 2)

volatile sig_atomic_t stop_flag = 0;
pthread_t monitor_tid, backup_tid;

char SOURCE_DIR[PATH_MAX];
char BACKUP_DIR[PATH_MAX];
char LOG_FILE[PATH_MAX];
char PID_FILE[PATH_MAX];

int pipefd[2];
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int wd;
    char path[PATH_MAX];
} WatchNode;

#define MAX_WD 8192
static WatchNode wd_map[MAX_WD];
static int wd_count = 0;
void log_message(const char *fmt, ...);
void daemonize_and_write_pid();
void signal_handler(int sig);
void *monitor_thread_func(void *arg);
void *backup_thread_func(void *arg);
void copy_latest_file(const char *relative_path);
void perform_full_backup();
void ensure_dir_exists(const char *path);
void perform_full_backup_recursive(const char *base_src, const char *base_rel);
void add_watch_recursive(int fd, const char *path);
void add_watch(int fd, const char *abs_path);
int already_running();

int main() {
    const char *home = getenv("HOME");
    snprintf(SOURCE_DIR, sizeof(SOURCE_DIR), "%s/Desktop/source", home);
    snprintf(BACKUP_DIR, sizeof(BACKUP_DIR), "%s/Desktop/backup", home);
    snprintf(LOG_FILE, sizeof(LOG_FILE), "%s/Desktop/backupd.log", home);
    snprintf(PID_FILE, sizeof(PID_FILE), "%s/Desktop/backupd.pid", home);

    ensure_dir_exists(SOURCE_DIR);
    ensure_dir_exists(BACKUP_DIR);

    if (already_running()) {
        fprintf(stderr, "backupd: Already running.\n");
        return 1;
    }

    if (pipe(pipefd) == -1) {
        perror("pipe");
        return 1;
    }

    daemonize_and_write_pid();

    struct sigaction sa = {0};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);

    log_message("Backup Daemon started.");

    pthread_create(&monitor_tid, NULL, monitor_thread_func, NULL);
    pthread_create(&backup_tid, NULL, backup_thread_func, NULL);

    pthread_join(monitor_tid, NULL);
    pthread_join(backup_tid, NULL);

    unlink(PID_FILE);
    log_message("Backup Daemon stopped.");
    return 0;
}

void daemonize_and_write_pid() {
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    if (setsid() < 0) exit(1);

    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);

    umask(0);
    chdir("/");

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    FILE *pf = fopen(PID_FILE, "w");
    if (pf) { fprintf(pf, "%d\n", getpid()); fclose(pf); }
}
int already_running() {
    FILE *pf = fopen(PID_FILE, "r");
    if (!pf) return 0;

    int pid = 0;
    fscanf(pf, "%d", &pid);
    fclose(pf);
    if (pid <= 1) return 0;

    if (kill(pid, 0) == 0) return 1; // running

    return 0; // stale pidfile
}
void signal_handler(int sig) {
    char msg[2] = {0};
    if (sig == SIGTERM || sig == SIGINT) {
        stop_flag = 1;
        msg[0] = 'Q';
    } else if (sig == SIGUSR1) {
        msg[0] = 'F';
    }
    write(pipefd[1], msg, 2);
}

void log_message(const char *fmt, ...) {
    pthread_mutex_lock(&log_mutex);
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) { pthread_mutex_unlock(&log_mutex); return; }

    time_t now = time(NULL);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%c", localtime(&now));

    fprintf(log, "[%s] ", timestr);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(log, fmt, ap);
    va_end(ap);

    fprintf(log, "\n");
    fclose(log);
    pthread_mutex_unlock(&log_mutex);
}
void add_watch(int fd, const char *abs_path) {
    int wd = inotify_add_watch(fd, abs_path,
        IN_CREATE | IN_MODIFY | IN_MOVED_TO | IN_DELETE);

    if (wd < 0) return;

    wd_map[wd_count].wd = wd;
    strcpy(wd_map[wd_count].path, abs_path);
    wd_count++;

    log_message("Watching: %s", abs_path);
}
void add_watch_recursive(int fd, const char *path) {
    add_watch(fd, path);

    DIR *d = opendir(path);
    if (!d) return;

    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;

        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", path, e->d_name);

        struct stat st;
        if (stat(full, &st) == 0 && S_ISDIR(st.st_mode)) {
            add_watch_recursive(fd, full);
        }
    }
    closedir(d);
}

// ---------------- MONITOR THREAD -----------------
void *monitor_thread_func(void *arg) {
    int fd = inotify_init();
    if (fd < 0) return NULL;

    wd_count = 0;
    add_watch_recursive(fd, SOURCE_DIR);

    char buffer[BUF_LEN];

    while (!stop_flag) {
        int len = read(fd, buffer, BUF_LEN);
        if (len < 0) {
            if (errno == EINTR) continue;
            usleep(200000);
            continue;
        }

        int i = 0;
        while (i < len) {
            struct inotify_event *ev = (struct inotify_event *)&buffer[i];

            char base[PATH_MAX] = "";
            for (int k = 0; k < wd_count; k++)
                if (wd_map[k].wd == ev->wd)
                    strcpy(base, wd_map[k].path);

            if (ev->len > 0) {
                char full[PATH_MAX];
                snprintf(full, sizeof(full), "%s/%s", base, ev->name);

                char rel[PATH_MAX];
                if (strncmp(full, SOURCE_DIR, strlen(SOURCE_DIR)) == 0)
                    strcpy(rel, full + strlen(SOURCE_DIR) + 1);
                else
                    strcpy(rel, ev->name);

                char msg[MSG_BUF];
                msg[0] = 'C';
                strcpy(&msg[1], rel);
                write(pipefd[1], msg, strlen(rel) + 2);

                struct stat st;
                if (stat(full, &st) == 0 && S_ISDIR(st.st_mode) &&
                    (ev->mask & IN_CREATE)) {
                    add_watch_recursive(fd, full);
                }
            }

            i += EVENT_SIZE + ev->len;
        }
    }

    write(pipefd[1], "Q", 2);
    close(fd);
    return NULL;
}

// ---------------- BACKUP THREAD -----------------
void *backup_thread_func(void *arg) {
    char buf[MSG_BUF];

    perform_full_backup();

    while (!stop_flag) {
        int r = read(pipefd[0], buf, MSG_BUF);
        if (r <= 0) continue;

        char type = buf[0];
        char *path = &buf[1];

        if (type == 'Q') break;

        if (type == 'F') {
            log_message("Manual full backup triggered");
            perform_full_backup();
            continue;
        }

        // ----------- AUTO-FIX DIRECTORY CREATION -----------
        char full_src[PATH_MAX];
        snprintf(full_src, sizeof(full_src), "%s/%s", SOURCE_DIR, path);

        struct stat st_src;
        if (stat(full_src, &st_src) == 0 && S_ISDIR(st_src.st_mode)) {

            char full_dst[PATH_MAX];
            snprintf(full_dst, sizeof(full_dst), "%s/%s", BACKUP_DIR, path);

            struct stat st_dst;
            if (stat(full_dst, &st_dst) == 0) {
                if (S_ISREG(st_dst.st_mode)) {
                    unlink(full_dst);
                    log_message("Auto-Fix: Removed wrong file blocking directory: %s", path);
                }
            }

            ensure_dir_exists(full_dst);
            log_message("Created directory in backup: %s", path);
            continue;
        }

        // ---------------- FILE COPY ----------------
        copy_latest_file(path);
    }
    return NULL;
}

// ---------------- COPY FILE -----------------
void copy_latest_file(const char *relative_path) {
    char src[PATH_MAX], dst[PATH_MAX];
    snprintf(src, sizeof(src), "%s/%s", SOURCE_DIR, relative_path);
    snprintf(dst, sizeof(dst), "%s/%s", BACKUP_DIR, relative_path);

    char folder[PATH_MAX];
    strcpy(folder, relative_path);

    char *slash = strrchr(folder, '/');
    if (slash) {
        *slash = 0;
        char dst_dir[PATH_MAX];
        snprintf(dst_dir, sizeof(dst_dir), "%s/%s", BACKUP_DIR, folder);
        ensure_dir_exists(dst_dir);
    }

    FILE *in = fopen(src, "rb");
    if (!in) return;

    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return; }

    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
        fwrite(buf, 1, n, out);

    fclose(in);
    fclose(out);

    log_message("Updated backup: %s", relative_path);
}

// ---------------- FULL BACKUP -----------------
void perform_full_backup() {
    log_message("Performing full backup...");
    perform_full_backup_recursive(SOURCE_DIR, "");
}

void perform_full_backup_recursive(const char *base_src, const char *base_rel) {
    char path[PATH_MAX];
    if (base_rel[0] == '\0')
        strcpy(path, base_src);
    else
        snprintf(path, sizeof(path), "%s/%s", base_src, base_rel);

    DIR *d = opendir(path);
    if (!d) return;

    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;

        char rel[PATH_MAX];
        if (base_rel[0] == '\0')
            strcpy(rel, e->d_name);
        else
            snprintf(rel, sizeof(rel), "%s/%s", base_rel, e->d_name);

        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", base_src, rel);

        struct stat st;
        if (stat(full, &st) == -1) continue;

        if (S_ISDIR(st.st_mode)) {
            char dst_dir[PATH_MAX];
            snprintf(dst_dir, sizeof(dst_dir), "%s/%s", BACKUP_DIR, rel);
            ensure_dir_exists(dst_dir);
            perform_full_backup_recursive(base_src, rel);
        } else if (S_ISREG(st.st_mode)) {
            copy_latest_file(rel);
        }
    }
    closedir(d);
}

// ---------------- ENSURE DIR EXIST -----------------
void ensure_dir_exists(const char *p) {
    char tmp[PATH_MAX];
    strcpy(tmp, p);

    for (char *s = tmp + 1; *s; s++) {
        if (*s == '/') {
            *s = 0;
            mkdir(tmp, 0755);
            *s = '/';
        }
    }
    mkdir(tmp, 0755);
}final
