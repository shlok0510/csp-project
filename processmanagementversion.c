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

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))

// Globals for graceful shutdown
volatile sig_atomic_t stop_flag = 0;
pthread_t monitor_tid, backup_tid;

// --- Function declarations ---
void *monitor_thread_func(void *arg);
void *backup_thread_func(void *arg);
void perform_backup_all(const char *source, const char *destination);
void copy_file(const char *source_path, const char *dest_path);
void signal_handler(int sig);
void daemonize();
void log_message(const char *msg);

// --- Global paths (auto set) ---
char SOURCE_DIR[PATH_MAX];
char BACKUP_DIR[PATH_MAX];
char LOG_FILE[PATH_MAX];

// --- MAIN ---
int main() {
    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "Cannot get HOME directory.\n");
        return 1;
    }

    snprintf(SOURCE_DIR, sizeof(SOURCE_DIR), "%s/Desktop/source", home);
    snprintf(BACKUP_DIR, sizeof(BACKUP_DIR), "%s/Desktop/backup", home);
    snprintf(LOG_FILE, sizeof(LOG_FILE), "%s/Desktop/backupd.log", home);

    mkdir(SOURCE_DIR, 0755);
    mkdir(BACKUP_DIR, 0755);

    // Turn process into daemon
    daemonize();

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    log_message("Backup Daemon started.");
    log_message("Monitoring directory changes...");

    // Start threads
    if (pthread_create(&monitor_tid, NULL, monitor_thread_func, NULL) != 0) {
        log_message("Error creating monitor thread.");
        exit(1);
    }
    if (pthread_create(&backup_tid, NULL, backup_thread_func, NULL) != 0) {
        log_message("Error creating backup thread.");
        exit(1);
    }

    pthread_join(monitor_tid, NULL);
    pthread_join(backup_tid, NULL);

    log_message("Backup Daemon stopped.");
    return 0;
}

// --- Convert to Daemon ---
void daemonize() {
    pid_t pid = fork();
    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS); // Parent exits

    if (setsid() < 0)
        exit(EXIT_FAILURE);

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS);

    umask(0);
    chdir("/");

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);
}

// --- Signal handler ---
void signal_handler(int sig) {
    stop_flag = 1;
}

// --- Log to file ---
void log_message(const char *msg) {
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) return;
    time_t now = time(NULL);
    fprintf(log, "[%s] %s\n", ctime(&now), msg);
    fclose(log);
}

// --- Monitor thread ---
void *monitor_thread_func(void *arg) {
    int fd, wd;
    char buffer[BUF_LEN];

    fd = inotify_init();
    if (fd < 0) {
        log_message("inotify_init failed");
        return NULL;
    }

    wd = inotify_add_watch(fd, SOURCE_DIR, IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO);
    if (wd < 0) {
        log_message("inotify_add_watch failed");
        close(fd);
        return NULL;
    }

    while (!stop_flag) {
        int length = read(fd, buffer, BUF_LEN);
        if (length < 0 && errno != EINTR) {
            log_message("read error");
            break;
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->len > 0) {
                char msg[512];
                snprintf(msg, sizeof(msg), "Change detected: %s", event->name);
                log_message(msg);
                perform_backup_all(SOURCE_DIR, BACKUP_DIR);
            }
            i += EVENT_SIZE + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
    return NULL;
}

// --- Backup thread (periodic) ---
void *backup_thread_func(void *arg) {
    while (!stop_flag) {
        perform_backup_all(SOURCE_DIR, BACKUP_DIR);
        sleep(30); // every 30 seconds
    }
    return NULL;
}

// --- Recursively copy directories ---
void perform_backup_all(const char *source, const char *destination) {
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;
    char source_path[PATH_MAX], dest_path[PATH_MAX];

    mkdir(destination, 0755);

    if ((dir = opendir(source)) == NULL) return;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        snprintf(source_path, sizeof(source_path), "%s/%s", source, entry->d_name);
        snprintf(dest_path, sizeof(dest_path), "%s/%s", destination, entry->d_name);

        if (stat(source_path, &statbuf) == -1) continue;

        if (S_ISDIR(statbuf.st_mode)) {
            perform_backup_all(source_path, dest_path);
        } else if (S_ISREG(statbuf.st_mode)) {
            struct stat dest_stat;
            if (stat(dest_path, &dest_stat) == -1 || statbuf.st_mtime > dest_stat.st_mtime) {
                copy_file(source_path, dest_path);
                char msg[512];
                snprintf(msg, sizeof(msg), "Copied: %s", source_path);
                log_message(msg);
            }
        }
    }
    closedir(dir);
}

// --- Copy file ---
void copy_file(const char *source_path, const char *dest_path) {
    FILE *src = fopen(source_path, "rb");
    if (!src) return;

    FILE *dst = fopen(dest_path, "wb");
    if (!dst) {
        fclose(src);
        return;
    }

    char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0)
        fwrite(buffer, 1, bytes, dst);

    fclose(src);
    fclose(dst);
}
