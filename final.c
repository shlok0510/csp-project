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

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))

// --- Global Paths ---
char SOURCE_DIR[PATH_MAX];
char BACKUP_DIR[PATH_MAX];
char LOG_FILE[PATH_MAX];

// --- Function Prototypes ---
void *monitor_thread_func(void *arg);
void *backup_thread_func(void *arg);
void perform_backup_all(const char *source, const char *destination);
void copy_file(const char *source_path, const char *dest_path);
void log_message(const char *msg);

// --- Logging Function ---
void log_message(const char *msg) {
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) return;

    time_t now = time(NULL);
    char *timestamp = ctime(&now);
    timestamp[strlen(timestamp) - 1] = '\0'; // Remove newline

    fprintf(log, "[%s] %s\n", timestamp, msg);
    fclose(log);
}

// --- Main Function ---
int main() {
    const char *home = getenv("HOME");
    if (!home) home = "/home/user";

    snprintf(SOURCE_DIR, sizeof(SOURCE_DIR), "%s/Desktop/source", home);
    snprintf(BACKUP_DIR, sizeof(BACKUP_DIR), "%s/Desktop/backup", home);
    snprintf(LOG_FILE, sizeof(LOG_FILE), "%s/Desktop/backupd.log", home);

    mkdir(SOURCE_DIR, 0755);
    mkdir(BACKUP_DIR, 0755);

    log_message("Backup daemon started.");
    log_message("Monitoring directory changes...");

    pthread_t monitor_tid, backup_tid;

    if (pthread_create(&monitor_tid, NULL, monitor_thread_func, NULL) != 0) {
        perror("Failed to create monitor thread");
        return 1;
    }

    if (pthread_create(&backup_tid, NULL, backup_thread_func, NULL) != 0) {
        perror("Failed to create backup thread");
        return 1;
    }

    pthread_join(monitor_tid, NULL);
    pthread_join(backup_tid, NULL);

    return 0;
}

// --- Directory Monitor Thread ---
void *monitor_thread_func(void *arg) {
    int fd, wd;
    char buffer[BUF_LEN];

    fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        return NULL;
    }

    wd = inotify_add_watch(fd, SOURCE_DIR,
                           IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO);
    if (wd < 0) {
        perror("inotify_add_watch");
        close(fd);
        return NULL;
    }

    while (1) {
        int length = read(fd, buffer, BUF_LEN);
        if (length < 0) {
            perror("read");
            break;
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->len > 0) {
                char msg[PATH_MAX + 64];
                if (event->mask & IN_CREATE) {
                    snprintf(msg, sizeof(msg), "CREATE: %s", event->name);
                    log_message(msg);
                    perform_backup_all(SOURCE_DIR, BACKUP_DIR);
                }
                if (event->mask & IN_MODIFY) {
                    snprintf(msg, sizeof(msg), "MODIFY: %s", event->name);
                    log_message(msg);
                    perform_backup_all(SOURCE_DIR, BACKUP_DIR);
                }
                if (event->mask & IN_DELETE) {
                    snprintf(msg, sizeof(msg), "DELETE: %s", event->name);
                    log_message(msg);
                    perform_backup_all(SOURCE_DIR, BACKUP_DIR);
                }
                if (event->mask & (IN_MOVED_FROM | IN_MOVED_TO)) {
                    snprintf(msg, sizeof(msg), "MOVE: %s", event->name);
                    log_message(msg);
                    perform_backup_all(SOURCE_DIR, BACKUP_DIR);
                }
            }
            i += EVENT_SIZE + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
    log_message("Monitor thread exiting.");
    return NULL;
}

// --- Periodic Backup Thread ---
void *backup_thread_func(void *arg) {
    while (1) {
        log_message("Backup thread: Performing periodic backup...");
        perform_backup_all(SOURCE_DIR, BACKUP_DIR);
        sleep(15);
    }
    return NULL;
}

// --- Recursive Backup Function ---
void perform_backup_all(const char *source, const char *destination) {
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;

    char source_path[PATH_MAX];
    char dest_path[PATH_MAX];
    char msg[PATH_MAX + 64];  // ✅ FIXED BUFFER SIZE

    mkdir(destination, 0755);

    if ((dir = opendir(source)) == NULL) {
        perror("opendir");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        int len_source = snprintf(source_path, sizeof(source_path), "%s/%s", source, entry->d_name);
        int len_dest = snprintf(dest_path, sizeof(dest_path), "%s/%s", destination, entry->d_name);

        if (len_source >= sizeof(source_path) || len_dest >= sizeof(dest_path)) {
            snprintf(msg, sizeof(msg), "Warning: Path too long, skipping %s", entry->d_name);
            log_message(msg);
            continue;
        }

        if (stat(source_path, &statbuf) == -1) continue;

        if (S_ISDIR(statbuf.st_mode)) {
            perform_backup_all(source_path, dest_path);
        } else if (S_ISREG(statbuf.st_mode)) {
            struct stat dest_statbuf;
            if (stat(dest_path, &dest_statbuf) == -1 || statbuf.st_mtime > dest_statbuf.st_mtime) {
                copy_file(source_path, dest_path);
                snprintf(msg, sizeof(msg), "Copied: %s", source_path);
                log_message(msg);
            }
        }
    }
    closedir(dir);
}

// --- File Copy Function ---
void copy_file(const char *source_path, const char *dest_path) {
    FILE *source_file, *dest_file;
    char buffer[4096];
    size_t bytes;

    source_file = fopen(source_path, "rb");
    if (!source_file) return;

    dest_file = fopen(dest_path, "wb");
    if (!dest_file) {
        fclose(source_file);
        return;
    }

    while ((bytes = fread(buffer, 1, sizeof(buffer), source_file)) > 0)
        fwrite(buffer, 1, bytes, dest_file);

    fclose(source_file);
    fclose(dest_file);

    struct stat st;
    if (stat(source_path, &st) == 0)
        chmod(dest_path, st.st_mode);
}
