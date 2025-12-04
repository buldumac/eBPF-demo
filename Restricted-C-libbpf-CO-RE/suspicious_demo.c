// suspicious_demo.c

// Lab-only "suspicious" process to exercies eBPF-based monitoring
//
// Behaviors:
//  1. Connects to 8.8.8.8:53 (Google DNS)
//  2. Performs some file I/O and syscalls
//  3. Allocates a large chunk of memory and touches it.
//  4. "Ransomware-like" file activing in ~/demo_files (safe)
//
// Us this only in a controlled environment

// gcc -O2 -Wall suspicious_demo.c -o suspicious_demo

#define _GNU_SOURCE // enable GNU-specific and extra POSIX features when including system headers

// system headers -> C header files that come from the OS / C standard library, not custom ones

#include <stdio.h>      // printf, snprintf, fprintf, fopen, FILE *, perror
#include <stdlib.h>     // malloc, free, exit, atoi, atexit, rand
#include <string.h>     // strlen, strcmp, strcpy, strcat, memset, memcmp, memmove, strstr
#include <unistd.h>     // read, write, fork, _exit, pipe, dup, usleep, STDIN_FILENO
#include <sys/socket.h> // socket, bind, listen, connect, send, AF_INET, SOCK_STREAM, struct sockaddr
#include <arpa/inet.h>  // htons, htonl, ntohs, ntohl, inet_addr, struct in_addr
#include <sys/stat.h>   // st_size, st_mode, stat, fstat, lstat, chmod, umask
#include <fcntl.h>      // O_TRUNC, O_CREAT, O_NONBLOCK, AT_FDCWD
#include <errno.h>      // errno, EAGAIN, EINTR, ENOENT, EACCESS, ENOMEM

#define DEMO_DIR      "./test-ransom"
#define NUM_DEMO_FILES 10
#define DEMO_FILE_SIZE 4096
#define BIG_ALLOC_SIZE (100UL << 20) // 100 * 1024 * 1024 = 100 MB
#define SMALL_ALLOC_SIZE (1UL << 20) // 1 * 1024 * 1024 = 1 MB

static void demo_connect_8888(void) {
    printf("[*] Connecting to 8.8.8.8:53 ...\n");
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket creating error");
        return;
    }
    
    // IPv4 socket address
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);  // DNS port
    
    // inet_pton converts network address from text representation
    // in binary form for use in kernel's network stack
    int ret = inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);
    if (ret == 0) {
        fprintf(stderr, "inet_pton: invalid IP address string\n");
        close(sockfd);
        return;
    } else if (ret == -1) {
        perror("inet_pton convert failed");
        close(sockfd);
        return;
    }
    
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect error");
    } else {
        printf("[+] Connected (or at least connect() succeeded().\n");
    }
    
    close(sockfd);
}

static void demo_basic_syscalls(void) {
    printf("[*] Doing some basic file I/O syscalls ...\n");
    
    // 0644 -> rw-r--r--
    // O_WRONLY -> open write-only
    // O_CREAT  -> create the file if it does not exist
    // O_TRUNC  -> if the file already exists, truncate it to length 0 (erase contents)
    int fd = open("./demo_syscalls.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open demo_syscalls.log error");
        return;
    }
    
    const char *msg = "This is a demo log line for eBPF monitoring.\n";
    for (int i = 0; i < 5; i++) {
        ssize_t written = write(fd, msg, strlen(msg));
        if (written < 0) {
            perror("write to demo log file error");
            break;
        }
        fsync(fd); // more syscalls, and shows up clearly
    }
    
    close(fd);
}

static void demo_alloc(size_t alloc_size) {
    printf("[*] Allocating %d MB of memory ...\n", (int)(alloc_size / (1024 * 1024)));
    
    char *buf = malloc(alloc_size);
    if (!buf) {
        perror("malloc allocation fail");
        return;
    }
    
    // Touch each page to make sure the kernel actually backs it
    // Because of demand paging and lazy allocation, the kernel usually
    // doesn't allocate physical RAM immediately
    
    // This techniques is known as "touching" or "faulting in" pages
    
    // We need to know what is the size of a memory page on this system
    // Typical page size is 4096 bytes or 4 Kib, but it depends on architecture/config
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    for (size_t offset = 0; offset < alloc_size; offset += page_size) {
        buf[offset] = (char)(offset & 0xFF);
    }
    
    printf("[+] Allocation done, sleeping for a bit ...\n");
    sleep(3);
    
    free(buf);
    printf("[+] Memory freed.\n");
}

// Create demo directory and files
static int prepare_demo_files(void) {
    printf("[*] Preparing demo files in %s ...\n", DEMO_DIR);
    
    if (mkdir(DEMO_DIR, 0755) < 0) {
        if (errno != EEXIST) {
            perror("mkdir error");
            return -1;
        }
    }
    
    char path[256];
    
    for (int i = 0; i < NUM_DEMO_FILES; i++) {
        snprintf(path, sizeof(path), "%s/file_%d.txt", DEMO_DIR, i);
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            perror("open demo file error");
            continue;
        }
        
        char content[DEMO_FILE_SIZE];
        int len = snprintf(content, sizeof(content),
                            "This is demo file %d. "
                            "It will be 'encrypted' by this test program.\n",
                            i);
        if (len < 0) {
            len = 0;
        }
        
        if (write(fd, content, (size_t)len) < 0) {
            perror("write demo file error");
        }
        
        close(fd);
    }
    
    printf("[+] Demo files prepared.\n");
    return 0;
}

// "Ransomware-like" behavior on demo files only
// Instead of real crypto, we simply overwrite content with "ENCRYPTED" marker
// This is enough to show lots of open/write events to eBPF
static void demo_fake_ransomware(void) {
    printf("[*] Starting fake ransomware activity on %s ...\n", DEMO_DIR);
    
    char path[256];
    
    for (int i = 0; i < NUM_DEMO_FILES; i++) {
        snprintf(path, sizeof(path), "%s/file_%d.txt", DEMO_DIR, i);
        
        int fd = open(path, O_WRONLY);
        if (fd < 0) {
            perror("open for rake encryption error");
            continue;
        }
        
        const char *marker = 
            "ENCRYPTED_BY_DEMO_TOOL\n"
            "(This is only a test, not read ransomware.)\n";
        ssize_t len = (ssize_t)strlen(marker);
        
        if (ftruncate(fd, 0) < 0) {
            perror("ftruncate error");
        }
        
        if (write(fd, marker, (size_t)len) < 0) {
            perror("write marker error");
        }
        
        fsync(fd); // flush to disk, more syscalls
        close(fd);
        
        // rename file to simulate extension change
        char new_path[256];
        snprintf(new_path, sizeof(new_path), "%s/file_%d.txt.enc", DEMO_DIR, i);
        // rename(path, new_path) -> syscall is rename
        if (renameat(AT_FDCWD, path, AT_FDCWD, new_path) < 0) {
            perror("rename to .env");
        }
        
        // brief sleep to behavior is visible over time in traces
        usleep(200 * 1000); // 200 ms
        
        printf("[+] Fake ransomware activity complete.\n");
    }
}

int main(int argc, char *argv[], char *envp[]) {
    printf("=== Suspicious demo process (for eBPF CoP) ===\n");
    
    demo_connect_8888();
    demo_basic_syscalls();
    demo_alloc(BIG_ALLOC_SIZE);
    demo_alloc(SMALL_ALLOC_SIZE);
    
    if (prepare_demo_files() == 0) {
        demo_fake_ransomware();
    }
    
    return 0;
}





