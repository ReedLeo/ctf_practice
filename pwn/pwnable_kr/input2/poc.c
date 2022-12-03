#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>

char* new_argv[101] = {[0 ... 99] = "A"};
char* new_envp[10];

int pipe_stdin[2], pipe_stderr[2];

void stage1_argv() {
    new_argv['A'] = "\x00";
    new_argv['B'] = "\x20\x0a\x0d";
}

void stage2_stdio() {
    close(0);
    pipe(pipe_stdin);

    close(2);
    pipe(pipe_stderr);

}

void stage3_env() {
    new_envp[0] = "\xde\xad\xbe\xef=\xca\xfe\xba\xbe";
}

void stage4_file() {
    int fd = open("\x0a", O_WRONLY|O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    write(fd, "\x00\x00\x00\x00", 4);
    close(fd);
}

void stage5_socket(int port) {
    int sd, cd;
    struct sockaddr_in saddr;
    cd = socket(AF_INET, SOCK_STREAM, 0);
    if (cd == -1) {
        printf("socket error: %s\n", strerror(errno));
        exit(-1);
    }

    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &saddr.sin_addr);
    sd = connect(cd, (struct sockaddr*)&saddr, sizeof(saddr));
    if (sd == -1) {
        printf("conenct failed: %s\n", strerror(errno));
        exit(-1);
    }

    write(sd, "\xde\xad\xbe\xef", 4);

    close(sd);
    close(cd);
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s [victime_file] [port]\n", argv[0]);
        exit(-1);
    }

    int port = atoi(argv[2]);
    const char* filename = argv[1];

    stage1_argv();
    stage2_stdio();
    stage3_env();
    stage4_file();

    pid_t pid = fork();
    if (pid == -1) {
        printf("fork fialed: %s\n", strerror(errno));
        exit(-1);
    } else if (pid == 0) {
        // child
        close(pipe_stdin[1]);
        close(pipe_stderr[1]);

        // for stage5, set the argv['C'] = port
        new_argv['C'] = argv[2];
        execve(filename, new_argv, new_envp);
        exit(-1);
    } else {
        // parent
        close(pipe_stderr[0]);
        close(pipe_stdin[0]);

        write(pipe_stdin[1], "\x00\x0a\x00\xff", 4);
        write(pipe_stderr[1], "\x00\x0a\x02\xff", 4);

        sleep(2);
        stage5_socket(port);
    }

    return 0;
}