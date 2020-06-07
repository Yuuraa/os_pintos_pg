#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler(struct intr_frame *);
void exit(int);
int write(int, const void *, unsigned);

void syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f) {
    printf("system call! : %d\n", *(uint32_t *)(f->esp));
    switch (*(uint32_t *)(f->esp)) {
        case SYS_HALT:
            break;
        case SYS_EXIT:
            exit(*(uint32_t *)(f->esp + 4));
            break;
        case SYS_WRITE:
            write((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
            break;
    }

    thread_exit();
}

void exit(int status) {
    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_exit();
}

int write(int fd, const void *buffer, unsigned size) {
    if (fd == 1) {
        putbuf(buffer, size);
        return size;
    }
    return -1;
}