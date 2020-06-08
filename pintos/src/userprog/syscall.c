#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "filesys/off_t.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

static void syscall_handler(struct intr_frame *);

void halt(void);
void exit(int);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
struct lock filesys_lock;

void is_valid_address(const void *);

//Ref. from userprog/syscall.c
struct file {
    struct inode *inode;
    off_t pos;
    bool deny_write;
};

void is_valid_address(const void *vaddr) {
    if (!is_user_vaddr(vaddr)) {
        exit(-1);
    }
}

void syscall_init(void) {
    lock_init(&filesys_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f) {
    int *esp_ptr = f->esp;

    switch (*(uint32_t *)(f->esp)) {
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            is_valid_address(f->esp + 4);
            exit(*(uint32_t *)(f->esp + 4));
            break;
        case SYS_EXEC:
            is_valid_address(f->esp + 4);
            f->eax = exec((const char *)*(uint32_t *)(f->esp + 4));
            break;
        case SYS_WAIT:
            is_valid_address(f->esp + 4);
            f->eax = wait((pid_t) * (uint32_t *)(f->esp + 4));
            break;
        case SYS_CREATE:
            is_valid_address(f->esp + 4);
            is_valid_address(f->esp + 8);
            f->eax = create((const char *)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
            break;
        case SYS_REMOVE:
            is_valid_address(f->esp + 4);
            f->eax = remove((const char *)*(uint32_t *)(f->esp + 4));
            break;
        case SYS_OPEN:
            is_valid_address(f->esp + 4);
            f->eax = open((const char *)*(uint32_t *)(f->esp + 4));
            break;
        case SYS_FILESIZE:
            is_valid_address(f->esp + 4);
            f->eax = filesize((int)*(uint32_t *)(f->esp + 4));
            break;
        case SYS_READ:
            is_valid_address(f->esp + 4);
            is_valid_address(f->esp + 8);
            is_valid_address(f->esp + 12);
            f->eax = read((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
            break;
        case SYS_WRITE:
            is_valid_address(f->esp + 4);
            is_valid_address(f->esp + 8);
            is_valid_address(f->esp + 12);
            f->eax = write((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
            break;
        case SYS_SEEK:
            is_valid_address(f->esp + 4);
            is_valid_address(f->esp + 8);
            seek((int)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
            break;
        case SYS_TELL:
            is_valid_address(f->esp + 4);
            f->eax = tell((int)*(uint32_t *)(f->esp + 4));
            break;
        case SYS_CLOSE:
            is_valid_address(f->esp + 4);
            close((int)*(uint32_t *)(f->esp + 4));
            break;
        default:
            printf("Default %d\n", *esp_ptr);
    }

    //thread_exit();
}

void halt(void) {
    shutdown_power_off();
}

void exit(int status) {
    int i;
    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_current()->exit_status = status;
    for (i = 3; i < 128; i++) {
        if (thread_current()->fd[i] != NULL) {
            close(i);
        }
    }
    thread_exit();
}

pid_t exec(const char *cmd_line) {
    return process_execute(cmd_line);
}

int wait(pid_t pid) {
    return process_wait(pid);
}

bool create(const char *file, unsigned initial_size) {
    if (file == NULL) {
        exit(-1);
    }
    is_valid_address(file);
    return filesys_create(file, initial_size);
}

bool remove(const char *file) {
    if (file == NULL) {
        exit(-1);
    }
    is_valid_address(file);
    return filesys_remove(file);
}

int open(const char *file) {
    int i;
    struct file *fp;

    if (file == NULL) {
        exit(-1);
    }
    is_valid_address(file);
    lock_acquire(&filesys_lock);

    int ret = -1;
    fp = filesys_open(file);

    if (fp == NULL) {
        ret = -1;
    } else {
        for (i = 3; i < 128; i++) {
            if (thread_current()->fd[i] == NULL) {
                if (strcmp(thread_current()->name, file) == 0) {
                    file_deny_write(fp);
                }
                thread_current()->fd[i] = fp;
                ret = i;
                break;
            }
        }
    }
    lock_release(&filesys_lock);
    return ret;
}

int filesize(int fd) {
    if (thread_current()->fd[fd] == NULL) {
        exit(-1);
    }
    return file_length(thread_current()->fd[fd]);
}

int read(int fd, void *buffer, unsigned size) {
    int i;
    int ret;
    is_valid_address(buffer);
    lock_acquire(&filesys_lock);

    if (fd == 0) {
        for (i = 0; i < size; i++) {
            if (((char *)buffer)[i] == '\0') {
                break;
            }
        }
        ret = i;
    } else if (fd > 2) {
        if (thread_current()->fd[fd] == NULL) {
            exit(-1);
        }
        ret = file_read(thread_current()->fd[fd], buffer, size);
    }
    lock_release(&filesys_lock);
    return ret;
}

int write(int fd, const void *buffer, unsigned size) {
    is_valid_address(buffer);
    lock_acquire(&filesys_lock);

    if (fd == 1) {
        putbuf(buffer, size);
        lock_release(&filesys_lock);
        return size;
    } else if (fd > 2) {
        if (thread_current()->fd[fd] == NULL) {
            lock_release(&filesys_lock);
            exit(-1);
        }
        if (thread_current()->fd[fd]->deny_write) {
            file_deny_write(thread_current()->fd[fd]);
        }

        lock_release(&filesys_lock);
        return file_write(thread_current()->fd[fd], buffer, size);
    }
    lock_release(&filesys_lock);
    return -1;
}

void seek(int fd, unsigned position) {
    if (thread_current()->fd[fd] == NULL) {
        exit(-1);
    }

    file_seek(thread_current()->fd[fd], position);
}

unsigned tell(int fd) {
    if (thread_current()->fd[fd] == NULL) {
        exit(-1);
    }

    return file_tell(thread_current()->fd[fd]);
}

void close(int fd) {
    struct file *fp;

    if (thread_current()->fd[fd] == NULL) {
        exit(-1);
    }

    fp = thread_current()->fd[fd];
    thread_current()->fd[fd] = NULL;

    return file_close(fp);
}