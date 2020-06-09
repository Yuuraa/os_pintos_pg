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

/* Syscall list*/
// My implementations for Problem 3: System Calls
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
/* Syscall list*/

// My function to check if the address is vaildwr
void is_valid_address(const void *);

//Ref. from filesys/file.c
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
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f) {
    // Check the esp. Inside the switch statement
    is_valid_address(f->esp);

    // should check the address with proper argument number
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
            printf("Default %d\n", *(uint32_t *)(f->esp));
    }
    // Original code
    // thread_exit();
}

/* My implementation for Syscall list*/
// Terminates Pintos by calling shutdown_power_off() in devices/shutdown.h
void halt(void) {
    shutdown_power_off();
}

// Terminates the current user program, returning status to the kernel
void exit(int status) {
    // My Implementation for Problem 1: Process termination message
    printf("%s: exit(%d)\n", thread_current()->name, status);

    int i;
    thread_current()->exit_status = status;

    //close files
    for (i = 3; i < 128; i++) {
        if (thread_current()->fd[i] != NULL) {
            close(i);
        }
    }
    thread_exit();
}

// Runs the executable whose name is given in cmd_line, passing given arguments, returning the new process's pid
pid_t exec(const char *cmd_line) {
    return process_execute(cmd_line);
}

// Waits for a child process pid and retrieves the child's exit status
int wait(pid_t pid) {
    return process_wait(pid);
}

// Creates new file with initial_size, returns true if successful false otherwise
bool create(const char *file, unsigned initial_size) {
    if (file == NULL) {
        exit(-1);
    }
    is_valid_address(file);
    return filesys_create(file, initial_size);
}

// Deletes the file named file
bool remove(const char *file) {
    if (file == NULL) {
        exit(-1);
    }
    is_valid_address(file);
    return filesys_remove(file);
}

// Opens the file called file
int open(const char *file) {
    int i;
    struct file *fp;

    if (file == NULL) {
        exit(-1);
    }
    is_valid_address(file);

    // Protect the file system while opening the file

    int ret = -1;
    fp = filesys_open(file);

    if (fp == NULL) {
        return -1;  // Returns -1 if the file cannot be opened
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
    return ret;
}

// Returns the size of the file in bytes, open as fd
int filesize(int fd) {
    if (thread_current()->fd[fd] == NULL) {
        exit(-1);
    }
    return file_length(thread_current()->fd[fd]);
}

// Reads size bytes from the file open as fd into buffer
int read(int fd, void *buffer, unsigned size) {
    int i;
    is_valid_address(buffer);

    if (fd == 0) {
        for (i = 0; i < size; i++) {
            if (((char *)buffer)[i] == '\0') {
                break;
            }
        }
        return i;
    } else if (fd > 2) {
        if (thread_current()->fd[fd] == NULL) {
            exit(-1);
        }
        return file_read(thread_current()->fd[fd], buffer, size);
    }
    return -1;
}

// Writes size bytes from buffer to the open file fd
int write(int fd, const void *buffer, unsigned size) {
    is_valid_address(buffer);

    // Standard output
    if (fd == 1) {
        putbuf(buffer, size);
        return size;
    } else if (fd > 2) {
        if (thread_current()->fd[fd] == NULL) {
            exit(-1);
        }
        if (thread_current()->fd[fd]->deny_write) {
            file_deny_write(thread_current()->fd[fd]);
        }
        return file_write(thread_current()->fd[fd], buffer, size);
    }
    return -1;
}

// Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file
void seek(int fd, unsigned position) {
    if (thread_current()->fd[fd] == NULL) {
        exit(-1);
    }

    file_seek(thread_current()->fd[fd], position);
}

// Returns the positoin of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file
unsigned tell(int fd) {
    if (thread_current()->fd[fd] == NULL) {
        exit(-1);
    }

    return file_tell(thread_current()->fd[fd]);
}

// Closes the file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one.
void close(int fd) {
    struct file *fp;

    if (thread_current()->fd[fd] == NULL) {
        exit(-1);
    }

    fp = thread_current()->fd[fd];
    thread_current()->fd[fd] = NULL;

    return file_close(fp);
}