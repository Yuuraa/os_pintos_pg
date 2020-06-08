#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

static void syscall_handler(struct intr_frame *);
void halt(void);
void exit(int);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void halt(void);
void is_valid_address(const void *);

struct proc_file {
    struct file *ptr;
    int fd;
    struct list_elem elem;
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
            break;
        case SYS_REMOVE:
            break;
        case SYS_OPEN:
            break;
        case SYS_FILESIZE:
            break;
        case SYS_READ:
            is_valid_address(f->esp + 4);
            is_valid_address(f->esp + 8);
            is_valid_address(f->esp + 12);
            f->eax = read((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
            break;
        case SYS_WRITE:
            f->eax = write((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
            break;
        case SYS_SEEK:
            break;
        case SYS_TELL:
            break;
        case SYS_CLOSE:
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
    //Terminate child process
    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_current()->exit_status = status;
    thread_exit();
}

pid_t exec(const char *cmd_line) {
    return process_execute(cmd_line);
}

int wait(pid_t pid) {
    return process_wait(pid);
}

int read(int fd, void *buffer, unsigned size) {
    int i;
    if (fd == 0) {
        for (i = 0; i < size; i++) {
            if (((char *)buffer)[i] == '\0') {
                break;
            }
        }
    }
    return i;
}

int write(int fd, const void *buffer, unsigned size) {
    if (fd == 1) {
        putbuf(buffer, size);
        return size;
    }
    return -1;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
// It's from manual 3.1.5
static int
get_user(const uint8_t *uaddr) {
    int result;
    asm("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a"(result)
        : "m"(*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
// It's from manual 3.1.5
static bool
put_user(uint8_t *udst, uint8_t byte) {
    int error_code;
    asm("movl $1f, %0; movb %b2, %1; 1:"
        : "=&a"(error_code), "=m"(*udst)
        : "q"(byte));
    return error_code != -1;
}