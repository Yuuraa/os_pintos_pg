#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
void exit(int);  // add syscall exit
int write(int, const void *, unsigned);

#endif /* userprog/syscall.h */
