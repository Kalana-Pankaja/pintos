#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "filesys/file.h"

/* File descriptor structure. */
struct file_descriptor
  {
    int fd;                     /* File descriptor number. */
    struct file *file;          /* File pointer. */
    struct list_elem elem;      /* List element. */
  };

void syscall_init (void);
void syscall_exit (int status);

#endif /* userprog/syscall.h */
