#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

typedef int pid_t;

static void syscall_handler (struct intr_frame *);
static struct lock filesys_lock;

/* User memory access functions. */
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static bool is_valid_pointer (const void *ptr);
static bool is_valid_string (const char *str);
static bool is_valid_buffer (const void *buffer, unsigned size);

/* System call implementations. */
static void sys_halt (void);
static void sys_exit (int status);
static pid_t sys_exec (const char *cmd_line);
static int sys_wait (pid_t pid);
static bool sys_create (const char *file, unsigned initial_size);
static bool sys_remove (const char *file);
static int sys_open (const char *file);
static int sys_filesize (int fd);
static int sys_read (int fd, void *buffer, unsigned size);
static int sys_write (int fd, const void *buffer, unsigned size);
static void sys_seek (int fd, unsigned position);
static unsigned sys_tell (int fd);
static void sys_close (int fd);

/* File descriptor helpers. */
static struct file_descriptor *get_file_descriptor (int fd);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
}

/* Reads a byte at user virtual address UADDR.
   Returns the byte value if successful, -1 if a segfault occurred. */
static int
get_user (const uint8_t *uaddr)
{
  if (!is_user_vaddr (uaddr))
    return -1;
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  if (!is_user_vaddr (udst))
    return false;
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* Verifies that a pointer is valid. */
static bool
is_valid_pointer (const void *ptr)
{
  if (ptr == NULL || !is_user_vaddr (ptr))
    return false;
  return get_user ((const uint8_t *) ptr) != -1;
}

/* Verifies that a string is valid. */
static bool
is_valid_string (const char *str)
{
  if (!is_valid_pointer (str))
    return false;

  int ch;
  while ((ch = get_user ((const uint8_t *) str)) != -1 && ch != '\0')
    str++;

  return ch != -1;
}

/* Verifies that a buffer is valid. */
static bool
is_valid_buffer (const void *buffer, unsigned size)
{
  if (buffer == NULL)
    return false;

  const uint8_t *buf = buffer;
  unsigned i;
  for (i = 0; i < size; i++)
    {
      if (!is_valid_pointer (buf + i))
        return false;
    }
  return true;
}

/* System call handler. */
static void
syscall_handler (struct intr_frame *f)
{
  int *esp = f->esp;

  /* Verify stack pointer. */
  if (!is_valid_pointer (esp))
    {
      sys_exit (-1);
      return;
    }

  int syscall_number = *esp;

  switch (syscall_number)
    {
    case SYS_HALT:
      sys_halt ();
      break;

    case SYS_EXIT:
      if (!is_valid_pointer (esp + 1))
        sys_exit (-1);
      sys_exit (*(esp + 1));
      break;

    case SYS_EXEC:
      if (!is_valid_pointer (esp + 1))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      if (!is_valid_string ((const char *) *(esp + 1)))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_exec ((const char *) *(esp + 1));
      break;

    case SYS_WAIT:
      if (!is_valid_pointer (esp + 1))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_wait (*(esp + 1));
      break;

    case SYS_CREATE:
      if (!is_valid_pointer (esp + 1) || !is_valid_pointer (esp + 2))
        {
          f->eax = 0;
          sys_exit (-1);
          break;
        }
      if (!is_valid_string ((const char *) *(esp + 1)))
        {
          f->eax = 0;
          sys_exit (-1);
          break;
        }
      f->eax = sys_create ((const char *) *(esp + 1), *(esp + 2));
      break;

    case SYS_REMOVE:
      if (!is_valid_pointer (esp + 1))
        {
          f->eax = 0;
          sys_exit (-1);
          break;
        }
      if (!is_valid_string ((const char *) *(esp + 1)))
        {
          f->eax = 0;
          sys_exit (-1);
          break;
        }
      f->eax = sys_remove ((const char *) *(esp + 1));
      break;

    case SYS_OPEN:
      if (!is_valid_pointer (esp + 1))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      if (!is_valid_string ((const char *) *(esp + 1)))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_open ((const char *) *(esp + 1));
      break;

    case SYS_FILESIZE:
      if (!is_valid_pointer (esp + 1))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_filesize (*(esp + 1));
      break;

    case SYS_READ:
      if (!is_valid_pointer (esp + 1) || !is_valid_pointer (esp + 2) ||
          !is_valid_pointer (esp + 3))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      if (!is_valid_buffer ((void *) *(esp + 2), *(esp + 3)))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_read (*(esp + 1), (void *) *(esp + 2), *(esp + 3));
      break;

    case SYS_WRITE:
      if (!is_valid_pointer (esp + 1) || !is_valid_pointer (esp + 2) ||
          !is_valid_pointer (esp + 3))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      if (!is_valid_buffer ((const void *) *(esp + 2), *(esp + 3)))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_write (*(esp + 1), (const void *) *(esp + 2), *(esp + 3));
      break;

    case SYS_SEEK:
      if (!is_valid_pointer (esp + 1) || !is_valid_pointer (esp + 2))
        sys_exit (-1);
      sys_seek (*(esp + 1), *(esp + 2));
      break;

    case SYS_TELL:
      if (!is_valid_pointer (esp + 1))
        {
          f->eax = 0;
          sys_exit (-1);
          break;
        }
      f->eax = sys_tell (*(esp + 1));
      break;

    case SYS_CLOSE:
      if (!is_valid_pointer (esp + 1))
        sys_exit (-1);
      sys_close (*(esp + 1));
      break;

    default:
      printf ("Unknown system call: %d\n", syscall_number);
      sys_exit (-1);
      break;
    }
}

/* Halt system call. */
static void
sys_halt (void)
{
  shutdown_power_off ();
}

/* Exit system call. */
static void
sys_exit (int status)
{
  struct thread *cur = thread_current ();
  cur->exit_status = status;
  thread_exit ();
}

/* Exec system call. */
static pid_t
sys_exec (const char *cmd_line)
{
  pid_t pid = process_execute (cmd_line);
  return pid;
}

/* Wait system call. */
static int
sys_wait (pid_t pid)
{
  return process_wait (pid);
}

/* Create system call. */
static bool
sys_create (const char *file, unsigned initial_size)
{
  if (file == NULL || strlen (file) == 0)
    sys_exit (-1);

  lock_acquire (&filesys_lock);
  bool success = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  return success;
}

/* Remove system call. */
static bool
sys_remove (const char *file)
{
  if (file == NULL)
    sys_exit (-1);

  lock_acquire (&filesys_lock);
  bool success = filesys_remove (file);
  lock_release (&filesys_lock);
  return success;
}

/* Open system call. */
static int
sys_open (const char *file)
{
  if (file == NULL || strlen (file) == 0)
    return -1;

  lock_acquire (&filesys_lock);
  struct file *f = filesys_open (file);
  lock_release (&filesys_lock);

  if (f == NULL)
    return -1;

  struct thread *cur = thread_current ();
  struct file_descriptor *fd_elem = palloc_get_page (0);
  if (fd_elem == NULL)
    {
      file_close (f);
      return -1;
    }

  fd_elem->fd = cur->next_fd++;
  fd_elem->file = f;
  list_push_back (&cur->file_list, &fd_elem->elem);

  return fd_elem->fd;
}

/* Get file descriptor from list. */
static struct file_descriptor *
get_file_descriptor (int fd)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&cur->file_list); e != list_end (&cur->file_list);
       e = list_next (e))
    {
      struct file_descriptor *fd_elem = list_entry (e, struct file_descriptor, elem);
      if (fd_elem->fd == fd)
        return fd_elem;
    }
  return NULL;
}

/* Filesize system call. */
static int
sys_filesize (int fd)
{
  struct file_descriptor *fd_elem = get_file_descriptor (fd);
  if (fd_elem == NULL)
    return -1;

  lock_acquire (&filesys_lock);
  int size = file_length (fd_elem->file);
  lock_release (&filesys_lock);
  return size;
}

/* Read system call. */
static int
sys_read (int fd, void *buffer, unsigned size)
{
  if (fd == 0)
    {
      /* Read from keyboard. */
      unsigned i;
      uint8_t *buf = buffer;
      for (i = 0; i < size; i++)
        buf[i] = input_getc ();
      return size;
    }

  struct file_descriptor *fd_elem = get_file_descriptor (fd);
  if (fd_elem == NULL)
    return -1;

  lock_acquire (&filesys_lock);
  int bytes_read = file_read (fd_elem->file, buffer, size);
  lock_release (&filesys_lock);
  return bytes_read;
}

/* Write system call. */
static int
sys_write (int fd, const void *buffer, unsigned size)
{
  if (fd == 1)
    {
      /* Write to console. */
      putbuf (buffer, size);
      return size;
    }

  struct file_descriptor *fd_elem = get_file_descriptor (fd);
  if (fd_elem == NULL)
    return -1;

  lock_acquire (&filesys_lock);
  int bytes_written = file_write (fd_elem->file, buffer, size);
  lock_release (&filesys_lock);
  return bytes_written;
}

/* Seek system call. */
static void
sys_seek (int fd, unsigned position)
{
  struct file_descriptor *fd_elem = get_file_descriptor (fd);
  if (fd_elem == NULL)
    return;

  lock_acquire (&filesys_lock);
  file_seek (fd_elem->file, position);
  lock_release (&filesys_lock);
}

/* Tell system call. */
static unsigned
sys_tell (int fd)
{
  struct file_descriptor *fd_elem = get_file_descriptor (fd);
  if (fd_elem == NULL)
    return 0;

  lock_acquire (&filesys_lock);
  unsigned position = file_tell (fd_elem->file);
  lock_release (&filesys_lock);
  return position;
}

/* Close system call. */
static void
sys_close (int fd)
{
  struct file_descriptor *fd_elem = get_file_descriptor (fd);
  if (fd_elem == NULL)
    return;

  lock_acquire (&filesys_lock);
  file_close (fd_elem->file);
  lock_release (&filesys_lock);

  list_remove (&fd_elem->elem);
  palloc_free_page (fd_elem);
}

/* Public exit function for use by exception handler. */
void
syscall_exit (int status)
{
  sys_exit (status);
}
