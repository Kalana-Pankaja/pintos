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
static bool safe_read_int (int *dst, const int *src);
static bool safe_read_pointer (void **dst, const void **src);

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

/* Safely reads an integer from user space. */
static bool
safe_read_int (int *dst, const int *src)
{
  /* Check all 4 bytes of the integer */
  const uint8_t *bytes = (const uint8_t *) src;
  int i;
  
  for (i = 0; i < 4; i++)
    {
      if (!is_user_vaddr (bytes + i))
        return false;
    }
  
  /* Read each byte using get_user */
  uint8_t result_bytes[4];
  for (i = 0; i < 4; i++)
    {
      int byte = get_user (bytes + i);
      if (byte == -1)
        return false;
      result_bytes[i] = (uint8_t) byte;
    }
  
  /* Reconstruct the integer */
  *dst = *((int *) result_bytes);
  return true;
}

/* Safely reads a pointer from user space. */
static bool
safe_read_pointer (void **dst, const void **src)
{
  return safe_read_int ((int *) dst, (const int *) src);
}

/* Verifies that a string is valid. */
static bool
is_valid_string (const char *str)
{
  if (!is_user_vaddr (str))
    return false;

  int ch;
  const char *ptr = str;
  
  /* Check each character until null terminator */
  while (true)
    {
      /* Check if this address is in user space */
      if (!is_user_vaddr (ptr))
        return false;
      
      /* Safely read the byte */
      ch = get_user ((const uint8_t *) ptr);
      if (ch == -1)
        return false;
      
      if (ch == '\0')
        break;
      
      ptr++;
      
      /* Prevent infinite loops on very long strings */
      if (ptr - str > PGSIZE)
        return false;
    }

  return true;
}

/* Verifies that a buffer is valid. */
static bool
is_valid_buffer (const void *buffer, unsigned size)
{
  if (buffer == NULL)
    return false;

  const uint8_t *buf = buffer;
  unsigned i;
  
  /* Check for overflow: if buffer + size wraps around, it's invalid */
  if ((uintptr_t) buf + size < (uintptr_t) buf)
    return false;
  
  /* Check that the entire range is in user space */
  if (!is_user_vaddr (buf) || !is_user_vaddr (buf + size - 1))
    return false;
  
  /* Verify we can actually read the buffer by checking first and last byte,
     and a few bytes in between for efficiency */
  if (get_user (buf) == -1)
    return false;
  
  if (size > 0 && get_user (buf + size - 1) == -1)
    return false;
  
  /* For larger buffers, check a few more spots */
  if (size > PGSIZE)
    {
      for (i = PGSIZE; i < size; i += PGSIZE)
        {
          if (get_user (buf + i) == -1)
            return false;
        }
    }
  
  return true;
}

/* System call handler. */
static void
syscall_handler (struct intr_frame *f)
{
  int *esp = f->esp;
  int syscall_number;
  int arg1, arg2, arg3;
  void *ptr_arg;

  /* Verify stack pointer is valid and in user space */
  if (!is_user_vaddr (esp) || !is_user_vaddr ((uint8_t *) esp + 3))
    {
      sys_exit (-1);
      return;
    }

  /* Safely read the syscall number */
  if (!safe_read_int (&syscall_number, esp))
    {
      sys_exit (-1);
      return;
    }

  switch (syscall_number)
    {
    case SYS_HALT:
      sys_halt ();
      break;

    case SYS_EXIT:
      if (!safe_read_int (&arg1, esp + 1))
        sys_exit (-1);
      else
        sys_exit (arg1);
      break;

    case SYS_EXEC:
      if (!safe_read_pointer (&ptr_arg, (void **) (esp + 1)))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      if (!is_valid_string ((const char *) ptr_arg))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_exec ((const char *) ptr_arg);
      break;

    case SYS_WAIT:
      if (!safe_read_int (&arg1, esp + 1))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_wait (arg1);
      break;

    case SYS_CREATE:
      if (!safe_read_pointer (&ptr_arg, (void **) (esp + 1)) ||
          !safe_read_int (&arg2, esp + 2))
        {
          f->eax = 0;
          sys_exit (-1);
          break;
        }
      if (!is_valid_string ((const char *) ptr_arg))
        {
          f->eax = 0;
          sys_exit (-1);
          break;
        }
      f->eax = sys_create ((const char *) ptr_arg, arg2);
      break;

    case SYS_REMOVE:
      if (!safe_read_pointer (&ptr_arg, (void **) (esp + 1)))
        {
          f->eax = 0;
          sys_exit (-1);
          break;
        }
      if (!is_valid_string ((const char *) ptr_arg))
        {
          f->eax = 0;
          sys_exit (-1);
          break;
        }
      f->eax = sys_remove ((const char *) ptr_arg);
      break;

    case SYS_OPEN:
      if (!safe_read_pointer (&ptr_arg, (void **) (esp + 1)))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      if (!is_valid_string ((const char *) ptr_arg))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_open ((const char *) ptr_arg);
      break;

    case SYS_FILESIZE:
      if (!safe_read_int (&arg1, esp + 1))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_filesize (arg1);
      break;

    case SYS_READ:
      if (!safe_read_int (&arg1, esp + 1) ||
          !safe_read_pointer (&ptr_arg, (void **) (esp + 2)) ||
          !safe_read_int (&arg3, esp + 3))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      if (!is_valid_buffer (ptr_arg, arg3))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_read (arg1, ptr_arg, arg3);
      break;

    case SYS_WRITE:
      if (!safe_read_int (&arg1, esp + 1) ||
          !safe_read_pointer (&ptr_arg, (void **) (esp + 2)) ||
          !safe_read_int (&arg3, esp + 3))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      if (!is_valid_buffer (ptr_arg, arg3))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_write (arg1, ptr_arg, arg3);
      break;

    case SYS_SEEK:
      if (!safe_read_int (&arg1, esp + 1) ||
          !safe_read_int (&arg2, esp + 2))
        sys_exit (-1);
      else
        sys_seek (arg1, arg2);
      break;

    case SYS_TELL:
      if (!safe_read_int (&arg1, esp + 1))
        {
          f->eax = 0;
          sys_exit (-1);
          break;
        }
      f->eax = sys_tell (arg1);
      break;

    case SYS_CLOSE:
      if (!safe_read_int (&arg1, esp + 1))
        sys_exit (-1);
      else
        sys_close (arg1);
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