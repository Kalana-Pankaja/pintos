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
static struct lock file_lock;

// user memory functions
static int get_user (const uint8_t *addr);
static bool put_user (uint8_t *dst, uint8_t byte);
static bool check_ptr (const void *ptr);
static bool check_str (const char *str);
static bool check_buf (const void *buffer, unsigned size);
static bool read_int (int *dst, const int *src);
static bool read_ptr (void **dst, const void **src);

// syscalls
static void sys_halt (void);
static void sys_exit (int status);
static pid_t sys_exec (const char *cmd);
static int sys_wait (pid_t pid);
static bool sys_create (const char *file, unsigned size);
static bool sys_remove (const char *file);
static int sys_open (const char *file);
static int sys_filesize (int fd);
static int sys_read (int fd, void *buffer, unsigned size);
static int sys_write (int fd, const void *buffer, unsigned size);
static void sys_seek (int fd, unsigned pos);
static unsigned sys_tell (int fd);
static void sys_close (int fd);

// helper
static struct file_descriptor *get_fd (int fd);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
}

// read byte from user memory
static int
get_user (const uint8_t *addr)
{
  if (!is_user_vaddr (addr))
    return -1;
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*addr));
  return result;
}

// write byte to user memory
static bool
put_user (uint8_t *dst, uint8_t byte)
{
  if (!is_user_vaddr (dst))
    return false;
  int error;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error), "=m" (*dst) : "q" (byte));
  return error != -1;
}

// check if pointer is valid
static bool
check_ptr (const void *ptr)
{
  if (ptr == NULL || !is_user_vaddr (ptr))
    return false;
  return get_user ((const uint8_t *) ptr) != -1;
}

// read int from user space
static bool
read_int (int *dst, const int *src)
{
  const uint8_t *bytes = (const uint8_t *) src;
  int i;

  for (i = 0; i < 4; i++)
    {
      if (!is_user_vaddr (bytes + i))
        return false;
    }

  uint8_t buf[4];
  for (i = 0; i < 4; i++)
    {
      int byte = get_user (bytes + i);
      if (byte == -1)
        return false;
      buf[i] = (uint8_t) byte;
    }

  *dst = *((int *) buf);
  return true;
}

// read pointer from user space
static bool
read_ptr (void **dst, const void **src)
{
  return read_int ((int *) dst, (const int *) src);
}

// check if string is valid
static bool
check_str (const char *str)
{
  if (!is_user_vaddr (str))
    return false;

  int ch;
  const char *p = str;

  while (true)
    {
      if (!is_user_vaddr (p))
        return false;

      ch = get_user ((const uint8_t *) p);
      if (ch == -1)
        return false;

      if (ch == '\0')
        break;

      p++;

      if (p - str > PGSIZE)
        return false;
    }

  return true;
}

// check if buffer is valid
static bool
check_buf (const void *buffer, unsigned size)
{
  if (buffer == NULL)
    return false;

  const uint8_t *buf = buffer;
  unsigned i;

  if ((uintptr_t) buf + size < (uintptr_t) buf)
    return false;

  if (!is_user_vaddr (buf) || !is_user_vaddr (buf + size - 1))
    return false;

  if (get_user (buf) == -1)
    return false;

  if (size > 0 && get_user (buf + size - 1) == -1)
    return false;

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

// syscall handler
static void
syscall_handler (struct intr_frame *f)
{
  int *esp = f->esp;
  int num;
  int arg1, arg2, arg3;
  void *ptr;

  // check stack pointer
  if (!is_user_vaddr (esp) || !is_user_vaddr ((uint8_t *) esp + 3))
    {
      sys_exit (-1);
      return;
    }

  // read syscall number
  if (!read_int (&num, esp))
    {
      sys_exit (-1);
      return;
    }

  switch (num)
    {
    case SYS_HALT:
      sys_halt ();
      break;

    case SYS_EXIT:
      if (!read_int (&arg1, esp + 1))
        sys_exit (-1);
      else
        sys_exit (arg1);
      break;

    case SYS_EXEC:
      if (!read_ptr (&ptr, (void **) (esp + 1)))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      if (!check_str ((const char *) ptr))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_exec ((const char *) ptr);
      break;

    case SYS_WAIT:
      if (!read_int (&arg1, esp + 1))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_wait (arg1);
      break;

    case SYS_CREATE:
      if (!read_ptr (&ptr, (void **) (esp + 1)) ||
          !read_int (&arg2, esp + 2))
        {
          f->eax = 0;
          sys_exit (-1);
          break;
        }
      if (!check_str ((const char *) ptr))
        {
          f->eax = 0;
          sys_exit (-1);
          break;
        }
      f->eax = sys_create ((const char *) ptr, arg2);
      break;

    case SYS_REMOVE:
      if (!read_ptr (&ptr, (void **) (esp + 1)))
        {
          f->eax = 0;
          sys_exit (-1);
          break;
        }
      if (!check_str ((const char *) ptr))
        {
          f->eax = 0;
          sys_exit (-1);
          break;
        }
      f->eax = sys_remove ((const char *) ptr);
      break;

    case SYS_OPEN:
      if (!read_ptr (&ptr, (void **) (esp + 1)))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      if (!check_str ((const char *) ptr))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_open ((const char *) ptr);
      break;

    case SYS_FILESIZE:
      if (!read_int (&arg1, esp + 1))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_filesize (arg1);
      break;

    case SYS_READ:
      if (!read_int (&arg1, esp + 1) ||
          !read_ptr (&ptr, (void **) (esp + 2)) ||
          !read_int (&arg3, esp + 3))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      if (!check_buf (ptr, arg3))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_read (arg1, ptr, arg3);
      break;

    case SYS_WRITE:
      if (!read_int (&arg1, esp + 1) ||
          !read_ptr (&ptr, (void **) (esp + 2)) ||
          !read_int (&arg3, esp + 3))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      if (!check_buf (ptr, arg3))
        {
          f->eax = -1;
          sys_exit (-1);
          break;
        }
      f->eax = sys_write (arg1, ptr, arg3);
      break;

    case SYS_SEEK:
      if (!read_int (&arg1, esp + 1) ||
          !read_int (&arg2, esp + 2))
        sys_exit (-1);
      else
        sys_seek (arg1, arg2);
      break;

    case SYS_TELL:
      if (!read_int (&arg1, esp + 1))
        {
          f->eax = 0;
          sys_exit (-1);
          break;
        }
      f->eax = sys_tell (arg1);
      break;

    case SYS_CLOSE:
      if (!read_int (&arg1, esp + 1))
        sys_exit (-1);
      else
        sys_close (arg1);
      break;

    default:
      printf ("Unknown system call: %d\n", num);
      sys_exit (-1);
      break;
    }
}

static void
sys_halt (void)
{
  shutdown_power_off ();
}

static void
sys_exit (int status)
{
  struct thread *t = thread_current ();
  t->exit_status = status;
  thread_exit ();
}

static pid_t
sys_exec (const char *cmd)
{
  pid_t pid = process_execute (cmd);
  return pid;
}

static int
sys_wait (pid_t pid)
{
  return process_wait (pid);
}

static bool
sys_create (const char *file, unsigned size)
{
  if (file == NULL || strlen (file) == 0)
    sys_exit (-1);

  lock_acquire (&file_lock);
  bool ok = filesys_create (file, size);
  lock_release (&file_lock);
  return ok;
}

static bool
sys_remove (const char *file)
{
  if (file == NULL)
    sys_exit (-1);

  lock_acquire (&file_lock);
  bool ok = filesys_remove (file);
  lock_release (&file_lock);
  return ok;
}

static int
sys_open (const char *file)
{
  if (file == NULL || strlen (file) == 0)
    return -1;

  lock_acquire (&file_lock);
  struct file *f = filesys_open (file);
  lock_release (&file_lock);

  if (f == NULL)
    return -1;

  struct thread *t = thread_current ();
  struct file_descriptor *fd_elem = palloc_get_page (0);
  if (fd_elem == NULL)
    {
      file_close (f);
      return -1;
    }

  fd_elem->fd = t->next_fd++;
  fd_elem->file = f;
  list_push_back (&t->file_list, &fd_elem->elem);

  return fd_elem->fd;
}

// get file descriptor
static struct file_descriptor *
get_fd (int fd)
{
  struct thread *t = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&t->file_list); e != list_end (&t->file_list);
       e = list_next (e))
    {
      struct file_descriptor *f = list_entry (e, struct file_descriptor, elem);
      if (f->fd == fd)
        return f;
    }
  return NULL;
}

static int
sys_filesize (int fd)
{
  struct file_descriptor *f = get_fd (fd);
  if (f == NULL)
    return -1;

  lock_acquire (&file_lock);
  int size = file_length (f->file);
  lock_release (&file_lock);
  return size;
}

static int
sys_read (int fd, void *buffer, unsigned size)
{
  if (fd == 0)
    {
      unsigned i;
      uint8_t *buf = buffer;
      for (i = 0; i < size; i++)
        buf[i] = input_getc ();
      return size;
    }

  struct file_descriptor *f = get_fd (fd);
  if (f == NULL)
    return -1;

  lock_acquire (&file_lock);
  int bytes = file_read (f->file, buffer, size);
  lock_release (&file_lock);
  return bytes;
}

static int
sys_write (int fd, const void *buffer, unsigned size)
{
  if (fd == 1)
    {
      putbuf (buffer, size);
      return size;
    }

  struct file_descriptor *f = get_fd (fd);
  if (f == NULL)
    return -1;

  lock_acquire (&file_lock);
  int bytes = file_write (f->file, buffer, size);
  lock_release (&file_lock);
  return bytes;
}

static void
sys_seek (int fd, unsigned pos)
{
  struct file_descriptor *f = get_fd (fd);
  if (f == NULL)
    return;

  lock_acquire (&file_lock);
  file_seek (f->file, pos);
  lock_release (&file_lock);
}

static unsigned
sys_tell (int fd)
{
  struct file_descriptor *f = get_fd (fd);
  if (f == NULL)
    return 0;

  lock_acquire (&file_lock);
  unsigned pos = file_tell (f->file);
  lock_release (&file_lock);
  return pos;
}

static void
sys_close (int fd)
{
  struct file_descriptor *f = get_fd (fd);
  if (f == NULL)
    return;

  lock_acquire (&file_lock);
  file_close (f->file);
  lock_release (&file_lock);

  list_remove (&f->elem);
  palloc_free_page (f);
}

/* Public exit function for use by exception handler. */
void
syscall_exit (int status)
{
  sys_exit (status);
}