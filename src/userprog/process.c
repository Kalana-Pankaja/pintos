#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static bool setup_stack_with_args (void **esp, const char *file_name);

/* pass stuff to start_process */
struct args_struct
  {
    char *filename;
    struct child_info *info;
  };

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  char *copy;
  char *temp;
  char *name;
  tid_t tid;
  struct thread *t = thread_current ();
  struct child_info *child;
  struct args_struct *args;

  // make copy of file_name
  copy = palloc_get_page (0);
  if (copy == NULL)
    return TID_ERROR;
  strlcpy (copy, file_name, PGSIZE);

  // get program name
  name = palloc_get_page (0);
  if (name == NULL)
    {
      palloc_free_page (copy);
      return TID_ERROR;
    }
  strlcpy (name, file_name, PGSIZE);
  name = strtok_r (name, " ", &temp);

  // make child info
  child = malloc (sizeof (struct child_info));
  if (child == NULL)
    {
      palloc_free_page (copy);
      palloc_free_page (name);
      return TID_ERROR;
    }

  // setup child info
  child->tid = TID_ERROR;
  child->exit_status = -1;
  child->waited = false;
  child->exited = false;
  sema_init (&child->wait_sema, 0);
  sema_init (&child->load_sema, 0);
  child->load_success = false;

  // add child to list
  list_push_back (&t->children, &child->elem);

  // make args
  args = malloc (sizeof (struct args_struct));
  if (args == NULL)
    {
      list_remove (&child->elem);
      free (child);
      palloc_free_page (copy);
      palloc_free_page (name);
      return TID_ERROR;
    }
  args->filename = copy;
  args->info = child;

  // create thread
  tid = thread_create (name, PRI_DEFAULT, start_process, args);
  palloc_free_page (name);

  if (tid == TID_ERROR)
    {
      list_remove (&child->elem);
      free (child);
      free (args);
      palloc_free_page (copy);
      return TID_ERROR;
    }

  // save tid
  child->tid = tid;

  // wait for load
  sema_down (&child->load_sema);
  if (!child->load_success)
    return TID_ERROR;

  return tid;
}

// start user process
static void
start_process (void *args_)
{
  struct args_struct *args = args_;
  char *file_name = args->filename;
  struct child_info *child = args->info;
  struct intr_frame if_;
  bool success;
  struct thread *t = thread_current ();

  // link child info to thread
  t->proc_info = child;

  // free args
  free (args);

  // setup interrupt frame and load
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  // tell parent
  child->load_success = success;
  sema_up (&child->load_sema);

  // if failed quit
  palloc_free_page (file_name);
  if (!success)
    thread_exit ();

  // start process
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

// wait for child
int
process_wait (tid_t child_tid)
{
  struct thread *t = thread_current ();
  struct list_elem *e;
  struct child_info *child = NULL;

  // find child
  for (e = list_begin (&t->children); e != list_end (&t->children);
       e = list_next (e))
    {
      struct child_info *c = list_entry (e, struct child_info, elem);
      if (c->tid == child_tid)
        {
          child = c;
          break;
        }
    }

  // if not found or already waited
  if (child == NULL || child->waited)
    return -1;

  // mark waited
  child->waited = true;

  // wait for child
  if (!child->exited)
    sema_down (&child->wait_sema);

  // get status
  int status = child->exit_status;

  // cleanup
  list_remove (&child->elem);
  free (child);

  return status;
}

// cleanup process
void
process_exit (void)
{
  struct thread *t = thread_current ();
  uint32_t *pd;

  // close all files
  struct list_elem *e;
  while (!list_empty (&t->file_list))
    {
      e = list_pop_front (&t->file_list);
      struct file_descriptor *fd = list_entry (e, struct file_descriptor, elem);
      file_close (fd->file);
      palloc_free_page (fd);
    }

  // allow write to exe
  if (t->executable != NULL)
    {
      file_allow_write (t->executable);
      file_close (t->executable);
    }

  // tell parent
  if (t->proc_info != NULL)
    {
      t->proc_info->exit_status = t->exit_status;
      t->proc_info->exited = true;
      sema_up (&t->proc_info->wait_sema);
    }

  // free children
  while (!list_empty (&t->children))
    {
      e = list_pop_front (&t->children);
      struct child_info *c = list_entry (e, struct child_info, elem);
      free (c);
    }

  // print message
  printf ("%s: exit(%d)\n", t->name, t->exit_status);

  // cleanup page directory
  pd = t->pagedir;
  if (pd != NULL)
    {
      t->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t ofs;
  bool success = false;
  int i;
  char *name, *temp;

  // make page directory
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  // get program name
  name = palloc_get_page (0);
  if (name == NULL)
    goto done;
  strlcpy (name, file_name, PGSIZE);
  name = strtok_r (name, " ", &temp);

  // open file
  file = filesys_open (name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", name);
      palloc_free_page (name);
      goto done;
    }

  // deny writes
  file_deny_write (file);
  t->executable = file;

  // read header
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", name);
      palloc_free_page (name);
      goto done;
    }

  // read program headers
  ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (ofs < 0 || ofs > file_length (file))
        goto done;
      file_seek (file, ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool write = (phdr.p_flags & PF_W) != 0;
              uint32_t fpage = phdr.p_offset & ~PGMASK;
              uint32_t mpage = phdr.p_vaddr & ~PGMASK;
              uint32_t pofs = phdr.p_vaddr & PGMASK;
              uint32_t rbytes, zbytes;
              if (phdr.p_filesz > 0)
                {
                  rbytes = pofs + phdr.p_filesz;
                  zbytes = (ROUND_UP (pofs + phdr.p_memsz, PGSIZE)
                                - rbytes);
                }
              else
                {
                  rbytes = 0;
                  zbytes = ROUND_UP (pofs + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, fpage, (void *) mpage,
                                 rbytes, zbytes, write))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  // setup stack
  if (!setup_stack_with_args (esp, file_name))
    {
      palloc_free_page (name);
      goto done;
    }

  // set start address
  *eip = (void (*) (void)) ehdr.e_entry;

  palloc_free_page (name);
  success = true;

 done:
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      size_t pread = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t pzero = PGSIZE - pread;

      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      if (file_read (file, kpage, pread) != (int) pread)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + pread, 0, pzero);

      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      read_bytes -= pread;
      zero_bytes -= pzero;
      upage += PGSIZE;
    }
  return true;
}

// setup stack
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool ok = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      ok = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (ok)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return ok;
}

// setup stack with args
static bool
setup_stack_with_args (void **esp, const char *file_name)
{
  char *argv[128];
  int argc = 0;
  char *token, *temp;
  char *copy;
  int i;
  uint8_t *sp;

  // setup stack
  if (!setup_stack (esp))
    return false;

  // copy filename
  copy = palloc_get_page (0);
  if (copy == NULL)
    return false;
  strlcpy (copy, file_name, PGSIZE);

  // parse args
  for (token = strtok_r (copy, " ", &temp); token != NULL;
       token = strtok_r (NULL, " ", &temp))
    {
      if (argc >= 128)
        {
          palloc_free_page (copy);
          return false;
        }
      argv[argc++] = token;
    }

  sp = *esp;

  // push args
  char *arg_addrs[128];
  for (i = argc - 1; i >= 0; i--)
    {
      size_t len = strlen (argv[i]) + 1;
      sp -= len;
      memcpy (sp, argv[i], len);
      arg_addrs[i] = (char *) sp;
    }

  // align
  while ((uintptr_t) sp % 4 != 0)
    {
      sp--;
      *sp = 0;
    }

  // push null
  sp -= sizeof (char *);
  *((char **) sp) = NULL;

  // push arg pointers
  for (i = argc - 1; i >= 0; i--)
    {
      sp -= sizeof (char *);
      *((char **) sp) = arg_addrs[i];
    }

  // push argv
  char **argv_ptr = (char **) sp;
  sp -= sizeof (char **);
  *((char ***) sp) = argv_ptr;

  // push argc
  sp -= sizeof (int);
  *((int *) sp) = argc;

  // push return address
  sp -= sizeof (void *);
  *((void **) sp) = NULL;

  *esp = sp;
  palloc_free_page (copy);

  return true;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
