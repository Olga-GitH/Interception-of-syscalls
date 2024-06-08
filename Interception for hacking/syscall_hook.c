#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
 
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/slab.h>
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Meshkova Olga");
MODULE_DESCRIPTION("A Linux Kernel Module to hook and proxy system calls using kprobes");
 
// Prototypes for the original system calls
static asmlinkage ssize_t (*original_sys_write)(unsigned int, const char __user *, size_t);
static asmlinkage ssize_t (*original_sys_read)(unsigned int, const char __user *, size_t);
 
// Call counters
static int nreads = 0, nwrites = 0;
 
// File path from the file descriptor
static char *get_file_path_from_fd(unsigned int fd) {
    struct file *file;
    struct path *path;
    char *buf = (char *)kmalloc(GFP_KERNEL, PATH_MAX);
    char *file_path = NULL;
    if (!buf) {return NULL;}
 
    file = fget(fd);
    if (file) {
        path = &file->f_path;
        path_get(path);
        file_path = d_path(path, buf, PATH_MAX);
        path_put(path);
        fput(file);
    }
    return file_path;
}
 
// Hooked write system call
static asmlinkage ssize_t hooked_sys_write(unsigned int fd, const char __user *buf, size_t count)
{
  printk(KERN_INFO "Hooked write called\n");
  // Any additional logic
  return original_sys_write(fd, buf, 1);
}
 
// Hooked read system call
static asmlinkage ssize_t hooked_sys_read(unsigned int fd, const char __user *buf, size_t count)
{
  printk(KERN_INFO "Hooked read called\n");
  // Any additional logic
  return original_sys_read(fd, buf, 1);
}
 
// Pre-handler for write
static int pre_handler_write(struct kprobe *p, struct pt_regs *regs)
{
  char * path_ = get_file_path_from_fd(regs->di);
  if (path_) {
     if (strstr(path_, "root/kernel_module") && nwrites <= 20) {
         // It's not a system record -> count them
         nwrites++;
         printk(KERN_INFO "pre_handler write syscall for file: %s\n", path_);
         // Save the original system call address
         original_sys_write = (void *)p->addr;
         // Change the instruction pointer to our hooked function
         regs->ip = (unsigned long)hooked_sys_write;
         return 1;
     }
     else {return 0;}
  }
  else {
     printk(KERN_INFO "write syscall for unknown file");
     return 0;
  }
}
 
// Pre-handler for read
static int pre_handler_read(struct kprobe *p, struct pt_regs *regs)
{
  char * path_ = get_file_path_from_fd(regs->di);
  if (path_) {
     if (strstr(path_, "root/kernel_module") && nreads <= 20) {
         // It's not a system record -> count them
         nreads++;
         printk(KERN_INFO "pre_handler read syscall for file: %s\n", path_);
         // Save the original system call address
         original_sys_read = (void *)p->addr;
         // Change the instruction pointer to our hooked function
         regs->ip = (unsigned long)hooked_sys_read;
         return 1;
     }
     else {return 0;}
  }
  else {
     printk(KERN_INFO "read syscall for unknown file");
     return 0;
  }
}

// Post-handler for write
static void post_handler_write(struct kprobe *p, struct pt_regs *regs, long unsigned int flags){
  char * path_ = get_file_path_from_fd(regs->di);
  if (path_ && strstr(path_, "root/kernel_module")) { // && nwrites <= 20) {
         printk(KERN_INFO "post_handler write: p->addr = 0x%p, ip = %lx, flags = 0x%lx\n",p->addr,regs->ip,regs->flags); }
}

// Post-handler for read 
static void post_handler_read(struct kprobe *p, struct pt_regs *regs, long unsigned int flags){
  char * path_ = get_file_path_from_fd(regs->di);
  if (path_ && strstr(path_, "root/kernel_module")) { // && nreads <= 20) {
         printk(KERN_INFO "post_handler read: p->addr = 0x%p, ip = %lx, flags = 0x%lx\n",p->addr,regs->ip,regs->flags); }
}

// Defining structure kprobe for breakpoint for ksys_write
static struct kprobe kp_write = {
  .symbol_name = "ksys_write",
  .pre_handler = pre_handler_write,
  .post_handler = post_handler_write,
};

// Defining structure kprobe for breakpoint for ksys_read
static struct kprobe kp_read = {
  .symbol_name = "ksys_read",
  .pre_handler = pre_handler_read,
  .post_handler = post_handler_read,
};
 
// Module initialization
static int __init syscall_hook_init(void)
{
  int ret;

  ret = register_kprobe(&kp_write);
  if (ret < 0) {
    printk(KERN_ERR "register_kprobe for write failed, returned %d\n", ret);
    return ret;
  }
 
  ret = register_kprobe(&kp_read);
  if (ret < 0) {
    printk(KERN_ERR "register_kprobe for read failed, returned %d\n", ret);
    unregister_kprobe(&kp_write);
    return ret;
  }
 
  printk(KERN_INFO "Syscall hook module loaded\n");
  return 0;
}
 
// Module cleanup
static void __exit syscall_hook_exit(void)
{
  unregister_kprobe(&kp_write);
  unregister_kprobe(&kp_read);
  printk(KERN_INFO "Syscall hook module unloaded\n");
}
 
module_init(syscall_hook_init);
module_exit(syscall_hook_exit);
