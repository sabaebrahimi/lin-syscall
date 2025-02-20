#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/sched.h>    // Required for pid_t and process-related functions
#include <linux/pid.h>      // Required for pid-related operations


SYSCALL_DEFINE2(pidchecker, char __user *, filename, pid_t, pid_number)
{
    char kernel_buf[256];  // Buffer to store copied string
    int copied;

    if (!filename)  // Check for NULL pointer
        return -EINVAL;

    // Copy string from user space to kernel space
    copied = strncpy_from_user(kernel_buf, filename, sizeof(kernel_buf) - 1);
    if (copied < 0)
        return -EFAULT;  // Error in copying

    kernel_buf[255] = '\0';  // Ensure null termination

    printk(KERN_INFO "my_syscall: Received string: %s and number: %d\n", kernel_buf, pid_number);

    return pid_number * 2;    // Example: return double the input value
}