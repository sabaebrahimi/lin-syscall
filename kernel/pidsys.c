#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/sched.h>    
#include <linux/pid.h>      
#include <linux/fs.h>
#include <linux/slab.h>

static int pid_exists_in_file(pid_t pid, struct file *file) {
    char *line;
    loff_t pos = 0;
    int found = 0;  
    char *buffer;
    ssize_t bytes_read;
    int current_number;

    buffer = kmalloc(256, GFP_KERNEL);
    if (!buffer) {
        printk(KERN_ERR "Kernel: Failed to allocate memory\n");
        filp_close(file, NULL);
        return -ENOMEM;
    }

    while ((bytes_read = kernel_read(file, buffer, 256 - 1, &pos)) > 0) {
        buffer[bytes_read] = '\0';
        line = buffer;

        while (line) {
            char *next = strchr(line, '\n');
            if (next)
                *next = '\0';

            if (kstrtoint(line, 10, &current_number) == 0) {
                if (current_number == pid) {
                    found = 1;
                    goto cleanup;
                }
            }

            if (!next)
                break;
            line = next + 1;
        }
    }

cleanup:
    kfree(buffer);
    return found;
}

SYSCALL_DEFINE2(pidchecker, char __user *, filename, pid_t, pid_number)
{
    char kernel_buf[256]; 
    int copied;
    struct file *file;
    loff_t pos = 0;
    int ret;
    int found = 0;

    if (!filename) 
        return -EINVAL;

    copied = strncpy_from_user(kernel_buf, filename, sizeof(kernel_buf) - 1);
    if (copied < 0)
        return -EFAULT;  

    kernel_buf[255] = '\0'; 

    file = filp_open(kernel_buf, O_RDWR | O_CREAT | O_APPEND, 0);

    if (IS_ERR(file)) {
        printk(KERN_ERR "Kernel: Failed to open file %s\n", kernel_buf);
        return PTR_ERR(file);
    }
    char *pid_str;
    pid_str = kmalloc(10, GFP_KERNEL);

    if (!pid_str) {
        printk(KERN_ERR "Kernel: Failed to allocate memory\n");
        return -ENOMEM;
    }

    sprintf(pid_str, "%d\n", pid_number);

    if (!pid_exists_in_file(pid_number, file)) {
        ret = kernel_write(file, pid_str, strlen(pid_str), &pos);
        if (ret < 0) {
            printk(KERN_ERR "Kernel: Failed to write to file\n");
        } else {
            printk(KERN_INFO "Kernel: Successfully wrote to file\n");
        }
    } else {
        printk(KERN_INFO "Kernel: PID already exists in file\n");
        found = 1;
    }
    filp_close(file, NULL);

    return found;    
}