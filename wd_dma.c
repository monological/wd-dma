/*
 * wd_dma.c – tiny DMA‑buffer exporter used by Wiredancer.
 *
 * Safe version with:
 *   • platform_device wrapper so we get valid DMA ops
 *   • reference‑counted mmap tracking (open/close)
 *   • minimal pr_info/pr_err prints for visibility
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/dma-mapping.h>
#include <linux/platform_device.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/compat.h>
#include <linux/mutex.h>

/* ---------- constants -------------------------------------------------- */
#define WD_SIZE   (1U << 22) /* 4 MiB buffer size */

/* ---------- context ---------------------------------------------------- */
struct wd_ctx {
    struct platform_device *pdev;
    void       *cpu_ptr;      /* kernel mapping */
    dma_addr_t  iova;         /* bus address */
    atomic_t    map_cnt;      /* active vmas */
    struct mutex lock;        /* ioctl / mmap */
};

static struct wd_ctx wd = {
    .pdev   = NULL,
    .cpu_ptr = NULL,
    .iova   = 0,
    .map_cnt = ATOMIC_INIT(0),
    .lock   = __MUTEX_INITIALIZER(wd.lock),
};

/* ---------- VMA helpers ------------------------------------------------ */
static int wd_validate_vma(struct vm_area_struct *vma)
{
    size_t len = vma->vm_end - vma->vm_start;
    if (len != WD_SIZE || vma->vm_pgoff) {
        pr_err("mmap: bad size %zu or offset %lu\n", len, vma->vm_pgoff);
        return -EINVAL;
    }
    vma->vm_flags |= VM_IO | VM_DONTEXPAND | VM_DONTDUMP;
    return 0;
}

static void wd_vma_close(struct vm_area_struct *vma)
{
    atomic_dec(&wd.map_cnt);
    pr_info("mmap closed (cnt=%d)\n", atomic_read(&wd.map_cnt));
}

static const struct vm_operations_struct wd_vm_ops = {
    .close = wd_vma_close,
};

/* ---------- file ops --------------------------------------------------- */
static int wd_open(struct inode *ino, struct file *filp)
{
    pr_info("open by pid %d\n", task_pid_nr(current));
    return 0;
}

static int wd_release(struct inode *ino, struct file *filp)
{
    pr_info("release by pid %d\n", task_pid_nr(current));
    return 0;
}

static long wd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    long ret;

    mutex_lock(&wd.lock);
    if (cmd == 0) {
        pr_info("ioctl: return IOVA 0x%llx\n", (unsigned long long)wd.iova);
        ret = copy_to_user((void __user *)arg, &wd.iova, sizeof(wd.iova)) ? -EFAULT : 0;
    } else {
        ret = -EINVAL;
    }
    mutex_unlock(&wd.lock);
    return ret;
}

#ifdef CONFIG_COMPAT
static long wd_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return wd_ioctl(filp, cmd, arg);
}
#endif

static int wd_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int rc = wd_validate_vma(vma);
    if (rc)
        return rc;

    rc = dma_mmap_coherent(&wd.pdev->dev, vma, wd.cpu_ptr, wd.iova, WD_SIZE);
    if (rc)
        return rc;

    vma->vm_ops = &wd_vm_ops;
    atomic_inc(&wd.map_cnt);
    pr_info("mmap ok (cnt=%d)\n", atomic_read(&wd.map_cnt));
    return 0;
}

static const struct file_operations wd_fops = {
    .owner          = THIS_MODULE,
    .open           = wd_open,
    .release        = wd_release,
    .unlocked_ioctl = wd_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = wd_compat_ioctl,
#endif
    .mmap           = wd_mmap,
};

static struct miscdevice wd_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "wd_dma",
    .fops  = &wd_fops,
};

/* ---------- init / exit ------------------------------------------------ */
static int __init wd_init(void)
{
    int rc;

    pr_info("loading (%u bytes)\n", WD_SIZE);

    wd.pdev = platform_device_register_simple("wd-dma-dev", -1, NULL, 0);
    if (IS_ERR(wd.pdev)) {
        pr_err("platform_device_register_simple failed\n");
        return PTR_ERR(wd.pdev);
    }

    rc = dma_set_mask_and_coherent(&wd.pdev->dev, DMA_BIT_MASK(64));
    if (rc) {
        pr_err("64‑bit DMA not supported\n");
        goto err_pdev;
    }

    wd.cpu_ptr = dma_alloc_coherent(&wd.pdev->dev, WD_SIZE, &wd.iova, GFP_KERNEL);
    if (!wd.cpu_ptr) {
        pr_err("dma_alloc_coherent failed\n");
        rc = -ENOMEM;
        goto err_pdev;
    }
    memset(wd.cpu_ptr, 0, WD_SIZE);

    rc = misc_register(&wd_misc);
    if (rc) {
        pr_err("misc_register failed\n");
        goto err_buf;
    }

    pr_info("buffer ready: CPU %p IOVA 0x%llx\n", wd.cpu_ptr, (unsigned long long)wd.iova);
    return 0;

err_buf:
    dma_free_coherent(&wd.pdev->dev, WD_SIZE, wd.cpu_ptr, wd.iova);
err_pdev:
    platform_device_unregister(wd.pdev);
    return rc;
}

static void __exit wd_exit(void)
{
    pr_info("unloading (active maps=%d)\n", atomic_read(&wd.map_cnt));

    misc_deregister(&wd_misc);
    dma_free_coherent(&wd.pdev->dev, WD_SIZE, wd.cpu_ptr, wd.iova);
    platform_device_unregister(wd.pdev);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Julian Lupu");
MODULE_DESCRIPTION("Wiredancer DMA buffer exporter");

module_init(wd_init);
module_exit(wd_exit);

