/* wd_dma.c  – stand-alone misc driver that allocates a DMA-coherent buffer
 *             and returns its IOVA (bus address) to user space via ioctl 0. */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/dma-mapping.h>
#include <linux/platform_device.h>
#include <linux/uaccess.h>
#include <linux/mm.h>

#define WD_SIZE   (1 << 16)           /* 64 KiB; adjust to taste          */

static struct platform_device *wd_pdev;
static void       *cpu_ptr;
static dma_addr_t  iova;


/* ---------- new mmap callback ---------- */

static int wd_mmap(struct file *filp, struct vm_area_struct *vma)
{
    /* optional size check */
    if (vma->vm_end - vma->vm_start != WD_SIZE)
        return -EINVAL;

    return dma_mmap_coherent(&wd_pdev->dev, vma,
                             cpu_ptr,          /* CPU address returned earlier */
                             iova,             /* device (bus) address        */
                             WD_SIZE);
}
/* --------------------------------------- */

/* ---------- misc char-device plumbing ---------- */

static long wd_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    return (cmd == 0) ? put_user(iova, (uint64_t __user *)arg) : -EINVAL;
}

static const struct file_operations wd_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = wd_ioctl,
    .mmap           = wd_mmap,
};

static struct miscdevice wd_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "wd_dma",
    .fops  = &wd_fops,
};

/* ---------- module init / exit ---------- */

static int __init wd_init(void)
{
    int rc;

    /* 1. Create a dummy platform device so we get valid DMA ops */
    wd_pdev = platform_device_register_simple("wd-dma-dev", -1, NULL, 0);
    if (IS_ERR(wd_pdev))
        return PTR_ERR(wd_pdev);

    /* 2. Allow >4 GiB addresses */
    dma_set_mask_and_coherent(&wd_pdev->dev, DMA_BIT_MASK(64));

    /* 3. Allocate the coherent buffer */
    cpu_ptr = dma_alloc_coherent(&wd_pdev->dev, WD_SIZE, &iova, GFP_KERNEL);
    if (!cpu_ptr) {
        pr_err("wd_dma: dma_alloc_coherent failed\n");
        rc = -ENOMEM;
        goto err_dev;
    }

    /* 4. Register the misc node */
    rc = misc_register(&wd_misc);
    if (rc)
        goto err_buf;

    pr_info("wd_dma: %u bytes @CPU %p, IOVA 0x%llx\n",
            WD_SIZE, cpu_ptr, (unsigned long long)iova);
    return 0;

err_buf:
    dma_free_coherent(&wd_pdev->dev, WD_SIZE, cpu_ptr, iova);
err_dev:
    platform_device_unregister(wd_pdev);
    return rc;
}

static void __exit wd_exit(void)
{
    misc_deregister(&wd_misc);
    dma_free_coherent(&wd_pdev->dev, WD_SIZE, cpu_ptr, iova);
    platform_device_unregister(wd_pdev);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("example");
MODULE_DESCRIPTION("simple DMA buffer exporter");
module_init(wd_init);
module_exit(wd_exit);
