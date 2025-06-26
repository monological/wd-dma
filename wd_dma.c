/*
 * wd_dma.c – DMA-buffer exporter for Wiredancer
 *
 * Two data paths are supported:
 *   1. A built-in 4 MiB coherent buffer.
 *   2. Pinning a single user hugepage and returning its IOVA to user space.
 *
 * The ioctl interface is:
 *   WD_IOC_GET_COHERENT   (0) – returns the IOVA of the built-in buffer.
 *   WD_IOC_MAP_HUGEPAGE   (1) – argument is a pointer to a user-space
 *                               variable that initially contains the
 *                               user virtual address of the hugepage.
 *                               On success it is overwritten with the IOVA.
 *
 * The driver tracks at most one pinned hugepage. A second MAP_HUGEPAGE call
 * replaces any previous mapping and cleans it up automatically. All resources
 * are released on module unload.
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
#include <linux/sizes.h>

/* ---------- constants -------------------------------------------------- */
#define WD_SIZE             (1U << 22)   /* 4 MiB coherent buffer */
#define WD_IOC_GET_COHERENT 0
#define WD_IOC_MAP_HUGEPAGE 1

#define WD_ERROR_IF_NOT_HUGEPAGE 0

/* ---------- context ---------------------------------------------------- */
struct wd_ctx {
    struct platform_device *pdev;

    /* built-in buffer */
    void       *cpu_ptr;
    dma_addr_t  iova;

    /* pinned hugepage */
    struct page *upage;
    size_t       upage_len;
    dma_addr_t   upage_iova;

    atomic_t     map_cnt;
    struct mutex lock;
};

static struct wd_ctx wd = {
    .pdev       = NULL,
    .cpu_ptr    = NULL,
    .iova       = 0,
    .upage      = NULL,
    .upage_len  = 0,
    .upage_iova = 0,
    .map_cnt    = ATOMIC_INIT(0),
    .lock       = __MUTEX_INITIALIZER(wd.lock),
};

/* ---------- helpers---------------------------------------------------- */

char *order_to_size_str(unsigned int order, char *buf, size_t len)
{
    unsigned long long bytes;

    if (order >= (sizeof(unsigned long long) * 8 - PAGE_SHIFT)) {
        scnprintf(buf, len, "overflow");
        return buf;
    }

    bytes = (unsigned long long)PAGE_SIZE << order;

    if (!(bytes & ((1ULL << 30) - 1)))
        scnprintf(buf, len, "%lluGiB", bytes >> 30);
    else if (!(bytes & ((1ULL << 20) - 1)))
        scnprintf(buf, len, "%lluMiB", bytes >> 20);
    else if (!(bytes & ((1ULL << 10) - 1)))
        scnprintf(buf, len, "%lluKiB", bytes >> 10);
    else
        scnprintf(buf, len, "%lluB", bytes);

    return buf;
}

/* ---------- VMA helpers ------------------------------------------------ */
static int wd_validate_vma(struct vm_area_struct *vma)
{
    size_t len = vma->vm_end - vma->vm_start;

    if (len != WD_SIZE || vma->vm_pgoff) {
        pr_err("mmap: bad size %zu or offset %lu\n",
               len, vma->vm_pgoff);
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

static void wd_unmap_hugepage(void)
{
    if (!wd.upage)
        return;

    /* unmap DMA */
    dma_unmap_page(&wd.pdev->dev,
                   wd.upage_iova,
                   wd.upage_len,
                   DMA_BIDIRECTIONAL);

    /* unpin page */
    {
        struct page *pages[1] = { wd.upage };
        unpin_user_pages_dirty_lock(pages, 1, true);
    }

    wd.upage      = NULL;
    wd.upage_len  = 0;
    wd.upage_iova = 0;

    pr_info("hugepage unmapped\n");
}

static long wd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    long ret = 0;

    mutex_lock(&wd.lock);

    switch (cmd) {
    case WD_IOC_GET_COHERENT: {
        ret = copy_to_user((void __user *)arg, &wd.iova,
                           sizeof(wd.iova)) ? -EFAULT : 0;
        break;
    }

    case WD_IOC_MAP_HUGEPAGE: {
        unsigned long uaddr;
        struct page  *page;
        size_t        len;
        dma_addr_t    dma;
        long pinned;
        char pagesize[32];
        int order;

        if (copy_from_user(&uaddr, (void __user *)arg,
                           sizeof(uaddr))) {
            ret = -EFAULT;
            break;
        }

        /* replace any existing mapping */
        wd_unmap_hugepage();

        /* pin exactly one page */
        pinned = pin_user_pages_fast(uaddr, 1,
                          FOLL_WRITE | FOLL_LONGTERM,
                          &page);
        if (pinned != 1) {
            pr_err("WD_IOC_MAP_HUGEPAGE: pin_user_pages_fast(vaddr 0x%lx) returned %ld\n",
                   uaddr, pinned);
            ret = (pinned < 0) ? pinned : -EFAULT;
            break;
        }

        len = PAGE_SIZE << compound_order(page);
        order = compound_order(page);
        order_to_size_str(order, pagesize, sizeof(pagesize));

        /* only allow hugepages and reject regular 4 KiB pages */
        if (order == 0) {
#if WD_ERROR_IF_NOT_HUGEPAGE
            struct page *pages[1] = { page };
            unpin_user_pages_dirty_lock(pages, 1, true);
            pr_err("WD_IOC_MAP_HUGEPAGE: vaddr=0x%lx pagesize=%s (not hugepage)\n",
                   uaddr, pagesize);
            ret = -EINVAL;
            break;
#else
            pr_warn("WD_IOC_MAP_HUGEPAGE: vaddr=0x%lx pagesize=%s (not hugepage), but continuing anyway\n",
                uaddr, pagesize);
#endif
        }

        dma = dma_map_page(&wd.pdev->dev, page, 0, len,
                           DMA_BIDIRECTIONAL);
        if (dma_mapping_error(&wd.pdev->dev, dma)) {
            struct page *pages[1] = { page };
            unpin_user_pages_dirty_lock(pages, 1, true);
            pr_err("WD_IOC_MAP_HUGEPAGE: dma_map_page failed (vaddr 0x%lx len %zu)\n",
                   uaddr, len);
            ret = -EIO;
            break;
        }

        wd.upage      = page;
        wd.upage_len  = len;
        wd.upage_iova = dma;

        ret = copy_to_user((void __user *)arg, &dma,
                           sizeof(dma)) ? -EFAULT : 0;

        if (!ret)
            pr_info("WD_IOC_MAP_HUGEPAGE: hugepage pinned with vaddr=0x%lx "
                    "pagesize=%s len=%zu -> IOVA 0x%llx\n",
                    uaddr, pagesize, len, (unsigned long long)dma);
        break;
    }

	default:
		ret = -EINVAL;
	}

	mutex_unlock(&wd.lock);
	return ret;
}

#ifdef CONFIG_COMPAT
static long wd_compat_ioctl(struct file *filp,
                            unsigned int cmd,
                            unsigned long arg)
{
    return wd_ioctl(filp, cmd, arg);
}
#endif

static int wd_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int rc = wd_validate_vma(vma);

    if (rc)
        return rc;

    rc = dma_mmap_coherent(&wd.pdev->dev, vma,
                           wd.cpu_ptr, wd.iova, WD_SIZE);
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
        pr_err("64-bit DMA not supported\n");
        goto err_pdev;
    }

    wd.cpu_ptr = dma_alloc_coherent(&wd.pdev->dev, WD_SIZE,
                                    &wd.iova, GFP_KERNEL);
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

    pr_info("coherent buffer ready: CPU %p, IOVA 0x%llx\n",
        wd.cpu_ptr, (unsigned long long)wd.iova);
    return 0;

err_buf:
    dma_free_coherent(&wd.pdev->dev, WD_SIZE, wd.cpu_ptr, wd.iova);
err_pdev:
    platform_device_unregister(wd.pdev);
    return rc;
}

static void __exit wd_exit(void)
{
    pr_info("unloading (active maps=%d)\n",
        atomic_read(&wd.map_cnt));

    wd_unmap_hugepage();
    misc_deregister(&wd_misc);
    dma_free_coherent(&wd.pdev->dev, WD_SIZE, wd.cpu_ptr, wd.iova);
    platform_device_unregister(wd.pdev);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Julian Lupu");
MODULE_DESCRIPTION("Wiredancer DMA buffer exporter with hugepage support");

module_init(wd_init);
module_exit(wd_exit);
