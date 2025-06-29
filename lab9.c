#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/err.h>
#include <linux/string.h>

#define DEVICE_NAME "lab9_crypto"
#define CLASS_NAME "lab9_class"

static int major_number;
static struct cdev lab9_cdev;
static struct class *lab_class = NULL;
static struct device *lab9_device = NULL;

struct lab9_data {
    char operation;     // '1': DES enc, '2': AES enc, '3': DES dec, '4': AES dec, '5': MD5, '6': SHA1, '7': SHA256
    char input[256];    // Dữ liệu đầu vào
    char key[32];       // Khóa (8 cho DES, 16 cho AES, bỏ qua cho hash)
    char result[512];   // Kết quả (hex cho enc/dec, hash output)
};

static int crypto_hex_to_bin(const char *hex, u8 *bin, size_t bin_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != bin_len * 2) {
        printk(KERN_ERR "Invalid hex string length\n");
        return -EINVAL;
    }
    for (size_t i = 0; i < bin_len; i++) {
        if (sscanf(hex + i * 2, "%2hhx", &bin[i]) != 1) {
            printk(KERN_ERR "Error converting hex to binary\n");
            return -EINVAL;
        }
    }
    return 0;
}

static int crypto_hash(struct lab9_data *data, const char *algo_name) {
    struct crypto_shash *tfm = NULL;
    u8 *hash = NULL;
    int ret = 0;

    tfm = crypto_alloc_shash(algo_name, 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to alloc hash %s: %ld\n", algo_name, PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }

    hash = kmalloc(crypto_shash_digestsize(tfm), GFP_KERNEL);
    if (!hash) {
        ret = -ENOMEM;
        goto out;
    }

    ret = crypto_shash_tfm_digest(tfm, data->input, strlen(data->input), hash);
    if (ret) {
        printk(KERN_ERR "Hash computation failed: %d\n", ret);
        goto out;
    }

    for (size_t i = 0; i < crypto_shash_digestsize(tfm); i++) {
        sprintf(data->result + i * 2, "%02x", hash[i]);
    }
    data->result[crypto_shash_digestsize(tfm) * 2] = '\0';

    printk(KERN_INFO "Hash %s result: %s\n", algo_name, data->result);

out:
    kfree(hash);
    if (tfm)
        crypto_free_shash(tfm);
    return ret;
}

// Hàm thêm padding PKCS#5/PKCS#7
static void add_pkcs_padding(u8 *input, size_t *len, size_t block_size) {
    size_t pad_len = block_size - (*len % block_size);
    if (pad_len == block_size) pad_len = block_size; // Đệm thêm một khối nếu đã đủ
    memset(input + *len, pad_len, pad_len);
    *len += pad_len;
}

// Hàm bỏ padding PKCS#5/PKCS#7
static int remove_pkcs_padding(u8 *input, size_t *len, size_t block_size) {
    if (*len < block_size || *len % block_size != 0) {
        printk(KERN_ERR "Invalid padded length: %zu\n", *len);
        return -EINVAL;
    }
    u8 pad_value = input[*len - 1];
    if (pad_value == 0 || pad_value > block_size) {
        printk(KERN_ERR "Invalid padding value: %u\n", pad_value);
        return -EINVAL;
    }
    for (size_t i = *len - pad_value; i < *len; i++) {
        if (input[i] != pad_value) {
            printk(KERN_ERR "Invalid padding byte at %zu\n", i);
            return -EINVAL;
        }
    }
    *len -= pad_value;
    return 0;
}

static int crypto_cipher(struct lab9_data *data) {
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    char *algo_name;
    int key_len;
    int ret = 0;
    u8 iv[16];

    // Xác định thuật toán, độ dài khóa và IV
    switch (data->operation) {
        case '1': case '3':
            algo_name = "cbc(des)";
            key_len = 8;
            memcpy(iv, "12345678", 8); // IV 8 byte cho DES
            break;
        case '2': case '4':
            algo_name = "cbc(aes)";
            key_len = 16;
            memcpy(iv, "1234567890abcdef", 16); // IV 16 byte cho AES
            break;
        default:
            printk(KERN_ERR "Invalid cipher operation: %c\n", data->operation);
            return -EINVAL;
    }

    // Kiểm tra đầu vào và khóa
    if (data->input[0] == '\0') {
        printk(KERN_ERR "Empty input string\n");
        return -EINVAL;
    }

    // Kiểm tra độ dài khóa
    size_t key_actual_len = strnlen(data->key, sizeof(data->key));
    if (key_actual_len < key_len) {
        printk(KERN_ERR "Invalid key length for %s, expected %d bytes, got %zu\n", 
               algo_name, key_len, key_actual_len);
        return -EINVAL;
    }

    // Khởi tạo skcipher
    tfm = crypto_alloc_skcipher(algo_name, 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to alloc cipher %s: %ld\n", algo_name, PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }

    ret = crypto_skcipher_setkey(tfm, data->key, key_len);
    if (ret) {
        printk(KERN_ERR "Key setup failed for %s: %d\n", algo_name, ret);
        goto out;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        printk(KERN_ERR "Failed to alloc skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    size_t len = strlen(data->input);
    size_t block_size = crypto_skcipher_blocksize(tfm);
    u8 *bin_input = NULL;

    if (data->operation == '3' || data->operation == '4') {
        // Giải mã: Chuyển hex thành binary
        len = strlen(data->input) / 2;
        if (len % block_size != 0 || len == 0) {
            printk(KERN_ERR "Invalid input length for decryption: %zu\n", len);
            ret = -EINVAL;
            goto out;
        }
        bin_input = kmalloc(len, GFP_KERNEL);
        if (!bin_input) {
            ret = -ENOMEM;
            goto out;
        }
        ret = crypto_hex_to_bin(data->input, bin_input, len);
        if (ret) {
            kfree(bin_input);
            goto out;
        }

        // Thực hiện giải mã
        struct scatterlist sg[1];
        sg_init_one(&sg[0], bin_input, len);
        skcipher_request_set_crypt(req, sg, sg, len, iv);
        ret = crypto_skcipher_decrypt(req);
        if (ret) {
            printk(KERN_ERR "Cipher decryption failed for %s: %d\n", algo_name, ret);
            kfree(bin_input);
            goto out;
        }

        // Bỏ padding sau giải mã
        ret = remove_pkcs_padding(bin_input, &len, block_size);
        if (ret) {
            kfree(bin_input);
            goto out;
        }
        strncpy(data->result, bin_input, len);
        data->result[len] = '\0';
    } else {
        // Mã hóa: Chuẩn bị đầu vào và thêm padding
        size_t padded_len = ((len + block_size - 1) / block_size) * block_size;
        bin_input = kzalloc(padded_len, GFP_KERNEL);
        if (!bin_input) {
            ret = -ENOMEM;
            goto out;
        }
        memcpy(bin_input, data->input, len);
        add_pkcs_padding(bin_input, &len, block_size);

        // Thực hiện mã hóa
        struct scatterlist sg[1];
        sg_init_one(&sg[0], bin_input, len);
        skcipher_request_set_crypt(req, sg, sg, len, iv);
        ret = crypto_skcipher_encrypt(req);
        if (ret) {
            printk(KERN_ERR "Cipher encryption failed for %s: %d\n", algo_name, ret);
            kfree(bin_input);
            goto out;
        }

        // Chuyển kết quả thành hex
        if (len * 2 >= sizeof(data->result)) {
            printk(KERN_ERR "Result buffer too small for hex output\n");
            ret = -ENOMEM;
            kfree(bin_input);
            goto out;
        }
        for (size_t i = 0; i < len; i++) {
            sprintf(data->result + i * 2, "%02x", bin_input[i]);
        }
        data->result[len * 2] = '\0';
    }

    printk(KERN_INFO "Cipher result for %s: %s\n", algo_name, data->result);

out:
    kfree(bin_input);
    if (req)
        skcipher_request_free(req);
    if (tfm)
        crypto_free_skcipher(tfm);
    return ret;
}

static int crypto_process(struct lab9_data *data) {
    switch (data->operation) {
        case '1': case '2': case '3': case '4':
            return crypto_cipher(data);
        case '5':
            return crypto_hash(data, "md5");
        case '6':
            return crypto_hash(data, "sha1");
        case '7':
            return crypto_hash(data, "sha256");
        default:
            printk(KERN_ERR "Invalid operation: %c\n", data->operation);
            return -EINVAL;
    }
}

static ssize_t lab9_write(struct file *file, const char __user *buffer, size_t len, loff_t *offset) {
    struct lab9_data *data;
    int ret;

    if (len < sizeof(struct lab9_data)) {
        printk(KERN_ERR "Invalid data size\n");
        return -EINVAL;
    }

    data = kmalloc(sizeof(*data), GFP_KERNEL);
    if (!data) {
        printk(KERN_ERR "Memory allocation failed\n");
        return -ENOMEM;
    }

    if (copy_from_user(data, buffer, sizeof(*data))) {
        printk(KERN_ERR "Copy from user failed\n");
        kfree(data);
        return -EFAULT;
    }

    data->input[sizeof(data->input) - 1] = '\0';
    data->key[sizeof(data->key) - 1] = '\0';
    data->result[sizeof(data->result) - 1] = '\0';

    printk(KERN_DEBUG "Received: operation=%c, input=%s, key=%s\n", data->operation, data->input, data->key);

    if (file->private_data) {
        kfree(file->private_data);
    }
    file->private_data = NULL;

    ret = crypto_process(data);
    if (!ret) {
        file->private_data = data;
    } else {
        kfree(data);
    }

    return ret ? ret : len;
}

static ssize_t lab9_read(struct file *file, char __user *buffer, size_t len, loff_t *offset) {
    struct lab9_data *data = file->private_data;

    if (!data) {
        printk(KERN_ERR "No data to read\n");
        return -EINVAL;
    }

    if (len < sizeof(*data)) {
        printk(KERN_ERR "User buffer too small\n");
        return -EINVAL;
    }

    if (copy_to_user(buffer, data, sizeof(*data))) {
        printk(KERN_ERR "Copy to user failed\n");
        return -EFAULT;
    }

    printk(KERN_DEBUG "Read result: %s\n", data->result);
    return sizeof(*data);
}

static int lab9_release(struct inode *inode, struct file *file) {
    if (file->private_data) {
        kfree(file->private_data);
        file->private_data = NULL;
    }
    return 0;
}

static const struct file_operations lab9_fops = {
    .owner = THIS_MODULE,
    .write = lab9_write,
    .read = lab9_read,
    .release = lab9_release,
};

static int __init lab9_init(void) {
    dev_t dev;
    int ret;

    ret = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
    if (ret) {
        printk(KERN_ERR "Failed to allocate chrdev\n");
        return ret;
    }
    major_number = MAJOR(dev);

    cdev_init(&lab9_cdev, &lab9_fops);
    ret = cdev_add(&lab9_cdev, dev, 1);
    if (ret) {
        printk(KERN_ERR "Failed to add cdev\n");
        goto unregister_chrdev;
    }

    lab_class = class_create(CLASS_NAME);
    if (IS_ERR(lab_class)) {
        printk(KERN_ERR "Failed to create class\n");
        ret = PTR_ERR(lab_class);
        goto delete_cdev;
    }

    lab9_device = device_create(lab_class, NULL, dev, NULL, DEVICE_NAME);
    if (IS_ERR(lab9_device)) {
        printk(KERN_ERR "Failed to create device\n");
        ret = PTR_ERR(lab9_device);
        goto destroy_class;
    }

    printk(KERN_INFO "Lab9_crypto module initialized\n");
    return 0;

destroy_class:
    class_destroy(lab_class);
delete_cdev:
    cdev_del(&lab9_cdev);
unregister_chrdev:
    unregister_chrdev_region(dev, 1);
    return ret;
}

static void __exit lab9_exit(void) {
    device_destroy(lab_class, MKDEV(major_number, 0));
    class_destroy(lab_class);
    cdev_del(&lab9_cdev);
    unregister_chrdev_region(MKDEV(major_number, 0), 1);
    printk(KERN_INFO "Lab9_crypto module removed\n");
}

module_init(lab9_init);
module_exit(lab9_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Trinh Van Binh");
MODULE_DESCRIPTION("Character driver for AES, DES, MD5, SHA1, SHA256");
