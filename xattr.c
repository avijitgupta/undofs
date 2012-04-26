#include "wrapfs.h"

/* This is lifted from fs/xattr.c */
void *wrapfs_xattr_alloc(size_t size, size_t limit)
{
	void *ptr;

	if (size > limit)
		return ERR_PTR(-E2BIG);

	if (!size)		/* size request, no buffer is needed */
		return NULL;

	ptr = kmalloc(size, GFP_KERNEL);
	if (unlikely(!ptr))
		return ERR_PTR(-ENOMEM);
	return ptr;
}

//Ecryptfs 
ssize_t 
wrapfs_getxattr_lower(struct dentry *lower_dentry, const char *name,
                        void *value, size_t size)
{
        int rc = 0;

        if (!lower_dentry->d_inode->i_op->getxattr) {
                rc = -EOPNOTSUPP;
                goto out;
        }
        mutex_lock(&lower_dentry->d_inode->i_mutex);
        rc = lower_dentry->d_inode->i_op->getxattr(lower_dentry, name, value,
                                                   size);
        mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
        return rc;
}


/*
 * BKL held by caller.
 * dentry->d_inode->i_mutex locked
 */
//Ecryptfs
ssize_t wrapfs_getxattr(struct dentry *dentry, const char *name, void *value,
			 size_t size)
{
	int err = 0;
	struct path lower_path;
	wrapfs_get_lower_path(dentry, &lower_path);
        err = wrapfs_getxattr_lower(lower_path.dentry, name,value, size);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * BKL held by caller.
 * dentry->d_inode->i_mutex locked
 */

//Ecryptfs
int wrapfs_setxattr(struct dentry *dentry, const char *name,
		     const void *value, size_t size, int flags)
{
        int rc = 0;
        struct dentry *lower_dentry;
	struct path lower_path;
	wrapfs_get_lower_path(dentry, &lower_path);
        lower_dentry = lower_path.dentry;
        if (!lower_dentry->d_inode->i_op->setxattr) {
                rc = -EOPNOTSUPP;
                goto out;
        }

        rc = vfs_setxattr(lower_dentry, name, value, size, flags);
out:
        wrapfs_put_lower_path(dentry, &lower_path);
	return rc;
}

/*
 * BKL held by caller.
 * dentry->d_inode->i_mutex locked
 */
int wrapfs_removexattr(struct dentry *dentry, const char *name)
{
        int rc = 0;
        struct dentry *lower_dentry;
	struct path lower_path;
        wrapfs_get_lower_path(dentry, &lower_path);
        lower_dentry = lower_path.dentry;

        if (!lower_dentry->d_inode->i_op->removexattr) {
                rc = -EOPNOTSUPP;
                goto out;
        }
        mutex_lock(&lower_dentry->d_inode->i_mutex);
        rc = lower_dentry->d_inode->i_op->removexattr(lower_dentry, name);
        mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
        wrapfs_put_lower_path(dentry, &lower_path);
        return rc;
}

/*
 * BKL held by caller.
 * dentry->d_inode->i_mutex locked
 */

//Ecryptfs
ssize_t wrapfs_listxattr(struct dentry *dentry, char *list, size_t size)
{
        int rc = 0;
        struct dentry *lower_dentry;
        struct path lower_path;
        wrapfs_get_lower_path(dentry, &lower_path);
        lower_dentry = lower_path.dentry;
        
	if (!lower_dentry->d_inode->i_op->listxattr) {
                rc = -EOPNOTSUPP;
                goto out;
        }
        mutex_lock(&lower_dentry->d_inode->i_mutex);
        rc = lower_dentry->d_inode->i_op->listxattr(lower_dentry, list, size);
        mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
        wrapfs_put_lower_path(dentry, &lower_path);
	return rc;

}

