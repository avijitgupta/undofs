/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "wrapfs.h"
#include <linux/module.h>

/*
 * There is no need to lock the wrapfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
int restore_policy=0;

static int wrapfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	char *dev_name = (char *) raw_data;
	struct inode *inode;
	struct nameidata nd;	
	struct qstr trashbin_qstr;
	unsigned int trashbin_mode = 0;
	struct inode* lower_inode;
/* NEW*/
	struct dentry *trashbin_dentry = NULL;
	struct dentry *dentry_root=NULL;
//	struct dentry *lower_dentry_root = NULL;
        const char* trash = ".trash";
//        struct path lp;
	//struct vfsmount *top_vfsmount;
/* End new*/


	if (!dev_name) {
		printk(KERN_ERR
		       "wrapfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"wrapfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct wrapfs_sb_info), GFP_KERNEL);
	if (!WRAPFS_SB(sb)) {
		printk(KERN_CRIT "wrapfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}

	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	wrapfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &wrapfs_sops;

	/* get a new inode and allocate our root dentry */
	inode = wrapfs_iget(sb, lower_path.dentry->d_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_alloc_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &wrapfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	wrapfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_alloc_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "wrapfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
//	sb->s_d_op = &wrapfs_dops; //Added

	/* no longer needed: free_dentry_private_data(sb->s_root); */

/* Putting the trashbin into private pointer*/

// 1 reference count for dentry_root

	dentry_root = dget(sb->s_root);

        //wrapfs_get_lower_path(dentry_root, &lp);
        //lower_dentry_root = lp.dentry;
//	top_vfsmount = current->fs->pwd.mnt;
//Path obtained contains the dentry of trash.
//        error = vfs_path_lookup(dentry_root, top_vfsmount , trash, LOOKUP_DIRECTORY , &path_obtained);
        trashbin_qstr.len = strlen(trash);
        trashbin_qstr.name = trash;
        trashbin_qstr.hash = full_name_hash(trash,strlen(trash));

	trashbin_dentry =  d_alloc(dentry_root, &trashbin_qstr);
	nd.flags = LOOKUP_DIRECTORY;
	wrapfs_lookup(dentry_root->d_inode, trashbin_dentry, &nd);
	
	/*if(error && error!=-ENOENT)
	{
		goto out_freeroot;
	}	*/
// Check what error is returned and modify the code below

	if(trashbin_dentry->d_inode==NULL)
	{
		 trashbin_mode =  trashbin_mode |(S_IFDIR | S_IRWXU | S_IRWXG| S_IRWXO);
                 err = wrapfs_mkdir(dentry_root->d_inode, trashbin_dentry, trashbin_mode);
		 if(!err)
		 {
		 	printk("Created a new .trash in the root directory mode %d", trashbin_mode);
			trashbin_dentry->d_inode->i_mode |= trashbin_mode;
 	        	lower_inode = wrapfs_lower_inode(trashbin_dentry->d_inode);
			lower_inode->i_mode |=trashbin_mode;
			set_trashbin_dentry(sb, trashbin_dentry);  ///Stuffing into private pointer for dentry
		 }
		 else
		 {
			goto out_freeroot;
		 }	
	}
	else 
	{
		printk(KERN_INFO "Trash Existing");
	 	set_trashbin_dentry(sb, trashbin_dentry);  ///Stuffing into private pointer for dentry
	}
	

//      if(error!=0)
//                printk(KERN_INFO "Some Error %d ENOENT %d ECHILD%d ENOTDIR %d EPERM %d EACCES %d ", error, ENOENT, ECHILD, ENOTDIR, EPERM, EACCES);
	
	goto out; /* all is well */

/* Conclusion*/
out_freeroot:
	
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(WRAPFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	dput(dentry_root);
	dput(trashbin_dentry);
	return err;
}

struct dentry *wrapfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	void *lower_path_name = (void *) dev_name;
	char* mount_flags = (char*)raw_data;
	//printk(KERN_INFO "%s", mount_flags);
	if(mount_flags && strcmp(mount_flags, "delete")==0)
		restore_policy = DELETE;		
		
	else 
		restore_policy = DONT_DELETE;

	return mount_nodev(fs_type, flags, lower_path_name,
			   wrapfs_read_super);
}

void my_generic_shutdown_super(struct super_block *sb)
{
	printk(KERN_INFO "Dentry Reference Count %d\n",get_trashbin_dentry(sb)->d_count);
	dput(get_trashbin_dentry(sb));
	generic_shutdown_super(sb);
}

static struct file_system_type wrapfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= WRAPFS_NAME,
	.mount		= wrapfs_mount,
	.kill_sb	= my_generic_shutdown_super,
	.fs_flags	= FS_REVAL_DOT,
};

static int __init init_wrapfs_fs(void)
{
	int err;

	pr_info("Registering wrapfs " WRAPFS_VERSION "\n");

	err = wrapfs_init_inode_cache();
	if (err)
		goto out;
	err = wrapfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&wrapfs_fs_type);
out:
	if (err) {
		wrapfs_destroy_inode_cache();
		wrapfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_wrapfs_fs(void)
{
	wrapfs_destroy_inode_cache();
	wrapfs_destroy_dentry_cache();
	unregister_filesystem(&wrapfs_fs_type);
	pr_info("Completed wrapfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("Wrapfs " WRAPFS_VERSION
		   " (http://wrapfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_wrapfs_fs);
module_exit(exit_wrapfs_fs);
