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
#include <linux/kernel.h>
#include <asm-generic/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#include <linux/linkage.h>
#include <asm/uaccess.h>
#include <linux/init.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <asm/unistd.h>
#include <linux/namei.h>
#include <linux/stat.h>
#define UID_MAX_LEN 10
#define PATH_LEN_MAX 4096
#define DIRECTORY 0
#define NORMAL_FILE 1
//static struct kmem_cache *dentry_cache __read_mostly;
struct dentry *__my_d_alloc(struct super_block *sb, const struct qstr *name)
{
        struct dentry *dentry;
        char *dname;

        dentry = kmalloc(sizeof(struct dentry), GFP_KERNEL);
        if (!dentry)
                return NULL;

        if (name->len > DNAME_INLINE_LEN-1) {
                dname = kmalloc(name->len + 1, GFP_KERNEL);
                if (!dname) {
                        kfree(dentry);
                        return NULL;
                }
        } else  {
                dname = dentry->d_iname;
        }
        dentry->d_name.name = dname;

        dentry->d_name.len = name->len;
        dentry->d_name.hash = name->hash;
        memcpy(dname, name->name, name->len);
        dname[name->len] = 0;

        dentry->d_count = 1;
        dentry->d_flags = 0;
        spin_lock_init(&dentry->d_lock);
        seqcount_init(&dentry->d_seq);
        dentry->d_inode = NULL;
        dentry->d_parent = dentry;
        dentry->d_sb = sb;
        dentry->d_op = NULL;
        dentry->d_fsdata = NULL;
        INIT_HLIST_BL_NODE(&dentry->d_hash);
        INIT_LIST_HEAD(&dentry->d_lru);
        INIT_LIST_HEAD(&dentry->d_subdirs);
        INIT_LIST_HEAD(&dentry->d_alias);
        INIT_LIST_HEAD(&dentry->d_u.d_child);
        d_set_d_op(dentry, dentry->d_sb->s_d_op);
//        this_cpu_inc(nr_dentry);
        return dentry;
}

struct dentry* my_d_alloc(struct dentry *parent, struct qstr *name)
{	
	struct dentry *dentry = __my_d_alloc(parent->d_sb, name);
        if (!dentry)
                return NULL;
        spin_lock(&parent->d_lock);
        /*
         * don't need child lock because it is not subject
         * to concurrency here
         */
        dget_dlock(parent);
        dentry->d_parent = parent;
//        list_add(&dentry->d_u.d_child, &parent->d_subdirs);
        spin_unlock(&parent->d_lock);

        return dentry;
}


static int wrapfs_create(struct inode *dir, struct dentry *dentry,
			 int mode, struct nameidata *nd)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path, saved_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;

	pathcpy(&saved_path, &nd->path);
	pathcpy(&nd->path, &lower_path);
	err = vfs_create(lower_parent_dentry->d_inode, lower_dentry, mode, nd);
	pathcpy(&nd->path, &saved_path);
	if (err)
		goto out;

	err = wrapfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, wrapfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int wrapfs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;
	struct path lower_old_path, lower_new_path;

	file_size_save = i_size_read(old_dentry->d_inode);
	wrapfs_get_lower_path(old_dentry, &lower_old_path);
	wrapfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);

	err = mnt_want_write(lower_new_path.mnt);
	if (err)
		goto out_unlock;

	err = vfs_link(lower_old_dentry, lower_dir_dentry->d_inode,
		       lower_new_dentry);
	if (err || !lower_new_dentry->d_inode)
		goto out;

	err = wrapfs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_new_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_new_dentry->d_inode);
	set_nlink(old_dentry->d_inode,
		  wrapfs_lower_inode(old_dentry->d_inode)->i_nlink);
	i_size_write(new_dentry->d_inode, file_size_save);
out:
	mnt_drop_write(lower_new_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	wrapfs_put_lower_path(old_dentry, &lower_old_path);
	wrapfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}
/*
static int my_wrapfs_rename(struct inode *lower_old_dir, struct dentry *lower_old_dentry,
			 struct inode *lower_new_dir, struct dentry *lower_new_dentry)
{
	int err = 0;
//	struct dentry *lower_old_dentry = NULL;
//	struct dentry *lower_new_dentry = NULL;
//	struct dentry *lower_old_dir_dentry = NULL;
//	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;

//	wrapfs_get_lower_path(old_dentry, &lower_old_path);
//	wrapfs_get_lower_path(new_dentry, &lower_new_path);
//	lower_old_dentry = lower_old_path.dentry;
//	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);
	
	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = mnt_want_write(lower_old_path.mnt);
	if (err)
		goto out;
	err = mnt_want_write(lower_new_path.mnt);
	if (err)
		goto out_drop_old_write;

	err = vfs_rename(lower_old_dir_dentry->d_inode, lower_old_dentry,
			 lower_new_dir_dentry->d_inode, lower_new_dentry);
	if (err)
		goto out_err;

//	fsstack_copy_attr_all(new_dir, lower_new_dir_dentry->d_inode);
//	fsstack_copy_inode_size(new_dir, lower_new_dir_dentry->d_inode);
//	if (new_dir != old_dir) {
//		fsstack_copy_attr_all(old_dir,
//				      lower_old_dir_dentry->d_inode);
//		fsstack_copy_inode_size(old_dir,
//					lower_old_dir_dentry->d_inode);
//	}

out_err:
	mnt_drop_write(lower_new_path.mnt);
out_drop_old_write:
	mnt_drop_write(lower_old_path.mnt);
out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	wrapfs_put_lower_path(old_dentry, &lower_old_path);
	wrapfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}
*/

/*
 * The locking rules in wrapfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int wrapfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;
	struct nameidata nd;
	nd.flags = 0;
	printk(KERN_INFO "Entry");
	
	wrapfs_get_lower_path(old_dentry, &lower_old_path);
	wrapfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	printk("lower__old_dentry %s", lower_old_dentry->d_iname);
	printk("lower_new_dentry %s", lower_new_dentry->d_iname);
	printk("lower_old_dir_dentry %s", lower_old_dir_dentry->d_iname);
	printk("lower_new_dir_dentry %s", lower_new_dir_dentry->d_iname);

	printk(KERN_INFO "Before Lock 1");
	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	printk(KERN_INFO "After Lock 1");
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	printk(KERN_INFO "Before mnt_want_write_1");
	err = mnt_want_write(lower_old_path.mnt);
	if (err)
		goto out;

	printk(KERN_INFO "Before mnt_want_write_2");
	err = mnt_want_write(lower_new_path.mnt);
	if (err)
		goto out_drop_old_write;

	printk(KERN_INFO "Before vfs_rename");
	err = vfs_rename(lower_old_dir_dentry->d_inode, lower_old_dentry,
			 lower_new_dir_dentry->d_inode, lower_new_dentry);
	if (err)
		goto out_err;
	if(lower_new_dentry->d_op)
	{
		printk(KERN_INFO "dentry Ops are set");
		if(lower_new_dentry->d_op->d_revalidate)
		{
			printk(KERN_INFO "Dentry revalidation is set");
			lower_new_dentry->d_op->d_revalidate(lower_new_dentry, &nd);
		}
	}
	if(lower_new_dentry->d_inode)
	{
		printk(KERN_INFO "After vfs rename, lower dentry contains an inode.");
	}

	printk(KERN_INFO "Copying Attributes ");
	fsstack_copy_attr_all(new_dir, lower_new_dir_dentry->d_inode);

	printk("%d %d\n", new_dir->i_mode, lower_new_dir_dentry->d_inode->i_mode);
       	printk("%d %d\n", new_dir->i_uid, lower_new_dir_dentry->d_inode->i_uid);
        printk("%d %d\n", new_dir->i_gid, lower_new_dir_dentry->d_inode->i_gid);
        printk("%d %d\n", new_dir->i_rdev, lower_new_dir_dentry->d_inode->i_rdev);
        printk("%ld %ld\n", new_dir->i_atime.tv_sec, lower_new_dir_dentry->d_inode->i_atime.tv_sec);
        printk("%ld %ld\n", new_dir->i_mtime.tv_sec, lower_new_dir_dentry->d_inode->i_mtime.tv_sec);
        printk("%ld %ld\n", new_dir->i_ctime.tv_sec, lower_new_dir_dentry->d_inode->i_ctime.tv_sec);
        printk("%d %d\n", new_dir->i_blkbits, lower_new_dir_dentry->d_inode->i_blkbits);
        printk("%d %d\n", new_dir->i_flags, lower_new_dir_dentry->d_inode->i_flags);
        printk("%d %d\n", new_dir->i_nlink, lower_new_dir_dentry->d_inode->i_nlink);
        


	fsstack_copy_inode_size(new_dir, lower_new_dir_dentry->d_inode);
        printk("%lld %lld\n", new_dir->i_size, lower_new_dir_dentry->d_inode->i_size);
 
	

	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				      lower_old_dir_dentry->d_inode);
		fsstack_copy_inode_size(old_dir,
					lower_old_dir_dentry->d_inode);
	}
	
out_err:
	mnt_drop_write(lower_new_path.mnt);
out_drop_old_write:
	mnt_drop_write(lower_old_path.mnt);
out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	wrapfs_put_lower_path(old_dentry, &lower_old_path);
	wrapfs_put_lower_path(new_dentry, &lower_new_path);
	
	printk(KERN_INFO "Final Exit");
	return err;
}

int wrapfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_mkdir(lower_parent_dentry->d_inode, lower_dentry, mode);
	if (err)
		goto out;

	err = wrapfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, wrapfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);
	/* update number of links on parent directory */
	set_nlink(dir, wrapfs_lower_inode(dir)->i_nlink);

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*TODO: Remove this recursion
The program will go kaboom otherwise*/

void create_path_from_dentry(struct dentry* dentry, char* path, int *pos)
{

	if(*pos>4096)return;

	if(strcmp(dentry->d_iname, "/")!=0)
	{
		create_path_from_dentry(dentry->d_parent, path, pos);	
	
	}
	else
	{
		path[0]='/';
		*pos = *(pos) + 1;
		return;
	}
	
	printk(KERN_INFO "Adding %s", dentry->d_iname);
	strncpy(path+*pos, dentry->d_iname, strlen(dentry->d_iname));
	*pos+=strlen(dentry->d_iname);
	path[*pos]='/';
	*pos= *(pos) +1;
	return;

}


/*
TODO: Make this compatible with long names. I have just used d_iname
*/

/*static int wrapfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err = 0;
	if(!delete_flag)
		err = wrapfs_undofs_unlink(dir, dentry);
	return err;
}*/

static void fetch_qstr(struct qstr * qstr_name, char * name)
{
	qstr_name->len = strlen(name);
	qstr_name->name = name;
	qstr_name->hash = full_name_hash(name, qstr_name->len);

}


static int wrapfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err=0;
	struct dentry* trashbin_dentry=NULL;
	struct dentry* renamed_dentry=NULL;	
	struct dentry* user_trashbin_dentry=NULL;
	struct super_block *sb;
//	struct qstr renamed_name;
	struct qstr user_trashbin_qstr;
	///Make this compatible for long names.
	struct nameidata nd;
//	const char* newname = dentry->d_iname;
	uid_t user, temp_uid;	
	char* user_trashbin_string;
//	int len_renamed;
	int num_digits_uid=0;
	int user_trashbin_len=0;	
	char* trashbin_prepend_name = ".trashbin_";
	int append_pointer=0;
	int user_trashbin_mode = 0;
//	struct path path_obtained;
	char *path_original = NULL;
	char *buf = NULL;
//	int type;
	int len_orig_path = 0;
	char temp_name[PAGE_SIZE];	
	int pos = 1;
	int len_name = 0;
	struct qstr temp_qstr;
	struct dentry* temp_dentry;
	struct dentry* parent_dentry;
	struct dentry* orig_temp_dentry;
	struct dentry* orig_parent_dentry;
	int temp_imode; 
	path_original  = kmalloc(PAGE_SIZE* sizeof(char), GFP_KERNEL);
	if(!path_original)
	{
		err = -ENOMEM;
		goto path_original_out;
	}
	buf  = kmalloc(PAGE_SIZE* sizeof(char), GFP_KERNEL);
	if(!buf)
	{
		err = -ENOMEM;
		goto buf_out;
	}
	

	memset(path_original, 0, PAGE_SIZE);
	path_original = dentry_path_raw(dentry, buf, PAGE_SIZE);
	len_orig_path = strlen(path_original); // +1 for terminating null
	path_original[len_orig_path] = '/';	
	len_orig_path++;
	path_original[len_orig_path] = 0; // Terminating Null
	/*TODO: Handle 4096 length  path*/

	printk(KERN_INFO "Original Path %s", path_original);
	sb= dir->i_sb;
	user = current->real_cred->uid;
	temp_uid = user;
	
	//We need to keep count =1 for root user with uid =0. Hence do.. while
	do
	{
		num_digits_uid++;
		temp_uid/=10;		
	}while(temp_uid);
	
	printk(KERN_INFO "Uid Length %d", num_digits_uid);	
	
	user_trashbin_len = strlen(trashbin_prepend_name) + num_digits_uid + 1;
	user_trashbin_string = kmalloc(user_trashbin_len, GFP_KERNEL);
	
	//+1 for the null
	if(!user_trashbin_string)
	{
		err = -ENOMEM;
		goto out;

	} // code enomem

	// Copying characters from prepend string 
	strncpy(user_trashbin_string, trashbin_prepend_name, strlen(trashbin_prepend_name));

	user_trashbin_string[user_trashbin_len-1] = 0;
	append_pointer = user_trashbin_len -2; 
	printk(KERN_INFO "Append pointer %d", append_pointer);
	temp_uid = user;
	do
	{
			user_trashbin_string[append_pointer] = temp_uid%10 + '0';
			temp_uid/=10;
			append_pointer--;
	}while(temp_uid);

	printk(KERN_INFO "User Trashbin String %s", user_trashbin_string);
	
	trashbin_dentry = dget(WRAPFS_SB(sb)->trashbin_dentry);  //Upper dentry of the trashbin
	//global trashbin dentry

	if(trashbin_dentry)
		printk(KERN_INFO "%s - Upper TRASHBIN DENTRY", trashbin_dentry->d_iname);
	//else ???
	/*TODO: If global trashbin does not exist then?*/

	// We need to search for user_trashbin_string inside the dentry of the global trashbin
	// We will need to create a new dentry for this user_trashbin_string and ->wrapfs_lookup it.
	// This will create the necessary interpose for us to call mkdir (if the user's directory does not exist
	//Or to access the positive dentry for rename!

	user_trashbin_qstr.len = user_trashbin_len;
	user_trashbin_qstr.name = user_trashbin_string;
	user_trashbin_qstr.hash = full_name_hash(user_trashbin_string, user_trashbin_len);
	user_trashbin_dentry =  d_alloc(trashbin_dentry, &user_trashbin_qstr);
	nd.flags = LOOKUP_DIRECTORY; // user_trashbin is a directory
	wrapfs_lookup(trashbin_dentry->d_inode, user_trashbin_dentry, &nd);

	if(user_trashbin_dentry->d_inode == NULL)
	{
		// Negative user_trashbbin dentry. We need to mkdir a directory (trashbin_xxx)
		user_trashbin_mode =  S_IFDIR | S_IRWXU;
		wrapfs_mkdir(trashbin_dentry->d_inode, user_trashbin_dentry, user_trashbin_mode);
	        if(!user_trashbin_dentry->d_inode)
		{
			printk("Did not receive inode for new trashbin at first");
		}

	}
	// We get the user trashbin dentry
	//Once we have the trashbin dentry, we need to create/access the user directory

	parent_dentry = dget(user_trashbin_dentry);
	orig_parent_dentry = dget(sb->s_root);
	while(path_original[pos]!=0)
	{
		if(path_original[pos] == '/')
		{
			pos++;
			temp_name[len_name] = 0; // terminal name
			printk(KERN_INFO "Temp name: %s %d", temp_name, len_name);

			if(path_original[pos] == 0)
				nd.flags = 0; // user_trashbin is a directory

			else
				nd.flags = LOOKUP_DIRECTORY;
			
			fetch_qstr(&temp_qstr, temp_name);
			temp_dentry = d_alloc(parent_dentry, &temp_qstr);
			wrapfs_lookup(parent_dentry->d_inode, temp_dentry, &nd);

			orig_temp_dentry =  d_alloc(orig_parent_dentry, &temp_qstr);
			wrapfs_lookup(orig_parent_dentry->d_inode, orig_temp_dentry, &nd);
			
	//		temp_imode = S_IRWXU;
	//		if(orig_temp_dentry)
	//		{
			// Only if user has permission to lookup in this directory will it get a positive dentry.
	//			if(orig_temp_dentry->d_inode)
					temp_imode = orig_temp_dentry->d_inode->i_mode;		
	//		}

			/// TODO: We need i_mode of original directory, and need to use umask()
	
			if(path_original[pos]!=0)
			{
				if(temp_dentry->d_inode == NULL )
					wrapfs_mkdir(parent_dentry->d_inode, temp_dentry, temp_imode);
					
				dput(parent_dentry);
				parent_dentry = dget(temp_dentry);
				dput(orig_parent_dentry);
				orig_parent_dentry = dget(orig_temp_dentry);
	
			}

			else 
				renamed_dentry = dget(temp_dentry);

			dput(temp_dentry);
			dput(orig_temp_dentry);
			len_name = 0;
		}
		else
			temp_name[len_name++] = path_original[pos++];
	}
		

	if(renamed_dentry)
	{
		if(!renamed_dentry->d_inode)printk(KERN_INFO "New Negative Dentry %s", renamed_dentry->d_iname);
	}

	wrapfs_rename(dentry->d_parent->d_inode, dentry, parent_dentry->d_inode, renamed_dentry);

out:

	printk(KERN_INFO "Before renamed_dentry");
	dput(renamed_dentry);
	printk(KERN_INFO "Before trashbin_dentry");
	dput(trashbin_dentry);
	printk(KERN_INFO "Before user_trashbin_dentry");
	dput(user_trashbin_dentry);
	printk(KERN_INFO "Before parent_dentry");
	dput(parent_dentry);
	printk(KERN_INFO "Before orig_parent_dentry");
	dput(orig_parent_dentry);
	if(user_trashbin_string)
	{
		
		printk(KERN_INFO "Before kfree 1");
		kfree(user_trashbin_string);
	}
free_buf:
	if(buf)
	{
		
		printk(KERN_INFO "Before kfree buf");
		kfree(buf);	
	}
buf_out:
	if(path_original)
	{
		
		printk(KERN_INFO "Before kfree path_original");
		kfree(path_original);
	
	}
//ath_put(&path_obtained);
path_original_out:
	return err;
}

static int wrapfs_normal_unlink(struct inode *dir, struct dentry *dentry)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode = wrapfs_lower_inode(dir);
	struct dentry *lower_dir_dentry;
	struct path lower_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_unlink(lower_dir_inode, lower_dentry);
	printk(KERN_INFO "In wrapfs_normal_unlink\n");
	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS
	 * below.  Silly-renamed files will get deleted by NFS later on, so
	 * we just need to detect them here and treat such EBUSY errors as
	 * if the upper file was successfully deleted.
	 */
	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
		err = 0;
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(dentry->d_inode,
		  wrapfs_lower_inode(dentry->d_inode)->i_nlink);
	dentry->d_inode->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	wrapfs_put_lower_path(dentry, &lower_path);
	printk(KERN_INFO "returning back from here\n");
	return err;
}

int trashbin_file_delete(char* file_name, struct super_block *sb)
{
	int user, temp_uid, err=0;
	int num_digits_uid = 0;
	int user_trashbin_len;
	char* trashbin_prepend_name = ".trashbin_";
	char* user_trashbin_string = NULL;
	int append_pointer;
	struct dentry* trashbin_dentry = NULL;
	struct dentry* user_trashbin_dentry = NULL;
	struct qstr user_trashbin_qstr;
	struct qstr file_qstr;
	struct dentry* file_dentry = NULL;
	struct nameidata nd;
	
	/* fetch current user */
	user = current->real_cred->uid;
	temp_uid = user;
	
	/*We need to keep count =1 for root user with uid =0. Hence do.. while */
	do
	{
		num_digits_uid++;
		temp_uid/=10;		
	}while(temp_uid);
	
	printk(KERN_INFO "Uid Length %d", num_digits_uid);	
	
	user_trashbin_len = strlen(trashbin_prepend_name) + num_digits_uid + 1;
	user_trashbin_string = kmalloc(user_trashbin_len, GFP_KERNEL);
	//+1 for the null
	if(!user_trashbin_string)
	{
		err = -ENOMEM;
		goto out;

	} // code enomem

	// Copying characters from prepend string 
	strncpy(user_trashbin_string, trashbin_prepend_name, strlen(trashbin_prepend_name));

	user_trashbin_string[user_trashbin_len-1] = 0;
	append_pointer = user_trashbin_len -2; 
	printk(KERN_INFO "Append pointer %d", append_pointer);
	temp_uid = user;
	do
	{
			user_trashbin_string[append_pointer] = temp_uid%10 + '0';
			temp_uid/=10;
			append_pointer--;
	}while(temp_uid);

	printk(KERN_INFO "User Trashbin String %s", user_trashbin_string);
	
	trashbin_dentry = dget(WRAPFS_SB(sb)->trashbin_dentry);  //Upper dentry of the trashbin
	
	if(trashbin_dentry)
		printk(KERN_INFO "%s - Upper TRASHBIN DENTRY", trashbin_dentry->d_iname);

	// We need to search for user_trashbin_string inside the dentry of the global trashbin
	// We will need to create a new dentry for this user_trashbin_string and ->wrapfs_lookup it.
	// This will create the necessary interpose for us to call mkdir (if the user's directory does not exist
	//Or to access the positive dentry for rename!

	user_trashbin_qstr.len = user_trashbin_len;
	user_trashbin_qstr.name = user_trashbin_string;
	user_trashbin_qstr.hash = full_name_hash(user_trashbin_string, user_trashbin_len);
	user_trashbin_dentry =  d_alloc(trashbin_dentry, &user_trashbin_qstr);
	nd.flags = LOOKUP_DIRECTORY; // user_trashbin is a directory
	wrapfs_lookup(trashbin_dentry->d_inode, user_trashbin_dentry, &nd);

	if(user_trashbin_dentry->d_inode == NULL)
	{
		//This condition should not occur. This means that the user has deleted the trashbin directory.
		/*TODO: Ensure that this condition is handled*/	
		printk(KERN_INFO "Negative user_trashbin_dentry: Inode NULL\n");
	}
	
	/*TODO: Handle directories. For that nd.flags has to differ. Pass that parameter from the 
	ioctl function somehow.*/
	file_qstr.len = strlen(file_name);
	file_qstr.name = file_name;
	file_qstr.hash = full_name_hash(file_name, strlen(file_name));
	
	file_dentry =  d_alloc(user_trashbin_dentry, &file_qstr);
	nd.flags = 0;
	wrapfs_lookup(user_trashbin_dentry->d_inode,file_dentry, &nd); 
	if(!file_dentry->d_inode)
	{
		err = -ENOENT;
		goto out;
	}
	else
	{
		printk(KERN_INFO "Received positive dentry for the file to restore");
	}

	
	err = wrapfs_normal_unlink(user_trashbin_dentry->d_inode, file_dentry);

out:
	if(user_trashbin_string)
		kfree(user_trashbin_string);
	dput(trashbin_dentry);
	dput(user_trashbin_dentry);
	dput(file_dentry);
	return err;
}

static int wrapfs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_symlink(lower_parent_dentry->d_inode, lower_dentry, symname);
	if (err)
		goto out;
	err = wrapfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, wrapfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}



/*TODO: Put Common code in a single method--
	-> Put conversion of user data into corrosponding trashbin in a separate function
	-> This can be reused in ->unlink and ->restore*/

int restore(char* file_name, struct super_block* sb)
{
	int user, temp_uid, err=0;
	int valid_original_path = 1;
	int num_digits_uid = 0;
	int user_trashbin_len;
	char* trashbin_prepend_name = ".trashbin_";
	char* user_trashbin_string = NULL;
	int append_pointer;
	struct dentry* trashbin_dentry = NULL;
	struct dentry* user_trashbin_dentry=NULL;
	struct qstr user_trashbin_qstr;
	struct qstr file_qstr;
	struct dentry* file_dentry = NULL;
	struct nameidata nd;
	struct path path_obtained;
	char received_path[PATH_LEN_MAX];
	int received_path_len =0;
	char parent_path[PATH_LEN_MAX];
	int parent_path_len;
	struct dentry* restore_dentry=NULL;
	struct path *lower_path;
	struct nameidata nd1;	
	struct dentry* rd = NULL;
	char* original_path = NULL;
	int pos = 0, numslash = 0;
	int file_type;
	struct dentry* parent_dentry;
	struct dentry* trashbin_parent_dentry;
	struct dentry* trashbin_temp_dentry;
	char temp_name[PAGE_SIZE];
	int len_name = 0;
	struct qstr temp_qstr;
	struct dentry* temp_dentry;
	int temp_imode = S_IRWXU;
	struct dentry* path_terminal_dentry = NULL;
	int len_orig_path = 0;
	struct dentry* err_ptr;
	//malloc for lower_path
	lower_path = kmalloc(sizeof(struct path), GFP_KERNEL);
	lower_path->dentry = NULL;
	lower_path->mnt = NULL;	
	//
	user = current->real_cred->uid;
	temp_uid = user;
	
	//We need to keep count =1 for root user with uid =0. Hence do.. while
	do
	{
		num_digits_uid++;
		temp_uid/=10;		
	}while(temp_uid);
	
	printk(KERN_INFO "Uid Length %d", num_digits_uid);	
	
	user_trashbin_len = strlen(trashbin_prepend_name) + num_digits_uid + 1;
	user_trashbin_string = kmalloc(user_trashbin_len, GFP_KERNEL);
	//+1 for the null
	if(!user_trashbin_string)
	{
		err = -ENOMEM;
		goto out;

	} // code enomem

	// Copying characters from prepend string 
	strncpy(user_trashbin_string, trashbin_prepend_name, strlen(trashbin_prepend_name));

	user_trashbin_string[user_trashbin_len-1] = 0;
	append_pointer = user_trashbin_len -2; 
	printk(KERN_INFO "Append pointer %d", append_pointer);
	temp_uid = user;
	do
	{
			user_trashbin_string[append_pointer] = temp_uid%10 + '0';
			temp_uid/=10;
			append_pointer--;
	}while(temp_uid);

	printk(KERN_INFO "User Trashbin String %s", user_trashbin_string);
	
	trashbin_dentry = dget(WRAPFS_SB(sb)->trashbin_dentry);  //Upper dentry of the trashbin
	
	if(trashbin_dentry)
		printk(KERN_INFO "%s - Upper TRASHBIN DENTRY", trashbin_dentry->d_iname);

	// We need to search for user_trashbin_string inside the dentry of the global trashbin
	// We will need to create a new dentry for this user_trashbin_string and ->wrapfs_lookup it.
	// This will create the necessary interpose for us to call mkdir (if the user's directory does not exist
	//Or to access the positive dentry for rename!

	user_trashbin_qstr.len = user_trashbin_len;
	user_trashbin_qstr.name = user_trashbin_string;
	user_trashbin_qstr.hash = full_name_hash(user_trashbin_string, user_trashbin_len);
	user_trashbin_dentry =  d_alloc(trashbin_dentry, &user_trashbin_qstr);
	nd.flags = LOOKUP_DIRECTORY; // user_trashbin is a directory
	wrapfs_lookup(trashbin_dentry->d_inode, user_trashbin_dentry, &nd);

	if(user_trashbin_dentry->d_inode == NULL)
	{
		//This condition should not occur. This means that the user has deleted the trashbin directory.
		/*TODO: Ensure that this condition is handled*/	
	}
	
	//First we query for a directory by default. If the lookup location is not a directory, we lookup again

	err = vfs_path_lookup(sb->s_root, current->fs->pwd.mnt , file_name, LOOKUP_DIRECTORY , &path_obtained);
	file_type = DIRECTORY;
	
	if(err == -ENOTDIR)
	{
		err = vfs_path_lookup(sb->s_root, current->fs->pwd.mnt , file_name, 0 , &path_obtained);
		file_type = NORMAL_FILE;
	}
	if(err < 0)
	{
		err = -ENOENT;
		goto out;
	}

	
	if(path_obtained.dentry)
	{
		if(path_obtained.dentry->d_inode)
		{	
			printk(KERN_INFO "1 otained +ve dentry to parent %s", path_obtained.dentry->d_iname);
			wrapfs_get_lower_path(path_obtained.dentry, lower_path);
			printk("Hiii");
			if(lower_path->dentry)
			{
				printk("Lower dentry for %s", lower_path->dentry->d_iname);
			}			
		}
	}

	
	while(file_name[pos]!=0)
	{
		if(file_name[pos]=='/' && numslash ==1)
		{
			numslash++;
			original_path = file_name + pos;
			break;
		}
		else if(file_name[pos]=='/')
			numslash++;
		
		pos++;
	}


	// Add a / if not already there
	len_orig_path = strlen(original_path); // +1 for terminating null

	if(original_path[len_orig_path-1] != '/')
	{
		original_path[len_orig_path] = '/';
		len_orig_path++;
		original_path[len_orig_path] = 0;
	}	


	if(numslash!=2)
	{
		//malformed path
		err = -ENOENT;
		goto path_put;
	}

	printk(KERN_INFO "Original path: %s ", original_path);
	//once we receive the original path, we must make the path if it does not exist


	if(err = -ENOENT || err == 0)
	{
		err = 0;
	}
	else
	{
		goto path_put;
	}
//////////////////////////////////////
	pos = 1;
	trashbin_parent_dentry = dget(user_trashbin_dentry);
	parent_dentry = dget(sb->s_root);


/* TODO: What if the process of rename fails? How do we delete the directory structure?*/

	while(original_path[pos]!=0)
	{
		if(original_path[pos] == '/')
		{
			pos++;
			temp_name[len_name] = 0; // terminal name
			printk(KERN_INFO "RESTORE: Temp name: %s %d", temp_name, len_name);

			if(original_path[pos] == 0)
			{
				// Looks up directory/file as per the type
				nd.flags = file_type? 0: LOOKUP_DIRECTORY; 
			}
			else
				nd.flags = LOOKUP_DIRECTORY;
			
			fetch_qstr(&temp_qstr, temp_name);

			temp_dentry = d_alloc(parent_dentry, &temp_qstr);
			err_ptr = wrapfs_lookup(parent_dentry->d_inode, temp_dentry, &nd);

			trashbin_temp_dentry = d_alloc(trashbin_parent_dentry, &temp_qstr);
			wrapfs_lookup(trashbin_parent_dentry->d_inode, trashbin_temp_dentry, &nd);

			
			temp_imode = trashbin_temp_dentry->d_inode->i_mode;		

			/// TODO: We need i_mode of original directory, and need to use umask()
	
			if(original_path[pos]!=0)
			{
				if(temp_dentry->d_inode == NULL) // We assume that the error here is only EACCES
					wrapfs_mkdir(parent_dentry->d_inode, temp_dentry, temp_imode);
					
				dput(parent_dentry);
				parent_dentry = dget(temp_dentry);
				dput(trashbin_parent_dentry);
				trashbin_parent_dentry = dget(trashbin_temp_dentry);
	
			}

			else 
			{
				restore_dentry = dget(temp_dentry); // This will be negative
				path_terminal_dentry = dget(trashbin_temp_dentry); // This will be positive
			}
			dput(temp_dentry);
			dput(trashbin_temp_dentry);
			len_name = 0;
		}
		else
			temp_name[len_name++] = original_path[pos++];
	}
	
	if(restore_dentry)
	{
		if(!restore_dentry->d_inode)printk(KERN_INFO "RESTORE:New Negative Dentry %s", restore_dentry->d_iname);
	}

	wrapfs_rename(trashbin_parent_dentry->d_inode, path_terminal_dentry, parent_dentry->d_inode, restore_dentry);
	nd.flags = file_type? 0: LOOKUP_DIRECTORY; 
	wrapfs_lookup(parent_dentry->d_inode, restore_dentry, &nd);



//////////////end////////////////////////

//	else
//		{
//			printk(KERN_INFO "Not found!");
//		}	
//	}



/*TODO: Handle directories. For that nd.flags has to differ. Pass that parameter from the 
	ioctl function somehow.*/
/*	file_qstr.len = strlen(file_name);
	file_qstr.name = file_name;
	file_qstr.hash = full_name_hash(file_name, strlen(file_name));
	
	file_dentry =  d_alloc(user_trashbin_dentry, &file_qstr);
	nd.flags = 0;
	wrapfs_lookup(user_trashbin_dentry->d_inode,file_dentry, &nd); 
	if(!file_dentry->d_inode)
	{
		err = -ENOENT;
		goto out;
	}
	else
	{
		printk(KERN_INFO "Received positive dentry for the file to restore");
	}
*/
//	received_path_len = wrapfs_getxattr(file_dentry, "user.path", received_path, PATH_LEN_MAX);	
//	printk(KERN_INFO "Received Xattr %s and length %d", received_path, received_path_len);

//	if(received_path_len <=0)
//	{
		// This happens when extended attributes are missing
		/*TODO: WHat error to show here*/
//		err = -EINVAL;
//		goto out;
//	}

	/* TODO: We need to change these vfs_path_lookup functions. Or find out a way to get the vfsmount structure
	apart from the present working directory. Maybe we could do it by stuffin git in superblocks private 
	pointer during mount. But how can we obtain the vfsmount during mount. We are missing something for sure*/

//	parent_path_len = received_path_len - strlen(file_name);
//	strncpy(parent_path, received_path, parent_path_len -1);
//	parent_path[parent_path_len-1] = 0;
//	printk( KERN_INFO "%s", parent_path);
	
//	err = vfs_path_lookup(sb->s_root, current->fs->pwd.mnt , parent_path, LOOKUP_DIRECTORY , &path_obtained);
//	if(path_obtained.dentry)
//	{
//		if(path_obtained.dentry->d_inode)
//		{	
//			printk(KERN_INFO "1 tained +ve dentry to parent %s", path_obtained.dentry->d_iname);
//			wrapfs_get_lower_path(path_obtained.dentry, lower_path);
//			printk("Hiii");
//			if(lower_path->dentry)
//			{
//				printk("Lower dentry for %s", lower_path->dentry->d_iname);
//			}			
//		}
//		else
//		{
//			printk(KERN_INFO "Not found!");
//		}	
//	}

	/* The Killer Blow!*/
	//path_obtained contains the restoration dentry
/*	restore_dentry = d_alloc(path_obtained.dentry, &file_qstr);
	nd1.flags = 0;
	wrapfs_lookup(path_obtained.dentry->d_inode, restore_dentry, &nd1);
	if(restore_dentry->d_inode)
	{
		err = -EEXIST;
		goto path_put;
	}
	
        wrapfs_rename(user_trashbin_dentry->d_inode, file_dentry, path_obtained.dentry->d_inode, restore_dentry);

	rd =  d_alloc(path_obtained.dentry, &file_qstr);
	nd1.flags =0;
	wrapfs_lookup(path_obtained.dentry->d_inode, rd, &nd1);
*/
//wrapfs_get_lower_path(restore_dentry, lower_path);
	//		printk("Hiii");
	//		if(lower_path->dentry)
	//		{
	//			printk("Lower dentry for %s", lower_path->dentry->d_iname);
	//			}			
	

	/*TODO: Remove Extended Attribute somehow. vfs_path_lookup causing deadlock and restore_dentry does not have inode yet*/
	//wrapfs_lookup(path_obtained.dentry->d_inode, restore_dentry, &nd1);
	//	wrapfs_removexattr(, "user.path")
dentry_put:
	dput(restore_dentry);
	dput(trashbin_parent_dentry);
	dput(parent_dentry);
	dput(path_terminal_dentry);
path_put:
//	dput(rd);
	path_put(&path_obtained);
//	path_put(lower_path);
out:
	if(user_trashbin_string)
	kfree(user_trashbin_string);
	dput(trashbin_dentry);
	dput(user_trashbin_dentry);
	dput(file_dentry);
	return err;
}

// TODO: Handle empty directory deletion
static int wrapfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path lower_path;
	
	printk(KERN_INFO "Inside rmdir");
	
	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_rmdir(lower_dir_dentry->d_inode, lower_dentry);
	if (err)
		goto out;

	printk(KERN_INFO "Before DROPPING");
 
	d_drop(dentry);	 //drop our dentry on success (why not VFS's job?) 
	if (dentry->d_inode)
		clear_nlink(dentry->d_inode);
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
	set_nlink(dir, lower_dir_dentry->d_inode->i_nlink);

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;

}

static int wrapfs_mknod(struct inode *dir, struct dentry *dentry, int mode,
			dev_t dev)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_mknod(lower_parent_dentry->d_inode, lower_dentry, mode, dev);
	if (err)
		goto out;

	err = wrapfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, wrapfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}



static int wrapfs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!lower_dentry->d_inode->i_op ||
	    !lower_dentry->d_inode->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = lower_dentry->d_inode->i_op->readlink(lower_dentry,
						    buf, bufsiz);
	if (err < 0)
		goto out;
	fsstack_copy_attr_atime(dentry->d_inode, lower_dentry->d_inode);

out:
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}

static void *wrapfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		goto out;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = wrapfs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = ERR_PTR(err);
	} else {
		buf[err] = '\0';
	}
out:
	nd_set_link(nd, buf);
	return NULL;
}

/* this @nd *IS* still used */
static void wrapfs_put_link(struct dentry *dentry, struct nameidata *nd,
			    void *cookie)
{
	char *buf = nd_get_link(nd);
	if (!IS_ERR(buf))	/* free the char* */
		kfree(buf);
}

static int wrapfs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err;

	lower_inode = wrapfs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);
	return err;
}

static int wrapfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;

	inode = dentry->d_inode;

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = inode_change_ok(inode, ia);
	if (err)
		goto out_err;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = wrapfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = wrapfs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use lower_dentry->d_inode, because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	err = notify_change(lower_dentry, &lower_ia); /* note: lower_ia */
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	wrapfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}


/* This is lifted from fs/xattr.c */
void *wrapfs_xattr_alloc(size_t size, size_t limit)
{
        void *ptr;

        if (size > limit)
                return ERR_PTR(-E2BIG);

        if (!size)              /* size request, no buffer is needed */
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
	if(!lower_dentry)
	{
		printk(KERN_INFO "Null dentry");
		goto out;
	}
	if(!lower_dentry->d_inode)
	{
		printk(KERN_INFO "Negative dentry - Not filled after rename :(");
		goto out;

	}
        if (!lower_dentry->d_inode->i_op->setxattr) {
                rc = -EOPNOTSUPP;
                goto out;
        }
        rc = vfs_setxattr(lower_dentry, name, value, size, flags);
out:
        wrapfs_put_lower_path(dentry, &lower_path);
        return rc;
}

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



const struct inode_operations wrapfs_symlink_iops = {
	.readlink	= wrapfs_readlink,
	.permission	= wrapfs_permission,
	.follow_link	= wrapfs_follow_link,
	.setattr	= wrapfs_setattr,
	.put_link	= wrapfs_put_link,
        .setxattr       = wrapfs_setxattr,
        .getxattr       = wrapfs_getxattr,
        .listxattr      = wrapfs_listxattr,
        .removexattr    = wrapfs_removexattr
};

const struct inode_operations wrapfs_dir_iops = {
	.create		= wrapfs_create,
	.lookup		= wrapfs_lookup,
	.link		= wrapfs_link,
	.unlink		= wrapfs_unlink,
	.symlink	= wrapfs_symlink,
	.mkdir		= wrapfs_mkdir,
	.rmdir		= wrapfs_rmdir,
	.mknod		= wrapfs_mknod,
	.rename		= wrapfs_rename,
	.permission	= wrapfs_permission,
	.setattr	= wrapfs_setattr,
        .setxattr       = wrapfs_setxattr,
        .getxattr       = wrapfs_getxattr,
        .listxattr      = wrapfs_listxattr,
        .removexattr    = wrapfs_removexattr

};

const struct inode_operations wrapfs_main_iops = {
	.permission	= wrapfs_permission,
	.setattr	= wrapfs_setattr,
        .setxattr 	= wrapfs_setxattr,
        .getxattr 	= wrapfs_getxattr,
        .listxattr 	= wrapfs_listxattr,
        .removexattr 	= wrapfs_removexattr
};