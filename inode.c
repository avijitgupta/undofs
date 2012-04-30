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
#include <linux/time.h>
#include <asm/unistd.h>
#include <linux/namei.h>
#include <linux/stat.h>
#include <linux/capability.h>
#include <linux/cred.h>

#define UID_MAX_LEN 10
#define PATH_LEN_MAX 4096
#define DIRECTORY 0
#define NORMAL_FILE 1

//#define DELETE_KEEPING_SAME_NAME

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

	#ifdef DEBUG
	printk("lower_old_dentry name : %s", lower_old_dentry->d_iname);
	printk("lower_new_dentry name : %s", lower_new_dentry->d_iname);
	printk("lower_old_dir_dentry  :%s", lower_old_dir_dentry->d_iname);
	printk("lower_new_dir_dentry  : %s", lower_new_dir_dentry->d_iname);
	#endif

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
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

	if(lower_new_dentry->d_op)
	{
		if(lower_new_dentry->d_op->d_revalidate)
		{
			lower_new_dentry->d_op->d_revalidate(lower_new_dentry, &nd);
		}
	}

	fsstack_copy_attr_all(new_dir, lower_new_dir_dentry->d_inode);
	fsstack_copy_inode_size(new_dir, lower_new_dir_dentry->d_inode);

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

/* 
 * Actual version of wrapfs_unlink changed to wrapfs_normal_unlink to
 * make it work for undofs
 */
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
	
	#ifdef DEBUG
	printk(KERN_INFO "Entering wrapfs_normal_unlink\n");
	#endif
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
	return err;
}

/* For filling a struct qstr using a file/dir name */
static void fetch_qstr(struct qstr * qstr_name, char * name)
{
	qstr_name->len = strlen(name);
	qstr_name->name = name;
	qstr_name->hash = full_name_hash(name, qstr_name->len);

}

/* For converting a long int to a string */
void my_itoa(char *str, long int num){
	int i = 10;
	long int rem = 0;
	str[i--] = 0;
        while(num!=0)
	{
                rem = num/10;
                rem = num - rem*10;
                str[i--] = rem + '0';
                num = num/10;
        }
}

/*
 * This is the version of unlink called when a user deletes a file.
 * This moves the to-be-deleted file to user_trashbin using wrapfs_rename
 */
static int wrapfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err = 0;
	struct super_block *sb;
	struct nameidata nd;
	int num_digits_uid=0;
	int user_trashbin_len=0;	
	int append_pointer=0;
	int user_trashbin_mode = 0;
	int len_orig_path = 0;
	int temp_imode; 
	int pos = 1, i=1;
	int len_name = 0;
	int flag =0;
	uid_t user, temp_uid;	
	char* p_o;
	char *buf = NULL;
	char* user_trashbin_string;
	char temp_name[PAGE_SIZE];	
	char timestamp_string[15];
	char* path_original=NULL;
	char* trashbin_prepend_name = ".trashbin_";
	struct dentry* err_dentry;
	struct dentry* trashbin_dentry = NULL;
	struct dentry* renamed_dentry = NULL;	
	struct dentry* user_trashbin_dentry = NULL;
	struct dentry* temp_dentry = NULL;
	struct dentry* parent_dentry = NULL;
	struct dentry* orig_temp_dentry = NULL;
	struct dentry* orig_parent_dentry = NULL;
	struct dentry* trash_dentry = NULL;
	struct qstr temp_qstr;
	struct qstr trash_qstr;
	struct qstr user_trashbin_qstr;
	long int timestamp;

	buf  = (char*)kmalloc(PAGE_SIZE, GFP_KERNEL);
	if(!buf) {
		err = -ENOMEM;
		goto out;
	}
	
	path_original = (char*)kmalloc(PAGE_SIZE, GFP_KERNEL);
	if(!path_original) {
		err = -ENOMEM;
		goto free_buf;
	}
	memset(path_original, 0, PAGE_SIZE);

	/* fetches the path of the file from the mount point */
	p_o = dentry_path_raw(dentry, buf, PAGE_SIZE);
	strcpy(path_original, p_o);	

	len_orig_path = strlen(path_original);
	if(path_original[len_orig_path-1]!='/') {
		path_original[len_orig_path] = '/';	
		len_orig_path++;
		path_original[len_orig_path] = 0;
	}

	#ifdef DEBUG
	printk(KERN_INFO "File Path : %s", path_original);
	#endif

	while(i < strlen(path_original) && path_original[i]!='/') {
		temp_name[i-1] = path_original[i];
		i++;
	}	
	temp_name[i] = 0; 

	/* 
	 * If a user deletes a file from the trashbin then normal unlink 
	 * should be called and file be deleted premanently from the trash 
	 */
	if(strcmp(temp_name, ".trash") == 0) {
		#ifdef DEBUG
		printk(KERN_INFO "Trashbin file delete");
		#endif
		kfree(buf);
		kfree(path_original);
		err = wrapfs_normal_unlink(dir, dentry);
		return err;
	}

	/* retrieves the user credentials like userid */
	sb= dir->i_sb;
	user = current->real_cred->uid;
	temp_uid = user;
	
	/* find the length of the userid */
	do {
		num_digits_uid++;
		temp_uid/=10;		
	}while(temp_uid);
	
	user_trashbin_len = strlen(trashbin_prepend_name) + num_digits_uid + 1;
	user_trashbin_string = (char*)kmalloc(user_trashbin_len, GFP_KERNEL);
	if(!user_trashbin_string) {
		err = -ENOMEM;
		goto free_path_original;
	}

	/* Copying characters from prepend string */
	strncpy(user_trashbin_string, trashbin_prepend_name, 
		strlen(trashbin_prepend_name));

	user_trashbin_string[user_trashbin_len-1] = 0;
	append_pointer = user_trashbin_len - 2; 
	temp_uid = user;
	
	/* creates a user_trashbin_<userid> name */
	do {
		user_trashbin_string[append_pointer] = temp_uid%10 + '0';
		temp_uid/=10;
		append_pointer--;
	}while(temp_uid);

	/* dentry of the global trashbin */	
	if(!WRAPFS_SB(sb)->trashbin_dentry){
		err = -EPERM;
		goto free_uts;
	}
	
	trashbin_dentry = dget(WRAPFS_SB(sb)->trashbin_dentry); 
	/* 
	 * Search for user_trashbin_string inside global trashbin. Create a 
	 * new dentry for this user_trashbin_string and ->wrapfs_lookup it. 
	 */ 
	user_trashbin_qstr.len = user_trashbin_len;
	user_trashbin_qstr.name = user_trashbin_string;
	user_trashbin_qstr.hash = full_name_hash(user_trashbin_string, 
							user_trashbin_len);
	user_trashbin_dentry =  d_alloc(trashbin_dentry, &user_trashbin_qstr);
	nd.flags = LOOKUP_DIRECTORY; 
	err_dentry = wrapfs_lookup(trashbin_dentry->d_inode, user_trashbin_dentry, &nd);
	err =  PTR_ERR(err_dentry);
	if(IS_ERR(err_dentry) && err!=-ENOENT){
		goto free_utd;	
	}


	/* 
	 * if user_trashbin is not found in the global trashbin, 
	 * then user_trashbin_dentry is negative. Hence, we need to create
	 * the user_trashbin directory. 
	 */
	if(user_trashbin_dentry->d_inode == NULL) {		
		user_trashbin_mode =  S_IFDIR | S_IRWXU;
		err = wrapfs_mkdir(trashbin_dentry->d_inode, user_trashbin_dentry,
							 user_trashbin_mode);
	        if(err< 0) {
			#ifdef DEBUG
			printk(KERN_INFO "user_trashbin not created.");
			#endif
			goto free_utd;
		}
	}

	parent_dentry = dget(user_trashbin_dentry);
	orig_parent_dentry = dget(sb->s_root);
	len_name = 0;

	/* 
	 * Iterate over whole path and check if directories in the trashbin 
	 * path are created or not. If not created, then create them with the
	 * same mode as the original directory in the path 
	 */
	while(path_original[pos]!=0) {
		if(path_original[pos] == '/') {	
			pos++;
			temp_name[len_name] = 0;
			if(path_original[pos] == 0)
				nd.flags = 0;			/* for file */
			else
				nd.flags = LOOKUP_DIRECTORY;	/* for dir */
				
			/* lookup for file/dir in the user_trashbin*/
			fetch_qstr(&temp_qstr, temp_name);
			temp_dentry = d_alloc(parent_dentry, &temp_qstr);
			err_dentry= wrapfs_lookup(parent_dentry->d_inode,temp_dentry,&nd);
			err =  PTR_ERR(err_dentry);
			if(IS_ERR(err_dentry) && err!=-ENOENT){
				dput(temp_dentry);
				d_drop(temp_dentry);
				goto dput_parents;	
			}

			/* lookup for file/dir in the original dir for mode */
			orig_temp_dentry =  d_alloc(orig_parent_dentry, &temp_qstr);
			err_dentry = wrapfs_lookup(orig_parent_dentry->d_inode, 
							orig_temp_dentry, &nd);
				
			err =  PTR_ERR(err_dentry);
			if(IS_ERR(err_dentry) && err!=-ENOENT){
				dput(temp_dentry);
				d_drop(temp_dentry);
				dput(orig_temp_dentry);
				goto dput_parents;	
			}

			temp_imode = orig_temp_dentry->d_inode->i_mode;		

			/// TODO:need to use umask()
	
			/* if we are in the middle of the path */
			if(path_original[pos]!=0) {
				/* if the directory doesn't exist in trashbin */
				if(temp_dentry->d_inode == NULL){
					err = wrapfs_mkdir(parent_dentry->d_inode, 
						temp_dentry, temp_imode);
					if(err<0) {
						dput(temp_dentry);
						d_drop(temp_dentry);
						dput(orig_temp_dentry);
						d_drop(orig_temp_dentry); 
						goto dput_parents;
					}
				}
				/*update trashbin parent and original parent */
				dput(parent_dentry);
				parent_dentry = dget(temp_dentry);
				dput(orig_parent_dentry);
				orig_parent_dentry = dget(orig_temp_dentry);
			}
			else 
				renamed_dentry = dget(temp_dentry);

			/* dput and d_drop the temporary dentries */
			dput(temp_dentry);
			d_drop(temp_dentry);
			dput(orig_temp_dentry);
			d_drop(orig_temp_dentry);
			len_name = 0;
		}
		else
			temp_name[len_name++] = path_original[pos++];
	}

	/* if the file/dir to be deleted exists in the trashbin */
	if(renamed_dentry->d_inode) {
		#ifdef DEBUG
		printk(KERN_INFO "File Exists in trashbin");
		#endif

		/* get a unique timstamp (atime) for renaming the file */
		timestamp = dentry->d_inode->i_atime.tv_sec;
		len_name = strlen(temp_name);
		temp_name[len_name] = '_';
		len_name++;
		my_itoa(timestamp_string, timestamp);

		/* if name becomes greater than PAGE_SIZE len, then abort */
		if(strlen(temp_name) + strlen(timestamp_string) > PAGE_SIZE) {
			err = -EEXIST;
			goto top_out;
		}		
		
		/* find length of the filename and terminate with the null */
		for(i = 0; i <= strlen(timestamp_string); i++) {
			temp_name[len_name] = timestamp_string[i];
			len_name++;
		}
		temp_name[len_name] = 0;

		/* do lookup for a negative dentry of new filename */
		fetch_qstr(&trash_qstr, temp_name);
		trash_dentry = d_alloc(parent_dentry, &trash_qstr);
		flag = 1;
		nd.flags = 0;
		err_dentry = wrapfs_lookup(parent_dentry->d_inode, trash_dentry, &nd);
		err =  PTR_ERR(err_dentry);
		if(IS_ERR(err_dentry) && err!=-ENOENT){
			goto top_out;	
		}

		if(trash_dentry->d_inode) {
			err = -EEXIST;
			goto top_out;
		}

		err = wrapfs_rename(dir, dentry, parent_dentry->d_inode, trash_dentry);
	}
	else 
		err = wrapfs_rename(dir, dentry, parent_dentry->d_inode, renamed_dentry);

	if(err<0)
		goto top_out;

/* dput and d_drop dentries, release buffers */
d_drop(dentry);

top_out:
	if(flag)
		dput(trash_dentry);
	dput(renamed_dentry);
dput_parents:
	dput(parent_dentry);
	dput(orig_parent_dentry);
	d_drop(renamed_dentry);

free_utd:
	dput(trashbin_dentry);
	dput(user_trashbin_dentry);
	d_drop(user_trashbin_dentry);	
free_uts:
	if(user_trashbin_string)
		kfree(user_trashbin_string);

free_path_original:
	if(path_original)
		kfree(path_original);

free_buf:
	if(buf)
		kfree(buf);

out:
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

/*
 * restore(), called by a user ioctl, restores a file/dir from the trashbin to
 * the original location of the file/dir.
 */

int restore(char* file_name, struct super_block* sb)
{
	int user, temp_uid, err=0;
	int num_digits_uid = 0;
	int user_trashbin_len;
	int append_pointer;
	int pos = 0, numslash = 0;
	int i=0, flag =0;
	int file_type;
	int len_name = 0;
	int temp_imode = S_IRWXU;
	int len_orig_path = 0;
	long int timestamp;
	char* original_path = NULL;
	char* trashbin_prepend_name = ".trashbin_";
	char* user_trashbin_string = NULL;
	char* new_restore_name = NULL;
	char temp_name[PAGE_SIZE];
	char timestamp_string[15];
	struct nameidata nd;
	struct qstr temp_qstr;
	struct qstr trash_qstr;
	struct qstr new_restore_qstr;
	struct qstr user_trashbin_qstr;
	struct path path_obtained;
	struct dentry* err_dentry;
	struct dentry* trash_dentry;
	struct dentry* parent_dentry;
	struct dentry* trashbin_parent_dentry;
	struct dentry* temp_dentry = NULL ;
	struct dentry* trashbin_dentry = NULL;
	struct dentry* user_trashbin_dentry=NULL;
	struct dentry* path_terminal_dentry = NULL;
	struct dentry* trashbin_temp_dentry = NULL;
	struct dentry* restore_dentry=NULL;
	struct dentry* new_restore_dentry = NULL;

	/* retrieve user credentials and restore policy */
	user = current->real_cred->uid;
	temp_uid = user;

	#ifdef DEBUG
	printk(KERN_INFO "Restore policy %d", restore_policy);	
	#endif

	/* find the length of the userid */
	do {
		num_digits_uid++;
		temp_uid/=10;		
	}while(temp_uid);
	
	/* compute the path of the user_trashbin */	
	user_trashbin_len = strlen(trashbin_prepend_name) + num_digits_uid + 1;
	user_trashbin_string = kmalloc(user_trashbin_len, GFP_KERNEL);
	if(!user_trashbin_string) {
		err = -ENOMEM;
		goto final_out;
	}
	strncpy(user_trashbin_string, trashbin_prepend_name, 
					strlen(trashbin_prepend_name));
	user_trashbin_string[user_trashbin_len-1] = 0;
	append_pointer = user_trashbin_len -2; 
	temp_uid = user;
	
	/* attach the <userid> to the user_trashbin as .trashbin_<userid> */
	do {
		user_trashbin_string[append_pointer] = temp_uid%10 + '0';
		temp_uid/=10;
		append_pointer--;
	}while(temp_uid);

        /*If global trashbin does not exist*/
	if(!WRAPFS_SB(sb)->trashbin_dentry){
                err = -EPERM;
		goto free_uts;
        }	

	/* global trashbin dentry */
	trashbin_dentry = dget(WRAPFS_SB(sb)->trashbin_dentry);	

        /* 
         * Search for user_trashbin_string inside global trashbin. Create a 
         * new dentry for this user_trashbin_string and ->wrapfs_lookup it. 
         */

	user_trashbin_qstr.len = user_trashbin_len;
	user_trashbin_qstr.name = user_trashbin_string;
	user_trashbin_qstr.hash = full_name_hash(user_trashbin_string, 
							user_trashbin_len);
	user_trashbin_dentry =  d_alloc(trashbin_dentry, &user_trashbin_qstr);
	nd.flags = LOOKUP_DIRECTORY;
	err_dentry = wrapfs_lookup(trashbin_dentry->d_inode, user_trashbin_dentry, &nd);

	if(IS_ERR(err_dentry)){
		err =  PTR_ERR(err_dentry);
		goto free_utd;	
	}


        /* 
         * if user_trashbin is not found in the global trashbin, 
         * then user_trashbin_dentry is negative 
         */
	if(user_trashbin_dentry->d_inode == NULL) {
		err =  -EPERM;
		goto free_utd;	
	}
	
	/*
	 * It will be assumed that the user wants to delete a directory, hence
	 * a lookup will be done for the directory. But, if the lookup fails,
	 * then we lookup for the file.
	 */

	err = vfs_path_lookup(sb->s_root, current->fs->pwd.mnt , file_name, 
					LOOKUP_DIRECTORY , &path_obtained);
	file_type = DIRECTORY;
	if(err == -ENOTDIR) {
		err = vfs_path_lookup(sb->s_root, current->fs->pwd.mnt , 
						file_name, 0 , &path_obtained);
		file_type = NORMAL_FILE;
	}
	if(err < 0) {
		err = -ENOENT;
		goto free_utd;
	}
	
	/* filtering the path from the .trash/.trashbin_<userid> to map it to
	 * its original path in the filesystem, relevant to the mount point */

	while(file_name[pos]!=0) {
		if(file_name[pos]=='/' && numslash == 1) {
			numslash++;
			original_path = file_name + pos;
			break;
		}
		else if(file_name[pos]=='/')
			numslash++;
		pos++;
	}

	/* Add a '/' to the path if not already there */
	len_orig_path = strlen(original_path);
	if(original_path[len_orig_path-1] != '/') {
		original_path[len_orig_path] = '/';
		len_orig_path++;
		original_path[len_orig_path] = 0;
	}	

	/* malformed path */
	if(numslash<2)
	{
		err = -ENOENT;
		goto path_put;
	}

	pos = 1;
	trashbin_parent_dentry = dget(user_trashbin_dentry);
	parent_dentry = dget(sb->s_root);

	/* 
         * Iterate over whole path and check if directories in the original
	 * path (from mount point) are created or not. If not created, then
	 * create them with the same mode as the dirs in the trashbin path.
         */
	while(original_path[pos]!=0) {
		if(original_path[pos] == '/') {
			pos++;
			temp_name[len_name] = 0; /* terminal name */

			/* lookup directory/file as per the type else dir */
			if(original_path[pos] == 0)
				nd.flags = file_type? 0: LOOKUP_DIRECTORY; 
			else
				nd.flags = LOOKUP_DIRECTORY;
		
			/* lookup for a dir/file in the original path */	
			fetch_qstr(&temp_qstr, temp_name);
			temp_dentry = d_alloc(parent_dentry, &temp_qstr);
			err_dentry = wrapfs_lookup(parent_dentry->d_inode,
							 temp_dentry, &nd);
		
			err =  PTR_ERR(err_dentry);
			if(IS_ERR(err_dentry) && err!=-ENOENT){
				dput(temp_dentry);
				d_drop(temp_dentry);
				goto drop_parents;	
			}
			/* lookup for a dir/file in the trashbin directory */
			trashbin_temp_dentry = 
				d_alloc(trashbin_parent_dentry, &temp_qstr);
			err_dentry = wrapfs_lookup(trashbin_parent_dentry->d_inode,
							trashbin_temp_dentry, &nd);
	
			err =  PTR_ERR(err_dentry);
			if(IS_ERR(err_dentry) && err!=-ENOENT){
				dput(temp_dentry);
				d_drop(temp_dentry);
				dput(trashbin_temp_dentry);
				d_drop(trashbin_temp_dentry);
				goto drop_parents;	
			}
		
			temp_imode = trashbin_temp_dentry->d_inode->i_mode;

			if(original_path[pos]!=0) {
				/* if dentry of original path is Negative, 
				 * then create a dir with same mode in trash */
				// We assume that the error here is only EACCES
				if(temp_dentry->d_inode == NULL){
				err = wrapfs_mkdir(parent_dentry->d_inode, 
						temp_dentry, temp_imode);
			
				if(err<0) {
					dput(temp_dentry);
					d_drop(temp_dentry);
					dput(trashbin_temp_dentry);
					d_drop(trashbin_temp_dentry); 
					goto drop_parents;
				}
				
				}
				/* as loop goes, so dput and reassign them */		
				dput(parent_dentry);
				parent_dentry = dget(temp_dentry);
				dput(trashbin_parent_dentry);
				trashbin_parent_dentry = dget(trashbin_temp_dentry);
			}	
			else {
				restore_dentry = dget(temp_dentry);
				path_terminal_dentry = dget(trashbin_temp_dentry);
			}
			/* dput and d_drop these for reassigning in the loop */
			dput(temp_dentry);
			d_drop(temp_dentry);
			dput(trashbin_temp_dentry);
			d_drop(trashbin_temp_dentry);
			len_name = 0;
		}
		else
			temp_name[len_name++] = original_path[pos++];
	}

	/* checking if the file to be restored exists in the original path */	
	if(restore_dentry && !restore_dentry->d_inode)
		printk(KERN_INFO "RESTORE: New Negative Dentry %s", 
						restore_dentry->d_iname);

	/* 
	 * if file/dir exists in the original path, then we check user's
	 * restore policy specified at the mount time.
	 */
	if(restore_dentry->d_inode) {
		/* user doesn't want to replace the file, if it exists */
		if(restore_policy == DONT_DELETE) {
			err = -EEXIST;
			goto dentry_put;
		}
		
		/* else rename the file with the new name taken from the
		 * access time of the file to be restored */
		else {
			#ifdef DEBUG
			printk(KERN_INFO "RESTORE: File Exists in orig dir");
			#endif

			timestamp = restore_dentry->d_inode->i_atime.tv_sec;
			len_name = strlen(temp_name);
			new_restore_name = (char*)kmalloc(len_name, GFP_KERNEL);
			if(!new_restore_name){
				err = -ENOMEM;	
				goto free_rname;
			}
			strcpy(new_restore_name, temp_name);
			temp_name[len_name] = '_';
			len_name++;
			my_itoa(timestamp_string, timestamp);

			/* to check if the file_name is greater than 4096 */
			if(strlen(temp_name) + strlen(timestamp_string) 
								> PAGE_SIZE) {
				err = -EEXIST;
				goto free_rname;
			}		

			/* calculate the length of the name */
			for(i = 0; i<=strlen(timestamp_string); i++)
			{
				temp_name[len_name] = timestamp_string[i];
				len_name++;
			}
			temp_name[len_name] = 0;

			/* 
			 * Before renaming to a new file in the original path,
			 * we want that the existing file be moved to the 
			 * trash. Hence, we rename it first and then we move
			 * the trash file by calling wrapfs_rename. The new
			 * file is moved with the timestamp appended to name.
			 */			
			fetch_qstr(&trash_qstr, temp_name);
			trash_dentry = d_alloc(trashbin_parent_dentry, 
								&trash_qstr);
			flag =1;
			nd.flags = file_type? 0: LOOKUP_DIRECTORY; 
			err_dentry = wrapfs_lookup(trashbin_parent_dentry->d_inode,
							 trash_dentry, &nd);
			
			err = PTR_ERR(err_dentry);
			if(IS_ERR(err_dentry) && err!=-ENOENT)
			{
				goto drop_trash;	
			}
			if(trash_dentry->d_inode)
			{
				err = -EEXIST;
				goto drop_trash;
			}
			
			/* move old file from original path to the trashbin */
			err = wrapfs_rename(parent_dentry->d_inode, restore_dentry,trashbin_parent_dentry->d_inode, trash_dentry);
		
			if(err < 0)
			{
				goto drop_trash;
			}
			d_drop(restore_dentry);
			d_drop(temp_dentry);/*TODO: Check This*/
			
			/* get a negative dentry for the new file to be move */
			fetch_qstr(&new_restore_qstr, new_restore_name);
			new_restore_dentry = d_alloc(parent_dentry, 
							&new_restore_qstr);
			err_dentry = wrapfs_lookup(parent_dentry->d_inode, 
						new_restore_dentry, &nd);

			err = PTR_ERR(err_dentry);
			if(IS_ERR(err_dentry) && err!=-ENOENT)
			{
				goto flag_put;	
			}
			if(new_restore_dentry->d_inode) {
				err = -EEXIST;
				goto flag_put;
			}
				
			/* move new file from trashbin to the original path */
			err = wrapfs_rename(trashbin_parent_dentry->d_inode, 
			path_terminal_dentry, new_restore_dentry->d_parent->d_inode, new_restore_dentry);
			if(err < 0) {	
				goto flag_put;
			}
			d_drop(path_terminal_dentry);
			d_drop(trashbin_temp_dentry);
			
			nd.flags = file_type? 0: LOOKUP_DIRECTORY;
			err_dentry = wrapfs_lookup(new_restore_dentry->d_parent->d_inode, new_restore_dentry, &nd);
			err = PTR_ERR(err_dentry);
			if(IS_ERR(err_dentry) && err!=-ENOENT)
			{
				goto flag_put;	
			}

			/* If we want to move files keeping the same name then
			 * we have to rename the moved file again */
#ifdef DELETE_KEEPING_SAME_NAME
			/*Receiving a positive dentry to trashbin file*/
	        	err = vfs_path_lookup(trashbin_parent_dentry, current->fs->pwd.mnt , temp_name, nd.flags , &trash_temp_path);
			if(err !=0)
				goto dentry_put; 

			if(trash_temp_path.dentry->d_inode) {
				#ifdef DEBUG
				printk(KERN_INFO "Received a +ve dentry inode");
				#endif
			}		
			/* We instantiate a new negative dentry of the original name to rename at*/
			fetch_qstr(&original_qstr, new_restore_name);
			original_dentry = d_alloc(trashbin_parent_dentry, &original_qstr);
			err_dentry = wrapfs_lookup(trashbin_parent_dentry->d_inode, original_dentry, &nd);
			err = PTR_ERR(err_dentry);
			if(IS_ERR(err_dentry) && err!=-ENOENT)
			{
				goto original_dentry_put;	
			}

	
			err = wrapfs_rename(trashbin_parent_dentry->d_inode, trash_temp_path.dentry, trashbin_parent_dentry->d_inode, original_dentry);
			if(err<0)
			{
				goto original_dentry_put;
			}
			d_drop(trash_temp_path.dentry);
			err_dentry = wrapfs_lookup(trashbin_parent_dentry->d_inode, original_dentry, &nd);
			err = PTR_ERR(err_dentry);
			if(IS_ERR(err_dentry) && err!=-ENOENT)
			{
				goto original_dentry_put;	
			}

#endif
		}
	}	

	/* if file/dir does not exist in the original path, then just call
	 * wrapfs_rename to move the file/dir */
	else {
		err = wrapfs_rename(trashbin_parent_dentry->d_inode, path_terminal_dentry, parent_dentry->d_inode, restore_dentry);
		if(err < 0){
			goto flag_put;
		}		

		d_drop(path_terminal_dentry);
		d_drop(trashbin_temp_dentry);
		nd.flags = file_type? 0: LOOKUP_DIRECTORY; 
		err_dentry = wrapfs_lookup(parent_dentry->d_inode, restore_dentry, &nd);
		err = PTR_ERR(err_dentry);
		if(IS_ERR(err_dentry) && err!=-ENOENT)
		{
			goto flag_put;	
		}
	}

/* free buffers, dput dentries and put paths */

#ifdef DELETE_KEEPING_SAME_NAME
original_dentry_put:
	dput(original_dentry);	
	if(trash_temp_path.dentry)
		path_put(&trash_temp_path);
#endif

flag_put:
	if(flag) 
		dput(new_restore_dentry);

drop_trash:
	if(flag)
	dput(trash_dentry);

free_rname:
	if(new_restore_name)
		kfree(new_restore_name);

dentry_put:	
	dput(restore_dentry);
	dput(path_terminal_dentry);

drop_parents:
	dput(parent_dentry);
	dput(trashbin_parent_dentry);
path_put:
	path_put(&path_obtained);

free_utd:
	dput(trashbin_dentry);
	dput(user_trashbin_dentry);
	
free_uts:
if(user_trashbin_string)
		kfree(user_trashbin_string);
final_out:
	return err;
}

/*
 * wrapfs_normal_rmdir is the original version of wrapfs_rmdir, which deletes
 * a directory (dentry) from its parent (dir). 
 */
static int wrapfs_normal_rmdir(struct inode *dir, struct dentry *dentry)
{
        struct dentry *lower_dentry;
        struct dentry *lower_dir_dentry;
        int err;
        struct path lower_path;

        wrapfs_get_lower_path(dentry, &lower_path);
        lower_dentry = lower_path.dentry;
        lower_dir_dentry = lock_parent(lower_dentry);

        err = mnt_want_write(lower_path.mnt);
        if (err)
                goto out_unlock;
        err = vfs_rmdir(lower_dir_dentry->d_inode, lower_dentry);
        if (err)
                goto out;

        d_drop(dentry); /* drop our dentry on success (why not VFS's job?) */
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


/*
 * wrapfs_rmdir is the modified version of wrapfs_rmdir, which deletes
 * a directory(dentry) from its parent(dir) and moves it to the trashbin
 * under the same path as its original.
 */
static int wrapfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	int err = 0;
	int len_name = 0;
	int len_orig_path = 0;
	int temp_imode; 
	uid_t user, temp_uid;	
	int num_digits_uid=0, i;
	int user_trashbin_len=0;	
	int append_pointer=0;
	int user_trashbin_mode = 0, pos=1;
	char* p_o;
	char *buf = NULL;
	char temp_name[PAGE_SIZE];
	char* path_original=NULL;
	char* user_trashbin_string;
	char* trashbin_prepend_name = ".trashbin_";
	struct super_block *sb;
	struct nameidata nd;
	struct dentry* temp_dentry = NULL;
	struct dentry* parent_dentry = NULL;
	struct dentry* trashbin_dentry=NULL;
	struct dentry* user_trashbin_dentry=NULL;
	struct dentry* orig_temp_dentry = NULL;
	struct dentry* orig_parent_dentry = NULL;
	struct dentry* err_dentry;	
	struct qstr user_trashbin_qstr;
	struct qstr temp_qstr;
	
	buf  = (char*)kmalloc(PAGE_SIZE, GFP_KERNEL);
	if(!buf) {
		err = -ENOMEM;
		goto out_end;
	}
	
	path_original = (char*)kmalloc(PAGE_SIZE, GFP_KERNEL);
	if(!path_original) {
		err = -ENOMEM;
		goto free_buf;
	}
	memset(path_original, 0, PAGE_SIZE);
	
	/* gets the path of the dentry from the mount point */
	p_o = dentry_path_raw(dentry, buf, PAGE_SIZE);
	strcpy(path_original, p_o);
	len_orig_path = strlen(path_original);
	if(path_original[len_orig_path-1]!='/')	{
		path_original[len_orig_path] = '/';	
		len_orig_path++;
		path_original[len_orig_path] = 0;
	}
	
	i=1;
	while(i < strlen(path_original) && path_original[i]!='/')
	{
		temp_name[i-1] = path_original[i];
		i++;
	}	
	temp_name[i] = 0; // terminating null . 

	/* 
	 * If this is the trashbin path, it should contain .trash/
	 * checking if the user deleted after entering the trashbin.
	 * Hence, checking for .trash/ in the pathname 
	 */
	if(strcmp(path_original, "/.trash/") == 0) {
		printk(KERN_INFO "Attempted to delete global \
				.trash. Operation not permitted");
		err = -EACCES;
		goto free_path_original;
	}	

	if(strcmp(temp_name, ".trash") == 0) {
		printk(KERN_INFO "Trashbin file delete");
		err = wrapfs_normal_rmdir(dir, dentry);
		goto free_path_original;
	}

	/* get current user's credentials */
	sb= dir->i_sb;
	user = current->real_cred->uid;
	temp_uid = user;
	
	/* calculating the length of the userid */
	do {
		num_digits_uid++;
		temp_uid/=10;		
	}while(temp_uid);

	/* get the user_trashbin name */	
	user_trashbin_len = strlen(trashbin_prepend_name) + num_digits_uid + 1;
	user_trashbin_string = kmalloc(user_trashbin_len, GFP_KERNEL);
	if(!user_trashbin_string) {
		err = -ENOMEM;
		goto free_path_original;

	}
	strncpy(user_trashbin_string, trashbin_prepend_name, 
						strlen(trashbin_prepend_name));
	user_trashbin_string[user_trashbin_len-1] = 0;
	
	/* appending the user id to get the user_trashbin_<userid> */
	append_pointer = user_trashbin_len -2; 
	temp_uid = user;
	do {
		user_trashbin_string[append_pointer] = temp_uid%10 + '0';
		temp_uid/=10;
		append_pointer--;
	}while(temp_uid);

	/* get the global trashbin dentry from the super_block */	
	if(!WRAPFS_SB(sb)->trashbin_dentry)
	{
		err = -EPERM;
		goto free_uts;	
	}

	trashbin_dentry = dget(WRAPFS_SB(sb)->trashbin_dentry);
	/* 
         * Search for user_trashbin_string inside global trashbin. Create a 
         * new dentry for this user_trashbin_string and ->wrapfs_lookup it. 
         */
	user_trashbin_qstr.len = user_trashbin_len;
	user_trashbin_qstr.name = user_trashbin_string;
	user_trashbin_qstr.hash = full_name_hash(user_trashbin_string, 
							user_trashbin_len);
	user_trashbin_dentry =  d_alloc(trashbin_dentry, &user_trashbin_qstr);
	nd.flags = LOOKUP_DIRECTORY; 	/* user_trashbin is a directory */
	err_dentry= wrapfs_lookup(trashbin_dentry->d_inode, user_trashbin_dentry, &nd);
	err = PTR_ERR(err_dentry);
	if(IS_ERR(err_dentry) && err!=-ENOENT)
	{
		goto dput_trash;	
	}
	
	/* 
	 * negative user_trashbin_dentry denotes user_trashbin is not created.
	 * Hence, we need to call wrapfs_mkdir to create a user_trashbin.
	 */
	if(user_trashbin_dentry->d_inode == NULL) {
		user_trashbin_mode =  S_IFDIR | S_IRWXU;
		err = wrapfs_mkdir(trashbin_dentry->d_inode, user_trashbin_dentry,
							 user_trashbin_mode);
	        if(err < 0)
		{
			goto dput_trash;
		}
	}

	parent_dentry = dget(user_trashbin_dentry);
	orig_parent_dentry = dget(sb->s_root);
	#ifdef DEBUG
	printk(KERN_INFO "Original path again %s %c", path_original, path_original[pos]);
	#endif
	len_name = 0;

        /* 
         * Iterate over whole path and check if directories in the original
         * path (from mount point) are created or not. If not created, then
         * create them with the same mode as the dirs in the trashbin path.
         */
	while(path_original[pos]!=0) {
		if(path_original[pos] == '/') {
			pos++;
			temp_name[len_name] = 0;
			nd.flags = LOOKUP_DIRECTORY;
			
			/* lookup for directory in trashbin */
			fetch_qstr(&temp_qstr, temp_name);
			temp_dentry = d_alloc(parent_dentry, &temp_qstr);
			err_dentry = wrapfs_lookup(parent_dentry->d_inode, temp_dentry,&nd);
			err = PTR_ERR(err_dentry);
			if(IS_ERR(err_dentry) && err!=-ENOENT)
			{
				dput(temp_dentry);
				d_drop(temp_dentry);
				goto dput_parents;	
			}
	
			/* lookup for the same directory in the path */
			orig_temp_dentry =  d_alloc(orig_parent_dentry, &temp_qstr);
			err_dentry = wrapfs_lookup(orig_parent_dentry->d_inode, 
							orig_temp_dentry, &nd);
			err = PTR_ERR(err_dentry);
			if(IS_ERR(err_dentry) && err!=-ENOENT)
			{
				dput(temp_dentry);
				d_drop(temp_dentry);
				dput(orig_temp_dentry);
				d_drop(orig_temp_dentry);
				goto dput_parents;	
			}
		
			temp_imode = orig_temp_dentry->d_inode->i_mode;		

			/* create a directory if it does not exist in trash */	
			if(temp_dentry->d_inode == NULL )
			{
				err = wrapfs_mkdir(parent_dentry->d_inode, temp_dentry, 
								temp_imode);
				if(err<0) {
					dput(temp_dentry);
					d_drop(temp_dentry);
					dput(orig_temp_dentry);
					d_drop(orig_temp_dentry); 
					goto dput_parents;
				}	
		
			}
			/* As loop goes, we need to drop/dput the dentries */					
			dput(parent_dentry);
			parent_dentry = dget(temp_dentry);
			dput(orig_parent_dentry);
			orig_parent_dentry = dget(orig_temp_dentry);
			dput(temp_dentry);
			d_drop(temp_dentry);
			dput(orig_temp_dentry);
			d_drop(orig_temp_dentry);
			len_name = 0;
		}
		else
			temp_name[len_name++] = path_original[pos++];
	}
	
	/* we call original wrapfs_rmdir to remove the original directory */
	err = wrapfs_normal_rmdir(dir, dentry);
	if(err < 0)
		goto dput_parents;

	/* free the buffere, dput/d_drop the dentries */
	d_drop(orig_temp_dentry);
	d_drop(orig_parent_dentry);
	d_drop(dentry);
dput_parents:
	dput(parent_dentry);
	dput(orig_parent_dentry);
	
dput_trash:
	dput(trashbin_dentry);
	dput(user_trashbin_dentry);

free_uts:
	if(user_trashbin_string)
		kfree(user_trashbin_string);

free_path_original:
	if(path_original)
		kfree(path_original);

free_buf:
	if(buf)
		kfree(buf);

out_end:
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

const struct inode_operations wrapfs_symlink_iops = {
	.readlink	= wrapfs_readlink,
	.permission	= wrapfs_permission,
	.follow_link	= wrapfs_follow_link,
	.put_link	= wrapfs_put_link,
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

};

const struct inode_operations wrapfs_main_iops = {
	.permission	= wrapfs_permission,
};
