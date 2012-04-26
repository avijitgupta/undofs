#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <malloc.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>

#include "ioctl_user.h"

int main(int argc, char **argv)
{
	/* Initialization of the variables */
	int index, c, errno;
        enum UNDOFS_OP
        {
                LIST,
                RESTORE,
                DELETE,
                INFO,
                NOT_SET
        }key_operation;
        int i, rval,fd, md5_ret=0;
        key_operation = NOT_SET;
        char path_to_mount[PATH_MAXLEN];
        char file[PATH_MAXLEN];
	errno = 0;
	opterr = 0;
		
	/* process the command line arguments */
	while ((c = getopt(argc, argv, "ld:r:h")) != -1)
	{
		switch (c)
		{
		        case 'l': 
				if(key_operation == NOT_SET)
	                                key_operation = LIST;
        	                else{
					errno = EINVAL;
                	                printf("Choose only one operation at a time\n");
                                	goto out;
                        	}
                        	break;

			case 'd':
				if(key_operation == NOT_SET){
        	                	key_operation = DELETE;
					strncpy(file, optarg, PATH_MAXLEN);
				}
	                        else{  
                                        errno = EINVAL;
                                        printf("Give only -d option to permanently delete the file.\n");
                                        goto out;
                                }

				if(!optarg){
					errno = EINVAL;
					printf("Option -d requires an argument.\n");
					goto out;
				}
			        break;

			case 'r':       
				if(key_operation == NOT_SET){
                                	key_operation = RESTORE;
	                                strncpy(file, optarg, PATH_MAXLEN);
        	                }
                	        else{
					errno = EINVAL;
                        	        printf("Choose only one operation at a time\n");
					goto out;
	                        }
        	                break;
	
			case 'h':
				printf("Usage :./ioctl {-d} [-h HELP] <mount point>.\n");
				printf("    -d:  to delete a file\n");
				printf("    -h:  to provide a helpful usage message\n");
				printf("    mount point: point where filesystem is mounted\n");
				errno = -EINVAL;
				goto out;
				break;
				
			/* other unknown arguments, if entered */
			default :
	             		if (isprint(optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				errno = -EINVAL;
				goto out;
		}
	}

	/* checking if decryption or encryption flag is set or not*/
	if(key_operation == NOT_SET){
		printf("Usage :./ioctl {-d} [-h HELP] <mount point>.\n");
		printf("See more usage with : ./ioctl -h\n");
		errno = -EINVAL;
		goto out;
	}

	/* filenames missing in the command line arguments */
	if(optind+1 > argc){
		printf("Filename/Mount Directory  missing in Non-option arguments listed\n");
		errno = -EINVAL;
		goto out;
	}

	/* arguments more than required in the command line */
	else if(optind+1 < argc){	
		printf("More than required arguments in Non-option arguments\n");
		errno = -EINVAL;
		goto out;
	}

	/* processing the input and output file arguments */
	for(index = optind; index < argc; index++){	

		/* for an input file name */
		if(index == optind){
			strcpy(path_to_mount, argv[optind]);
			printf("Mount Point Set:%s\n", path_to_mount);
		}
		else{
			errno = -EINVAL;
			printf("Non-option arguments, which are not required, entered.\n");
			goto out;
		}
	}

	fd = open(path_to_mount, O_RDONLY);
    	if(fd < 0){
        	printf("Error opening the directory\n");
		errno = fd;
	        goto out;
    	}

        switch(key_operation)
        {
                case LIST:
                        printf("Switch - List\n");
                        break;

                case RESTORE:
                        printf("Switch - Restore\n");
			rval = ioctl(fd, IORESTORE, file);
                        if(rval < 0){
				errno = rval;
                        	printf("ioctl error : %d\n", errno);
				goto out;
                        }
                        break;

                case DELETE:
                        printf("Switch - Delete\n");
			rval = ioctl(fd, IODELETE, file);
			if(rval < 0){
				errno = rval;
				printf("ioctl error : %d\n", errno);
				goto out;
			}
                        break;

                case INFO:
                        printf("Switch - Info\n");
                        break;

                case NOT_SET:
                        printf("Switch - Not Set\n");
                        break;
                default:
                        printf("In default");

        }

out:
	if(fd)
	close(fd);
	return errno;
}

