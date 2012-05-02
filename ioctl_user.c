#include <sys/ioctl.h>
#include <stdio.h>
#include <stdbool.h>
#include <malloc.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "ioctl_user.h"

int main(int argc, char **argv)
{
	/* Initialization of the variables */
	int index, c, errno;
        bool restore_flag = false;
        int rval=-1, fd;
        char path_to_mount[PATH_MAXLEN];
        char file[PATH_MAXLEN];
	errno = 0;
		
	/* process the command line arguments */
	while ((c = getopt(argc, argv, "r:h")) != -1)
	{
		switch (c)
		{
			case 'r':       
				if(restore_flag == false){
                                	restore_flag = true;
					if((optarg = strstr(optarg, ".trash/"))!= NULL){
		                                strncpy(file, optarg, PATH_MAXLEN);
						printf("File to be restored : %s\n", file);
					}
					else{
						errno = -EINVAL;
						printf("Please give path name with /.trash/\n");
						goto out;
					}
					
        	                }
                	        else{
					errno = -EINVAL;
                        	        printf("Choose only one operation at a time\n");
					goto out;
	                        }
        	                break;
	
			case 'h':
				printf("Usage :./ioctl {-r} [-h HELP] <mount point>.\n");
				printf("    -r:  to restore a file\n");
				printf("    -h:  to provide a helpful usage message\n");
				printf("    mount point: point where filesystem is mounted\n");
				errno = -EINVAL;
				goto out;
				break;
				
			/* other unknown arguments, if entered */
			default :
				fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				errno = -EINVAL;
				goto out;
		}
	}

	/* checking if decryption or encryption flag is set or not*/
	if(restore_flag == false){
		printf("Usage :./ioctl {-r} [-h HELP] <mount point>.\n");
		printf("See more usage with : ./ioctl -h\n");
		errno = -EINVAL;
		goto out;
	}

	/* filenames missing in the command line arguments */
	if(optind+1 > argc){
		printf("Arguments missing in command line. Please use ./ioctl -h\n");
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

	if(restore_flag){
		rval = ioctl(fd, IORESTORE, file);
		if(rval < 0){
			errno = rval;
			perror("IOCTL ERROR");
			printf("ioctl error : %d\n", errno);
		}
        }

out:
	if(fd)
	close(fd);
	return errno;
}

