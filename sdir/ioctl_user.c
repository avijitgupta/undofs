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
#include <openssl/md5.h>
#define IOSHOWFILES _IOR('r', 1, char*)
#define IORESTORE _IOW('r', 2, char*)
#define LENGTH_AES 32
#define PATH_MAXLEN 4096
#define MD5_DIGEST_LENGTH 16
#define MAX_PASSWORD_LENGTH 100


	
int display_usage()
{
			printf("Usage: ./cipher {-e|-d} [-c: CIPHER] {-p PASSWORD} [-h HELP] infile outfile\n");
		        printf("-e: to encrypt\n-d: to decrypt\n-p: to specify the password\n-h: to display help\ninfile:  input file\noutfile: output file\n");
        		printf("This program implements encryption Using AES\n");
			return 0;			
}


int main(int argc, char **argv) 
{

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
	char file_to_restore[PATH_MAXLEN];
	while ((i = getopt(argc, argv, "ld:r:h")) != -1) 
	{
        switch (i) 
	{
        
	case 'l': 	key_operation = LIST;
 		        break;

	case 'd':	key_operation =DELETE;
			break;
	
	case 'r':	key_operation = RESTORE;
			strncpy(file_to_restore, optarg, PATH_MAXLEN);
			break;

	case 'h':	display_usage();
			return 0;

	case '?':       if (optopt == 'p')
          		fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        		else if (isprint (optopt))
          		fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        		return -1;

        
	}
	}

#ifdef DEBUG	
	if(key_operation !=NOT_SET)
	{
		printf("Choice = %d\n", key_operation);
	}
#endif

	if(!argv[optind])
	{
		display_usage();
		return -1;
	}
	strcpy(path_to_mount, argv[optind]);
	
	printf("Mount Point Set:%s\n", path_to_mount);

	fd = open(path_to_mount, O_RDONLY);
	if(key_operation == RESTORE)
	{
		rval = ioctl(fd, IORESTORE,file_to_restore);
		if(rval < 0)
		{
			perror("ioctl:");
			return -1;
		}
	}
/*	else if(key_operation == KEY_UNSET)
	{
		rval = ioctl(fd,IOUNSETKEY, NULL);
		if(rval <0)
		perror("ioctl:");
		return -1;
	}	
	else
	{
		display_usage();
		return -1;
	}
*/
	close(fd);
	return 0;
}


