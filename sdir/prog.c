#include <sys/types.h>
#include <stdio.h>
int main()
{
	char arr[4096];
	arr[4095] = 0;
	int err;
	err = setxattr("/usr/src/hw3/fs/wrapfs/sdir/uuy", "path", "avijit", 7);
	perror("A");
	err = getxattr("/usr/src/hw3/fs/wrapfs/sdir/uuy", "path", arr, 4096);
	perror("B");
	printf("%s", arr);
	return 0;

}
