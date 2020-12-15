#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <windows.h>

const int s_iBufMax= 8192;
unsigned char g_rgBuf[s_iBufMax];



int main(int argn, char** argv)


/*
 *	zerodisk
 */

{
	int i;
	int iSize;
	int iOut= 0;

	if(argn<2) {
		printf("Zerodisk size file\n");
		return(1);
		}
	
	iSize= atoi(argv[1]);
	printf("ZeroDisk, Output: %s, %dKB\n", argv[2],iSize);

	if((iOut=_open(argv[2], _O_WRONLY | _O_CREAT | _O_BINARY))<0)  {
		printf("\nCannot creat %s quitting\n",argv[3]);
		return(1);
		}

	iSize/=8;
	memset(g_rgBuf,0,s_iBufMax);

	while(iSize-->0) {
		write(iOut, g_rgBuf, s_iBufMax);
		}

	close(iOut);
	printf("Done\n");
	return(0);
}
