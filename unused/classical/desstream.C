#include <stdio.h>
#include "deslib.h"
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

const int s_iBufMax= 8192;
unsigned rguSeed[2]= {0,0};
unsigned rguKey[2]= {0,0};
int iSize= 0;
int iOut= 0;



main(argn,argv)

int argn;
char *argv[];

/*
 *	des driver
 */

{
	int j;
	int r;
	unsigned inblk[2], outblk[2];

	if(argn<6) {
		printf("des seed seed key key size output\n");
		return(1);
		}
	rguKey[0]= 0;
	rguKey[1]= 0;
	r= 0;

	sscanf(argv[1],"%x", &rguSeed[0]);
	sscanf(argv[2],"%x", &rguSeed[1]);
	sscanf(argv[3],"%x", &rguKey[0]);
	sscanf(argv[4],"%x", &rguKey[1]);
	sscanf(argv[5],"%d", &iSize);
	
	printf("seed: %08x %08x, key: %08x %08x ,size: %d, file: %s\n",
		rguSeed[0], rguSeed[0], rguKey[0], rguKey[1], iSize, argv[6]);

	if((iOut=_open(argv[6], _O_WRONLY | _O_CREAT | _O_BINARY))<0)  {
		printf("\nCannot creat %s quitting\n",argv[6]);
		return(0);
		}
	compkeys(rguKey);

	inblk[0]= rguSeed[0];
	inblk[1]= rguSeed[1];
	for(j=0;j<iSize;j++) {
		des(inblk,outblk,r);
		write(iOut,outblk,8);
		inblk[0]^= outblk[0];
		inblk[1]^= outblk[1];
		}

	close(iOut);
	printf("Done\n");
	return(0);
}
