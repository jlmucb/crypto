#include <stdio.h>
#include "deslib.h"


int inf, ouf;
int max;
int nb;
int skip={0};


main(argn,argv)

int argn;
char *argv[];

/*
 *	des driver
 */

{
	int i,j,r;
	unsigned key[2], inblk[2], outblk[2];
	char *p,a,*q;
	char hkey[18];

	if(argn<2) {
		printf("des input output [-r] [-k0123456789abcdef] [-s#] [-m#]\n");
		exit();
		}
	max= 1000000;
	nb= 0;
	key[0]= 0;
	key[1]= 0;
	r= 0;
	for(i=0;i<argn;i++) {
		if(*argv[i]=='-')
		  switch(*(argv[i]+1)) {
		    case 's':
			sscanf(argv[i+1],"%d\0",&skip);
			break;
		    case 'k':
			p= argv[i]+2;
			printf("KEY: %s\n",p);
			a= *(p+8);
			*(p+8)= 0;
			sscanf(p,"%x\0",&key[0]);
			*(p+8)= a;
			sscanf(p+8,"%x\0",&key[1]);
			break;
		    case 'm':
			max= atoi(argv[i+1]);
			break;
		    case 'r':
			r= 1;
			break;
		    }
		}
	printf("DES Input: %s, Output: %s, Key: %08x%08x, skip: %d blocks\n",
		argv[1],argv[2],key[0],key[1],skip);

	if((inf=open(argv[1],0))<0) {
		printf("\nCannot open %s quittting\n",argv[2]);
		exit();
		}
	if((ouf=creat(argv[2],0666))<0)  {
		printf("\nCannot creat %s quitting\n",argv[1]);
		exit();
		}
	compkeys(key);
	if(skip>0)
		lseek(inf,skip,0);
	for(j=0;j<max;j++) {
		if(read(inf,inblk,8)<8)
			break;
		des(inblk,outblk,r);
		write(ouf,outblk,8);
		nb++;
		}

	close(inf);
	close(ouf);
	printf("Done %d blocks\n",nb);
	exit();
}
