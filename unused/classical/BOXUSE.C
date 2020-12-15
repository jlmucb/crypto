
// boxuse.c

#include "deslib.h"

/* --------------------------------------------------------------------- */


main(argn,argv)

int argn;
char *argv[];

{
	int i,j,k,n;

	for(i=0;i<8;i++) {
		printf("\n\n\n\t\t\tBox %d\n",i+1);
		for(j=0;j<16;j++)  {
			printf("\n%d: ",j);
			for(k=0;k<64;k++)
				if(s[64*i+k]==j)
					printf("  %d(%o)",k,k);
			}
		}

	printf("\n\n\n\nDone\n");
	exit();
}


/* ----------------------------------------------------------------------- */
