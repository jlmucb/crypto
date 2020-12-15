#include <stdio.h>


// diffan.c

#include "deslib.h"

/* --------------------------------------------------------------------- */


int dpc[4096];


void diffcount(char *sb)

{
	int i,ii,j,jj,k,m,i1,i2;


	for(j=0;j<(4096);j++)
			dpc[j]= 0;

	for(i=0;i<64;i++) {
		for(j=0;j<64;j++) {
			ii=(i&0x20)|((i<<4)&0x10)|((i>>1)&0xf);
			jj=(j&0x20)|((j<<4)&0x10)|((j>>1)&0xf);
			k=i^j;
			m= (int) (sb[ii]^sb[jj]);
			dpc[64*k+m]++;
			}
		}

	printf("In ");
	for(j=0;j<16;j++)
			printf("%2x ",j);
	printf("\n");

	for(k=0;k<64;k++) {
		printf("%2x ",k);
		for(j=0;j<16;j++)
			printf("%2d ",dpc[64*k+j]);
		printf("\n");
		}
}


main(int an, char *av[])

{
	int i;

	// for each sbox
	if(an<2)
		i= 1;
	else
		i= atoi(av[1]);
	printf("\n\nSbox %d\n",i);
	diffcount(&s[64*(i-1)]);

	exit();
}


/* ----------------------------------------------------------------------- */

