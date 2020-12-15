 #include <stdio.h>
#include "deslib.h"

// Dumpbool.c
//	dump sboxes into boolean function format


char buf[2048];


/* --------------------------------------------------------------------- */


int main(argn, argv, envp) 

int argn; char* argv[]; char *envp[]; 

{
	int i,j,k,m,n;
	int msk;
	char z,o;
	int sw;

	for(i=0;i<argn;i++)
		if(strcmp(argv[i],"-s")==0)
			sw= 1;

	printf("\n\nS boxes before row rearrangment\n");
	for(i=0;i<8;i++) { 
		printf("Box (%d)\n",i+1);
		for(j=0;j<64;j++) {
			k= s[64*i+j];
			printf(" %x", k);
			if((j%16)==15)
				printf("\n");
			}
		printf("\n\n");
		}

	z= 0;
	o= 1;
	if(sw)
		printf("\n\nS boxes after row rearrangment\n");
	else
		printf("\n\nS boxes before row rearrangment\n");
	for(i=0; i<8; i++) {  /* each S box */
	    for(j=0; j<4; j++) {  /* each bit position */
			msk= 1<<j;
			for(k=0; k<64; k++) { /* each x value */
				if(sw)
					m= (k&040)|((k&1)<<4)|((k>>1)&017);
				else
					m= k;
				if(s[64*i+m]&msk) {
					buf[256*i+64*j+k]= 1;
					printf("1");
					}
				else {
					buf[256*i+64*j+k]= 0;
					printf("0");
					}
				}
			printf("\n");
			}
	    }

	if((i=creat("sbbool", 0666))<0) {
		printf("cant creat sbbool\n");
		exit();
		}

	write(i,buf,2048);
	close(i);
	exit();
}


/* --------------------------------------------------------------------- */
