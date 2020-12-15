// Maxds.c
//		Hamming distance 


#include "deslib.h"


/* ------------------------------------------------------------------ */


int bitp[6]={01,02,04,010,020,040};


main(int argn, char* argv[])

{
	int i,j,k,n;
	int u,v,a,b,r,s;
	int min, max;

	for(n=0;n<8;n++)  {
		max= 0;
		min= 6;
		printf("Box %d:\n",n+1);
		for(i=0;i<64;i++)  {
			printf("\n%2o\t",i);
			for(j=0;j<6;j++) {
				u= 64*n+i;
				v= u^bitp[j];
				a= S[u];
				b= S[v];
				k= a^b;
				r= 0;
				for(s=0;s<4;s++)  {
					if((k&01)!=0)
						r++;
					k>>=1;
					}
				if(r>max)
					max= r;
				if(r<min)
					min= r;
				printf("%2d  ",r);
				}
			}
		printf("\tMaximum Hamming distance: %d, Min Hamming distance: %d\n",max,min);
		}

	printf("\nDone\n");
	exit();
}


/* ------------------------------------------------------------------ */




