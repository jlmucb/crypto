#include "desdata.c"


// Apx.c

/* --------------------------------------------------------------------- */

tobits(n,in,out)

int in;
char out[];

/*
 *	to internal format
 */

{
	int i;

	for(i=0;i<n;i++)  {
		out[n-1-i]= in&01;
		in>>= 1;
		}
	return;
}


frbits(n,in,out)

char in[];
int *out;

/*
 *	from internal format
 */

{
	int i;

	for(i=0;i<n;i++) {
		*out<<=1;
		*out|= in[i];
		}

	return;
}



/* ------------------------------------------------------------------- */

char ns[64];
char nv[64];


addup(x,y)

int x,y;

{
	int i,j;

	i= 0;
	if((y&1)!=0)
		i^= x&1;
	if((y&2)!=0)
		i^= (x>>1)&1;
	if((y&4)!=0)
		i^= (x>>2)&1;
	if((y&8)!=0)
		i^= (x>>3)&1;
	return(i);
}


main(argn,argv)

int argn;
char *argv[];

{
	int box, cmb;
	int i,j,k,m,n;
	char coeff[6],vec[6],mt[4];

	box= atoi(argv[1]);

	printf("Box: %d\n",box);
	for(cmb=1;cmb<16;cmb++) {
		for(i=0;i<64;i++) {
			/* correct for the way des does s box */
			k= (i&040)|((i&1)<<4)|((i>>1)&017);
			ns[i]= addup(s[64*(box-1)+k],cmb);
			}
		for(i=1;i<64;i++) {
			tobits(6,i,coeff);
			n= 0;
			for(j=0;j<64;j++) {
				tobits(6,j,vec);
				m= 0;
				for(k=0;k<6;k++)
					m^= coeff[k]*vec[k];
				if(m==ns[j])
					n++;
				}
			if((n>42)||(n<22)) {
				tobits(4,cmb,mt);
				printf("\tM: [");
				for(k=0;k<4;k++)
					printf("%d",mt[k]);
				printf("], ");
				printf("N: [");
				for(k=0;k<6;k++)
					printf("%d",coeff[k]);
				printf("]");
				if(n>32)
					printf("+0: %d ",n);
				else
					printf("+1: %d ",64-n);
				printf("\n");
				}
			}
		}
	printf("\n");

	exit();
}


/* ------------------------------------------------------------------- */


