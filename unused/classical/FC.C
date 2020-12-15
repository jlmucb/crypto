#include <dos.h>
#include <stdio.h>
#include <math.h>
#include <io.h>

/*
 *	(c) Copyright, 1991, John L. Manferdelli.  All Rights Reserved.
 *
 *	Frequency count, IC
 */


/* ------------------------------------------------------------------------ */


#define BUF  2048
#define UGBUF  256

static ugbuf[UGBUF];
int ugnc={0};

static char buf[BUF];
static int nc={0};
static char *cpos;

#define EC '\\'
#define CC '#'

int nlines={0};


/* ------------------------------------------------------------------------ */


jgetc(in)

int in;

{
	int i;

	if(ugnc>0)
		return((int) ugbuf[--ugnc]);

	if(nc<=0) {
		if((nc=read(in,buf,BUF))<=0)
			return(-1);
		cpos= buf;
		}
	i= *(cpos++);
	nc--;
	if(i==((int) '\n'))
		nlines++;
	return(i);
}


jungetc(in,ugc)

int in;
int ugc;

{
	if(ugnc>=UGBUF)
		return(-1);
	ugbuf[ugnc++]= ugc;
	return(ugc);
}


/* ------------------------------------------------------------------------ */

char trans[256]= {
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,1,2,3,4,5,6,7,
	      8,9,10,11,12,13,14,15,
	      16,17,18,19,20,21,22,23,
	      24,25,26,0,0,0,0,0,
	      0,1,2,3,4,5,6,7,
	      8,9,10,11,12,13,14,15,
	      16,17,18,19,20,21,22,23,
	      24,25,26,0,0,0,0,0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0};


#define NFC 50
int fc[NFC];			/* frequency count holder */
int exc[NFC];			/* characters to exclude */
int order[NFC];			/* frequency order */


char prmap[NFC]= {
	'*', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H','I',
	'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
	'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ' ','*','*','*',
	'*','*','*','*','*','*','*','*','*','*','*','*',
	'*','*','*','*','*','*','*'};



/* ------------------------------------------------------------------------ */


main(an,av)

int an;
char *av[];

{
	int in;
	int i,j,k,n;
	char *p;
	double x,y,u,z,ic;
	double rx,ry,rz,ric;

	if(an<2) {
		printf("Syntax: fc Input-file\n");
		exit(0);
		}
	if((in=open(av[1],0))<0) {
		printf("Can't open %s\n",av[1]);
		exit(0);
		}
	printf("Character count file: %s\n\n",av[1]);

	for(i=0;i<NFC;i++) {
		fc[i]= 0;
		if(i<28)
			exc[i]= 0;
		else
			exc[i]= 1;
		}
	exc[0]= 1;

#ifdef DEBUG
	printf("Counting characters\n");
#endif
	while((i=jgetc(in))>=0) {
		if((j=trans[i])>0)
			fc[j]++;
		}

#ifdef DEBUG
	printf("checking excluded\n");
#endif
	for(i=0;i<an;i++) {
		if((*av[i]=='-')&&(*(av[i]+1)=='e')) {
			p= av[i]+2;
			while(*p!='\0') {
				k= (int) *(p++);
				exc[trans[k]]= 1;
				}
			break;
			}
		}
	exc[0]= 1;

#ifdef DEBUG
	printf("totaling \n");
#endif
	n= 0;
	for(i=0;i<NFC;i++)
		if(exc[i]==0)
			n+= fc[i];
	if(n==0) {
		printf("No characters\n");
		close(in);
		exit(1);
		}

#ifdef DEBUG
	printf("preparing display\n");
#endif

	printf("\nCh Count   Freq    Ch Count   Freq    Ch Count   Freq    Ch Count   Freq\n");
	j= 0;
	x= (double)n;
	ic= 0.0;
	ric= 0.0;
	for(i=0;i<NFC;i++) {
		if(exc[i]==0) {
			y= ((double) fc[i]);
			z= y/x;
			ic+= z*z;
			ric+= (y/x)*((y-1.0)/(x-1.0));
			printf("%c %6d %6.3f",prmap[i],fc[i],z);
			j++;
			if(j==4) {
				printf("\n");
				j= 0;
				}
			else
				printf("    ");
			}
		}
	if(j!=0)
		printf("\n");
	printf("\n\n");
	for(i=0;i<NFC;i++)
		order[i]= i;
	for(i=0;i<NFC;i++) {
		for(j=(i+1);j<NFC;j++) {
			if(fc[order[i]]<fc[order[j]]) {
				k= order[i];
				order[i]= order[j];
				order[j]= k;
				}
			}
		}

	printf("\nCh Count   Freq    Ch Count   Freq    Ch Count   Freq    Ch Count   Freq\n");
	j= 0;
	for(k=0;k<NFC;k++) {
		i= order[k];
		if(exc[i]==0) {
			y= ((double) fc[i]);
			z= y/x;
			printf("%c %6d %6.3f",prmap[i],fc[i],z);
			j++;
			if(j==4) {
				printf("\n");
				j= 0;
				}
			else
				printf("    ");
			}
		}
	if(j!=0)
		printf("\n");
	printf("\n%d characters, index of coincidence: %.3f, IC(square approx): %.3f\n\n",n,ric,ic);
	close(in);
	exit(1);
}


/* ------------------------------------------------------------------------ */

