#include <stdio.h>


/*
 *	(c) Copyright, 1991, John L. Manferdelli.  All Rights Reserved.
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
	      0,   0, '\n',   0,   0,  0,   0,   0,   
	      0,   0,   0,   0,   0,   0,   0,   0,   
	      0,   0,   0,   0,   0,   0,   0,   0,   
	    ' ',   0,   0,   0,   0,   0,   0,   0,   
	      0,   0,   0,   0,   0,   0,   0,   0,
	      0,   0,   0,   0,   0,   0,   0,   0,   
	      0,   0,   0,   0,   0,   0,   0,   0,   
	      0,  'A', 'B', 'C', 'D', 'E', 'F', 'G',   
	     'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',  
	     'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
	     'X', 'Y', 'Z',   0,   0,   0,   0,   0,   
	      0,  'A', 'B', 'C', 'D', 'E', 'F', 'G',   
	     'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',  
	     'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
	     'X', 'Y', 'Z',   0,   0,   0,   0,   0,   
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



/* ------------------------------------------------------------------------ */


main(an,av)

int an;
char *av[];

{
	int in,out;
	int i,j,k;
	char a;

	if(an<3) {
		printf("Syntax: touc Input-file Output-file\n");
		exit(0);
		}
	if((in=open(av[1],0))<0) {
		printf("Can't open %s\n",av[1]);
		exit(0);
		}
	if((out=creat(av[2],0666))<0) {
		printf("Can't creat %s\n",av[2]);
		exit(0);
		}
	printf("To upper case, input: %s, output: %s\n",av[1],av[2]);
	while((i=jgetc(in))>=0) {
		if(trans[i]>=0)
			write(out,&trans[i],1);
		}
	write(out,"\n\n",2);
	close(in);
	close(out);
	exit(1);
}


/* ------------------------------------------------------------------------ */



