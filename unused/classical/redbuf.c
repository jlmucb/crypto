
/*
 *	(c) Copyright, 1991, John L. Manferdelli.  All Rights Reserved.
 */

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



