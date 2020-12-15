#include <dos.h>
#include <stdio.h>
#include <math.h>
#include <io.h>

/*
 *	(c) Copyright, 2007, John L. Manferdelli.  All Rights Reserved.
 *
 *	Venona differences
 */


/* ------------------------------------------------------------------------ */


#define BUF  2048
#define UGBUF  256
#define EC '\\'
#define CC '#'
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
	      0,   0,   0,   0,   0,   0,   0,   0
          };


/* ------------------------------------------------------------------------ */


class charIO {
public:
    int         in;
    char        ugbuf[UGBUF];
    int         ugnc;
    char        buf[BUF];
    int         nc;
    char        *cpos;
    int         nlines;

    int         nNTC;

    int         jgetc();
    int         jungetc(int ugc);
    int         getNTC();
    int         openFile(char*);
    void        closeFile();
    charIO()    {nc=0; ugnc= 0; nlines=0; nNTC= 0;};
};

/* ------------------------------------------------------------------------ */


int charIO::jgetc()

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


int charIO::jungetc(int ugc)

{
	if(ugnc>=UGBUF)
		return(-1);
	ugbuf[ugnc++]= ugc;
	return(ugc);
}


int charIO:: getNTC() 
{
    int i, j;

    for(;;) {
        i= jgetc();
        if(i<0)
            return(-1);
        j= trans[i];
        if(j>0)
            return(j);
    }
}


int   charIO::openFile(char* szFile)
{
    int i;

	if((i=open(szFile,0))<0) {
        return(-1);
		}
    in= i;
    return(1);
}


void  charIO::closeFile()
{
    close(in);
    in= 0;
    return;
}


/* ------------------------------------------------------------------------ */


int main(int an, char** av)

{
    charIO oFile1;
    charIO oFile2;
    int nNTC= 0;
    int iNTC1;
    int iNTC2;
    int idiff;
    int i,j,k;

	if(an<3) {
		printf("Syntax: diff Input-file1 Input-file2\n");
		return(1);
		}
	if(oFile1.openFile(av[1])<0) {
		printf("Can't open %s\n",av[1]);
		return(1);
		}
	if(oFile2.openFile(av[2])<0) {
		printf("Can't open %s\n",av[2]);
		return(1);
		}

    printf("Differences %s %s\n\n",av[1],av[2]);

    for(;;) {
	    iNTC1= oFile1.getNTC();
	    iNTC2= oFile2.getNTC();
        if(iNTC1<0 || iNTC2<0)
            break;
        if(iNTC1<1 || iNTC1>26)
            continue;
        if(iNTC2<1 || iNTC2>26)
            continue;
        nNTC++;
        if((nNTC%15)==0)
            printf("\n");
        idiff= (iNTC2-iNTC1+26)%26;
        printf("%2d, ", idiff);
    }
    printf("\n");

	oFile1.closeFile();
	oFile2.closeFile();
	return(0);
}


/* ------------------------------------------------------------------------ */

