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


// ii[i][j] = # with difference i and first letter j
int ii[26][26];


void zeroii()
{
    int i, j;

    for(i=0;i<26;i++) {
        for(j=0; j<26; j++) {
            ii[i][j]= 0;
        }
    }
}


void printii()
{
    int i, j;

    for(i=0; i<26; i++) {
        printf("Diff(%d):\n", i);
        for(j=0; j<26; j++) {
            printf("%6d(%c), ", ii[i][j], 'a'+j);
            if((j%6)==0 && j!=0)
                printf("\n");
        }
        printf("\n");
    }
}


/* ------------------------------------------------------------------------ */



void sortFloat(int n, double xFreq[], int iArray[])
{
    int i, j, k;
    double xCurmax;

    for(i=0;i<n;i++) {
        xCurmax= xFreq[iArray[i]];
        for(j= (i+1); j<n; j++) {
            if(xCurmax<xFreq[iArray[j]]) {
                xCurmax= xFreq[iArray[j]];
                k= iArray[j];
                iArray[j]= iArray[i];
                iArray[i]= k;
            }
        }
    }
}


int main(int an, char** av)

{
    charIO  oFile1;
    charIO  oFile2;
    int     nNTC= 0;
    int     iNTC1;
    int     iNTC2;
    int     idiff;
    int     rgiDiff[26];
    int     i,j,k;
    double  r,s,t;
    char    c1, c2;
    double  xFreq[26];
    int     iArray[26];


	if(an<3) {
		printf("Syntax: difffreq Input-file1 Input-file2\n");
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
    zeroii();

    printf("Two time frequency difference probabilities %s %s\n\n",av[1],av[2]);

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
        idiff= (iNTC2-iNTC1+26)%26;
        ++ii[idiff][iNTC1-1];
    }

    for(i=0; i<26;i++) {
        rgiDiff[i]= 0;
        for(j=0; j<26; j++) {
            rgiDiff[i]+= ii[i][j];
        }
    }

    for(i=0; i<26; i++) {
        printf("// Difference %2d:\n", i);
        t= (double) rgiDiff[i];
        // calculate
        for(j=0;j<26;j++) {
            k= ii[i][j];
            s= (double) k;
            r= s/t;
            xFreq[j]= r;
            iArray[j]= j;
        }
        // sort
        sortFloat(26, xFreq, iArray);
        // print sorted
        for(j=0;j<26;j++) {
            k= iArray[j];
            c1= 'a'+ k;
            c2= 'a' + ((k+i)%26);
            printf("\'%c\', \'%c\', %7.3f,\n", c1, c2, xFreq[k]);
        }
        printf("\n\n");
    }


	oFile1.closeFile();
	oFile2.closeFile();
	return(0);
}


/* ------------------------------------------------------------------------ */

