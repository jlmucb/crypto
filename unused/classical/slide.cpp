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

static char ugbuf[UGBUF];
int ugnc={0};

static char buf[BUF];
static int nc={0};
static char *cpos;

#define EC '\\'
#define CC '#'

int nlines={0};


/* ------------------------------------------------------------------------ */


int jgetc(int in)


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


int jungetc(int in,int ugc)

{
	if(ugnc>=UGBUF)
		return(-1);
	ugbuf[ugnc++]= ugc;
	return(ugc);
}


#define g_iSize 26


double g_rgxRegDist[g_iSize]= {
	0.0738,
	0.0104,
	0.0319,
	0.0387,
	0.1367,
	0.0253,
	0.0166,
	0.031,
	0.0742,
	0.0018,
	0.0036,
	0.0365,
	0.0242,
	0.0786,
	0.0685,
	0.0241,
	0.004,
	0.076,
	0.0658,
	0.0936,
	0.027,
	0.0163,
	0.0166,
	0.0043,
	0.0191,
	0.0014
	};


double g_rgxCurrentDist[g_iSize];

double g_rgxResult[g_iSize];


/* ------------------------------------------------------------------------ */


#define iMaxLine 120

int Getaline(int in, char szLine[])
{
	int	iC;
	int	iLen= 0;

	while((iC=jgetc(in))>0) {
		szLine[iLen++]= (char) iC;
		if(iC==(int)'\n') {
			szLine[iLen++]= '\n';
			if(iLen>=iMaxLine)
				return(-1);
			szLine[iLen++]= '\0';
			return(iLen);
			}
		if(iLen>=iMaxLine)
			return(-1);
		}
}

bool isWhitespace(char a)

{
	return(a==' ' || a== '\n');
	}


bool isNumber(char* p)
{
	if(*p=='.' || (*p>='0' && *p<='9'))
		return true;
	return false;
}



bool ReadDist(char* szName)
{
	int	in;
	int	iLine;
	char*	p;
	int	iNumNums= 0;
	char	rgszLine[iMaxLine];
	int 	i;
	bool	fComment= true;

	if((in=open(szName,0))<0) {
		printf("Can't open %s\n", szName);
		return(false);
		}
	
	while(iNumNums<g_iSize) {	
		if((iLine=Getaline(in,rgszLine))<0)
			break;
		// comment line?
		fComment= false;
		p= rgszLine;
		for(i= iLine; i>=0;i--) {
			if(isWhitespace((*p))) {
				p++;
				continue;
				}
			if(*p=='#')
				fComment= true;
			break;
			}
		// get frequency
		if(fComment || i<=0)
			continue;
		if(!isNumber(p))
			continue;

		sscanf(p, "%lf", &g_rgxCurrentDist[iNumNums]);
		iNumNums++;
		}

	close(in);
	return(true);
}


main(int an, char** av)

{
	int i,j,k;
	double x,xDist;

	if(an<2) {
		printf("Syntax: slide Input-file\n");
		return(1);
		
	}
	if(!ReadDist(av[1]))
		return(1);

	printf("Side normal alphabet against input alphabet and check distance\n");
	printf("Distribution:\n");
	for(i=0;i<g_iSize;i++) {
		printf("\t%7.5lf\n", g_rgxCurrentDist[i]);
		}
	printf("\n");
	for(i=0; i<g_iSize; i++) {
		// i is the shift in position
		xDist= 0.0;
		for(j=0;j<g_iSize;j++) {
			k= (i+j)%g_iSize;
			x= (g_rgxRegDist[j]-g_rgxCurrentDist[k]);
			xDist+= x*x;
			}
		g_rgxResult[i]= xDist;
		printf("Slide:%02d (%c), %8.4lf\n",i,'A'+i,xDist);
		}

	printf("\n");
	return(0);

}


/* ------------------------------------------------------------------------ */

