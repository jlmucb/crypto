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
	if(i==((int) CC)) {
		while(((i=jgetc(in))>0)&&(i!=((int)('\n'))));
		return(jgetc(in));
		}
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
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};


/* ------------------------------------------------------------------------ */

int nk;
char key[50];
char plain[50];
char invplain[50];
char cipher[50];
char invcipher[50];

invert(a,b)

char a[], b[];

{
	int i,j,k;

	for(i=0;i<26;i++)
		b[((int)a[i])-((int)'A')]= i+((int) 'A');
	b[i]= '\0';
	return;
}


vigcipher(k,p,pi,c,ci,l)

int k,l;
char p[],c[];
char pi[],ci[];

/*
 *	Let 
 *	   X(A),X(B),X(C),X(D),X(E),X(F),X(G),X(H),X(I),X(J),...,X(Z)
 *	be the plain sequence,
 *	   Y(A),Y(B),Y(C),Y(D),Y(E),Y(F),Y(G),Y(H),Y(I),Y(J),...,Y(Z)
 *	be the cipher sequence,
 *	   K(1),K(2),K(3),...,K(nk)
 *	be the key sequence. XX*=1.  YY*=1.
 *
 *	c[i]= Y( X*(p[i]) - Y*(K(i%nk)) )
 */

{
	int i;

	i= (((int)pi[(l-((int)'A'))])-((int)'A'))-
	   ((int) ci[(k-((int)'A'))])+((int)'A')+26;
	i%= 26;
	return((int)c[i]);
}


getalphline(in,p,n)

char *p;
int n;

{
	int i,j,k;
	char *q;

	i= 0;
	q= p;
	while((i<n)&&((j=jgetc(in))>0)) {
		if(trans[j]>0) {
			*(q++)= j;
			i++;
			}
		if((j==((int)'\n'))&&(i>0))
			break;
		}
	*q= '\0';
	return(i);
}


main(an,av)

int an;
char *av[];

{
	int in,out;
	int off, period;
	int i,j,k,m,n;
	char a;

	if(an<3) {
		printf("Syntax: Vig Key-file Input-file Output-file\n");
		exit(0);
		}
	if((in=open(av[1],0))<0) {
		printf("Can't open %s\n",av[1]);
		exit(0);
		}
	nk= getalphline(in,&key[0],49);
	if((i=getalphline(in,&plain[0],49))<26) {
		printf("Plain alphabet is incomplete, %d letters\n",i);
		exit(1);
		}
	if((i=getalphline(in,&cipher[0],49))<26) {
		printf("Plain alphabet is incomplete, %d letters\n",i);
		exit(1);
		}
	close(in);
	nc= 0;
	if((in=open(av[2],0))<0) {
		printf("Can't open %s\n",av[1]);
		exit(0);
		}
	if((out=creat(av[3],0666))<0) {
		printf("Can't creat %s\n",av[2]);
		exit(0);
		}
	invert(plain,invplain);
	invert(cipher,invcipher);
	printf("Vigeniere, input: %s, output: %s\n", av[2],av[3]);
	printf("key: %s\nplain:: %s\ncipher: %s\n",key,plain,cipher);
	printf("inverse of plain:: %s\ninverse of cipher: %s\n",
		invplain,invcipher);
	n= 0;
	k= 0;
	while((i=jgetc(in))>=0) {
		if(trans[i]==0)
			continue;
		if(k>=nk)
			k= 0;
		a= vigcipher((int) key[k],plain,invplain,cipher,invcipher,i);
		write(out,&a,1);
		n++;
		k++;
		if(n==40) {
			write(out,"\n",1);
			n= 0;
			}
		if((n!=0)&&((n%5)==0))
			write(out," ",1);
		}
	write(out,"\n\n",2);
	close(in);
	close(out);
	exit(1);
}


/* ------------------------------------------------------------------------ */



