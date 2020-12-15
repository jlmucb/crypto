#include <stdio.h>


#define NBC 12000
int bcf[NBC];

#define index(n,i) (((n*(n+1))/2)+i)


buildbin(k)

int k;

{
	int i,j,j1,i1;

	if((k<0)||(((k+1)*(k+2)/2)>NBC)) {
		printf("cant build binomial coefficients\n");
		return(-1);
		}

	bcf[index(0,0)]= 1;
	for(i=1;i<=k;i++) {
		bcf[index(i,0)]= 1;
		bcf[index(i,i)]= 1;
		i1= i-1;
		for(j=1;j<i;j++) {
			j1= j-1;
			bcf[index(i,j)]= bcf[index(i1,j1)]+bcf[index(i1,j)];
			}
		}

	return(1);
}


main(argn,argv)

int argn;
char *argv[];

{
	int i,j,k,n,m;
	double p,q,x,y,z,w;

	if(argn<3) {
		printf("# equations # correct P(equation is correct)\n");
		exit();
		}

	n= atoi(argv[1]);
	m= atoi(argv[2]);
	sscanf(argv[3],"%F",&p);
	printf("maximum sets, %d equations, >= %d correct, %f\n",n,m,p);
	if(buildbin(n)<0) {
		printf("cant build binomial coefficients\n");
		exit();
		}
	z= 0.0;
	q= 1.0-p;
	x= 1.0;
	y= 1.0;
	for(i=0;i<n;i++)
		x*= p;
	for(j=0;j<m;j++) {
		w= (double) bcf[index(n,(n-j))];
		z+= w*x*y;
		x/= p;
		y*= q;
		}
	printf("p\tq\tn\tm\tP\n");
	printf("%f\t%f\t%d\t%d\t%f\n",p,q,n,m,z);
	exit();
}

