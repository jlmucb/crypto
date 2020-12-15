
// pol7tab
//	print polynomials as coefficients in a matrix table


// -------------------------------------------------------------------

struct {
	int co[64];
	}  eq[32];


void bin(int i)

{
	int j;

	if(i==0) {
		printf("C");
		return;
		}
	for(j=0;j<6;j++) {
		if((i&040)!=0)
			printf("%d",j+1);
		i<<= 1;
		}

	return;
}




void binvar(int i)

{
	int j;
	int iap= 0;

	if(i==0) {
		printf("1");
		return;
		}
	for(j=0;j<6;j++) {
		if((i&040)!=0) {
			if((iap++)==0)
				printf("x%d",j+1);
			else  
				printf("*x%d",j+1);
			}
		i<<= 1;
		}

	return;
}


int subset(int a,int b)

{
	int i;

	for(i=0;i<6;i++) {
		if((a&1)==1)
			if((b&1)==0)
				return(0);
		a>>= 1;
		b>>= 1;
		}
	return(1);
}


int pc(int i)

{
	int j,k;

	k= 0;
	for(j=0;j<6;j++) {
		if((i&1)!=0)
			k++;
		i>>=1;
		}
	return(k);
}


void prtab()

{
	int i,j,k,m;

#ifdef NEVER
	printf("\n\n\n\n\n");
	for(i=0;i<32;i++) {
		printf("\n%2d ",i+1);
		for(k=0;k<6;k++)
		  for(j=0;j<64;j++)
		    if(pc(j)==k)
			printf(" %d", (m=eq[i].co[j]));
		}
#endif

	printf("\nCoefficient list\n");
	m= 0;
	for(k=0;k<6;k++) {
		for(j=0;j<64;j++) {
			if(pc(j)==k) {
				if(++m>=8) {
					printf("\n");
					m= 0;
					}
				bin(j);
				printf("  ");
				}
			}
		}

	printf("\n\nTable\n");
	for(i=0;i<32;i++) {
		printf("%2d ",i+1);
		for(j=0;j<64;j++)
			printf("%d",eq[i].co[j]);
		printf("\n");
		}

	printf("\n\nEquations\n");
	for(i=0;i<32;i++) {
		printf("f%d(x1,x2,x3,x4,x5,x6)= ",i+1);
		for(k=0;k<=6;k++) {
			for(j=0;j<64;j++) {
				if((pc(j)==k)&&(eq[i].co[j]!=0)) {
					binvar(j);
					printf("+");
					}
				}
			}
		printf("\n");
		}

	return;
}


// -------------------------------------------------------------------


main(argn,argv)

int argn;
char *argv[];

{
	int i,j,k;
	int of, sum;
	char t[64];
	char coef[64];

	if((of=open(argv[1],0))<0) {
		printf("\nCannot open %s, quitting\n",argv[1]);
		exit();
		}
	printf("\n\nPolynomial table: %s\n",argv[1]);
	for(i=0;i<32;i++)
		for(j=0;j<64;j++)
			eq[i].co[j]= 0;
	k= 0;
	for(;;) {
	  if(read(of,t,64)<=0)
		break;
	  for(i=0;i<64;i++) {
	    sum= 0;
	    for(j=0;j<64;j++)
			if(subset(j,i)==1)
				sum+= t[j];
	    eq[k].co[i]= sum%2;
	    }
	  k++;
	  }
	close(of);
	prtab();
	printf("\ndone\n");
	exit();
}


// -------------------------------------------------------------------

