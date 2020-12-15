struct block { int lhs, rhs;};
struct block invols[256];
int f[100];


/* ----------------------------------------------------------------------- */


apply(k,j,fn)

int k,j,fn;

{
	int n,m;
	int l,r;

	if(fn==0) {
		m= j&07;
		n= (j>>3)&07;
		}
	else {
		n= j&07;
		m= (j>>3)&07;
		}
		
	l= n;
	r= m^f[l^k];

	if(fn==1)
		return((r<<3)|l);
	else
		return((l<<3)|r);
}


main(argn,argv)

int argn;
char *argv[];

{
	int i,j,k,fn;
	char *p;

	fn= 0;
	for(i=1;i<argn;i++)
	  switch(*argv[i]) {
	    default:
		break;
	    case 'F':
		if((j=open(argv[i]+1,0))<0) {
			printf("Cannot open %s, quitting\n",argv[i]);
			exit();
			}
		read(j,f,8*4);
		close(j);
		break;
	    case 'S':
	    	fn= 1;
		break;
	    case 'K':
		k=0;
		p= argv[i];
		p++;
		for(;;)
		  if(*p=='\0')
			break;
		  else {
			k<<= 1;
			if(*(p++)=='1')
				k|= 1;
			}
		break;
	    }

	for(i=0;i<64;i++)
		invols[i].rhs= 0;
	for(i=0;i<64;i++)
		if(invols[i].rhs==0) {
			j= apply(k,i,fn);
#ifdef DEBUG
			printf("apply: %o, %o\n",i,j);
#endif
			invols[i].lhs= j;
			invols[i].rhs= 1;
			invols[j].lhs= i;
			invols[j].rhs= 1;
			}

	j= 0;
	for(i=0;i<64;i++)
	    if(invols[i].rhs==1) {
		invols[i].rhs= 0;
		if(i==invols[i].lhs) {
			invols[i].rhs= 0;
			printf("(%o) ",i);
			}
		else {
			invols[invols[i].lhs].rhs= 0;
			printf("(%o %o) ",i,invols[i].lhs);
			}
		if(((++j)%8)==0)
			printf("\n");
		}

	printf("\n\nkey: %o, function: ",k);
	for(i=0;i<8;i++)
		printf(" %o",f[i]);
	if(fn==0)
		printf("  switch off\n");
	else
		printf("  switch on\n");
	printf("\ndone\n\n");
	exit();
}

/* ----------------------------------------------------------------------- */

