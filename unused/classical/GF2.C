#define IR 0103

char mtab[4096];
char itab[64];

main() 

{
	int i,j,k,l,m;
	int of;

	for(i=0;i<64;i++)
	  for(j=0;j<64;j++)  {
		k= mul(i,j);
		l= rem(k,IR);
		mtab[64*i+j]= l;
		}
	of= creat("gf64",0666);
	write(of,mtab,4096);
	for(i=1;i<64;i++)
		for(j=1;j<64;j++)
			if(rem(mul(i,j),IR)==1) {
				itab[i]= j;
				break;
				}
	itab[0]= 0;
	write(of,itab,64);
	close(of);
	printf("\n\ndone\n");
	exit();
}


mul(a,b)

int a,b;

{
	int i,j,k;

	j= 0;
	for(i=0;i<16;i++) {
		if((a&1)!=0)
			j= b^j;
		b<<= 1;
		a>>= 1;
		}
	return(j);
}


rem(a,b)

int a,b;

{
	int i,j,k,n;

	if(b==0) 
		return(-1);
	for(n=16;n>=0;n--)
		if((b&(1<<n))!=0)
			break;
	for(k=16;k>=0;k--)
		if((a&(1<<k))!=0)
			break;
	if(n>k)
		return(a);
	n= k-n+1;
	b<<= n-1;
	for(i=0;i<n;i++) {
		if(((a>>(k-i))&1)!=0)
			a= a^b;
		b>>= 1;
		}
	return(a);
}
