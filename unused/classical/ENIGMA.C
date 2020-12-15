#include <stdio.h>

// Enigma

// p k C(i)R1C(-i)C(j)R2C(-j)C(k)R3C(-k)RRC(k)R3(-1)C(-k)C(j)R2(-1)C(-j)C(i)R1C(-i)K(-1)= c

// Enigma D  wiring

// a b c d e f g h i j k l m n o p q r s t u v w x y z		Input
// j w u l c m n o h p q z y x i r a d k e g v b t s f		Stator
// l p g s z m h a e o q k v x r f y b u t n i c j d w		Rotor 1
// s l v g b t f x j q o h e w i r z y a m k p c n d u		Rotor 2
// c j g d p s h k t u r a w z x f m y n q o b v l i e		Rotor 3
// i m e t c f g r a y s q b z x w l h k p v u p o j n		Reverse


// To set:
//	1. Rotor Order
//	2. Alphabet ring settings
//	3. Plugboard connections
//	4. Rotor starting positions


char st[26] = {				// stator
	'j', 'w', 'u', 'l', 'c', 'm', 'n', 'o', 'h', 'p', 'q', 'z',
	'y', 'x', 'i', 'r', 'a', 'd', 'k', 'e', 'g', 'v', 'b', 't',
	's', 'f'
	};

char r1[26] = {				// rotor 1
	'l', 'p', 'g', 's', 'z', 'm',
	'h', 'a', 'e', 'o', 'q', 'k',
	'v', 'x', 'r', 'f', 'y', 'b',
	'u', 't', 'n', 'i', 'c', 'j',
	'd', 'w'
	};

char r2[26] = {				// rotor 2
	's', 'l', 'v', 'g', 'b', 't',
	'f', 'x', 'j', 'q', 'o', 'h',
	'e', 'w', 'i', 'r', 'z', 'y',
	'a', 'm', 'k', 'p', 'c', 'n',
	'd', 'u'
	};

char r3[26] = {				// rotor 3
	'c', 'j', 'g', 'd', 'p', 's',
	'h', 'k', 't', 'u', 'r', 'a',
	'w', 'z', 'x', 'f', 'm', 'y',
	'n', 'q', 'o', 'b', 'v', 'l',
	'i', 'e'
	};

char rr[26] = {				// reverse
	'i', 'm', 'e', 't', 'c', 'f',
	'g', 'r', 'a', 'y', 's', 'q',
	'b', 'z', 'x', 'w', 'l', 'h',
	'k', 'p', 'v', 'u', 'p', 'o',
	'j', 'n'
	};


#define INTERNAL
#define NBUF 256


char sti[26], r1i[26], r2i[26], r3i[26], rri[26];

char setting[3];

int in, out;
int nb={-1};
char buf[NBUF];
char *pc;


int inlet()

{
	if(nb<=0) {
		if((nb=read(in,buf, NBUF))<=0)
			return(-1);
		pc= buf;
		}
	nb--;
	return((int)(*(pc++)));
}


int outlet(n)

int n;

{
	char a;

	a= n;
	write(out,&a,1);
	return;
}



main(an,av)

int an;
char *av[];

{
	int i,j,k,m,n;
	int s1,s2,s3;
	int t1,t2,t3,t4,t5,t6,t7,t8,t9,t10;

	if((in=open(av[2],0))<0) {
		printf("Cant open input\n");
		exit(1);
		}
	if((out=creat(av[3],1))<0) {
		printf("Cant open output\n");
		exit(1);
		}

	for(i=0;i<26;i++) {
		st[i]-= 'a';
		r1[i]-= 'a';
		r2[i]-= 'a';
		r3[i]-= 'a';
		rr[i]-= 'a';
		}
	setting[0]= *av[1];
	setting[1]= *(av[1]+1);
	setting[2]= *(av[1]+2);
	s1= setting[0]-'a';
	s2= setting[1]-'a';
	s3= setting[2]-'a';
	printf("internal settings %d%d%d\n",s1,s2,s3);

	for(i=0;i<26;i++) {
		sti[st[i]]= i;
		r1i[r1[i]]= i;
		r2i[r2[i]]= i;
		r3i[r3[i]]= i;
		rri[rr[i]]= i;
		}

	while((i=inlet())>0) {

		if((i>=((int)'a'))&&(i<=((int)'z')))
			i-= 'a';
		else {
			outlet(i);
			continue;
			}

		// encryption: input i.
		t1= st[i%26];			// after stator
		t2= r1[(t1+s1)%26];     // after rotor 1
		t3= r2[(t2+s2)%26];		// after rotor 2
		t4= r3[(t3+s3)%26];		// after rotor 3
		t5= rr[t4];				// after reflector
		t6= r3i[(t5+s3)%26];	// after reflected rotor 3
		t7= r2i[(t6+s2)%26];	// after reflected rotor 2
		t8= r3i[(t7+s1)%26];	// after reflected rotor 1
		t9= sti[t8];			// after inverted stator
#ifdef INTERNAL
		printf("%c %c %c %c %c %c %c %c %c %c\r\n",i+'a',t1+'a',
			t2+'a',t3+'a',t4+'a',t5+'a',t6+'a',t7+'a',t8+'a',t9+'a');
#endif

		// rotor motion
		s1++;
		if(s1>=26) {
			s1= 0;
			s2++;
			}
		if(s2>=26) {
			s2= 0;
			s3++;
			}
		if(s3>=26)
			s3= 0;
		outlet(t9+'a');
		}

    close(in);
    close(out);
	exit(0);
	}