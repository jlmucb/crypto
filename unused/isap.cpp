// 
// cl /O2 /GX isap.cpp ecn.cpp zzn2.cpp zzn.cpp big.cpp ms32.lib
// Program to find "Pairing Pseudoprimes"
//
// Uses supersingular curve y^2=x^3+ax, which is supersingular for prime modulus p=3 mod 4
// and has embeeding degree of k=2
//
// This program uses the known properties of the Tate Pairing to 
// discriminate between primes and non-primes, when used as the modulus
//
// P(-1,1) a = -2  tested up to 10^8 - no pseudoprimes
// P(1,2)  a =  3  tested up to 10^8 - no pseudoprimes
// P(-2,4) a = -12 tested up to 10^8 - no pseudoprimes
//
// Rational points can be found from http://www.asahi-net.or.jp/~KC2H-MSM/ec/eca1/index.htm
//

#include <iostream>
#include "ecn.h"
#include "zzn.h"
#include "zzn2.h"

using namespace std;

Miracl precision=10;

//
// Tate Pairing Code
//
// Extract ECn point in internal ZZn format
//

void extract(ECn& A,ZZn& x,ZZn& y)
{ 
    x=(A.get_point())->X;
    y=(A.get_point())->Y;
}

void extract(ECn& A,ZZn& x,ZZn& y,ZZn& z)
{ 
    big t;
    x=(A.get_point())->X;
    y=(A.get_point())->Y;
    t=(A.get_point())->Z;
    if (A.get_status()!=MR_EPOINT_GENERAL) z=1;
    else                                   z=t;
}

//
// Add A=A+B  (or A=A+A) 
//

ZZn2 g(ECn& A,ECn& B,ECn& Q)
{
    big ptr;
    ZZn lam,a,d,x,y,z,t;
    ZZn2 w;

    extract(A,x,y,z);
    extract(Q,a,d);

// Evaluate line from A - lam is line slope

    ptr=A.add(B);
    if (ptr==NULL)
        return (ZZn2)1; // slope is infinite
    
    lam=ptr;                       // slope = lam/A.z

// return (d-y)-slope.(a-x)

    x*=z; t=z; z*=z; z*=t;
    a*=z; 
    a+=x;    
    z*=d; w.set(y,-z);
    extract(A,x,y,z);   // only need z - its the denominator of the slope    
    w*=z; 
    a*=lam;
    w-=a; 
    
    return w;
}

//
// Tate Pairing - ecap(P,Q)
// Note - this code uses projective co-ordinates and is completely inversion-free
//

void tate(ECn& P,ECn& Q,ZZn2& res)
{ 
    Big n,m;
    ECn A;
    ZZn x,y,z;

    n=get_modulus();
    res=1;  
    if (P.iszero() || Q.iszero()) return;
    
    A=P;           // remember A   
 
    normalise(Q);

    extract(Q,x,y);
    if (x==0 && y==0) return;  // Q is on the base curve so P and Q are linearly dependent

    m=n+1;

    for (int i=bits(m)-2;i>=0;i--)
    {
        res*=res;
        res*=g(A,A,Q);  
        if (bit(m,i))
            res*=g(A,P,Q);
    }

    res=pow(res,n-1); // final exponentiation
    return;
}

int main(int argc,char **argv)
{
    miracl *mip=&precision;
    ECn P,Q;
    int j;
    Big a,n;
    Big x,y;
    BOOL isprime;
    ZZn2 r,r2;

    argc--; argv++;

    if (argc!=3)
    {
        cout << "Not enough parameters" << endl;
        cout << "Curve is y^2=x^3+ax" << endl;
        cout << "isap <a,x,y>" << endl;
        cout << "For example isap -12 -2 4" << endl;
        exit(0);
    }

    a=argv[0];
    x=argv[1];
    y=argv[2];

    if (y*y!=x*x*x+a*x)
    {
        cout << "Not an integer point on the curve!" << endl;
        exit(0);
    }

    mip->NTRY=50; // Miller-Rabin for prime(.) - 50 iterations

    for (j=0,n=7;n<100000000;n+=4,j++)
    {   
        if (j>0 && j%100000==0)  cout << "max= " << n << ", numbers tested for primality= " << j << endl;        
        
        ecurve(a,0,n,MR_PROJECTIVE);
        P.set(x,y);            

        if (gcd(n,a)!=1) continue;

// calculate pairing

        Q=P; Q+=Q; 
        if (Q.iszero())
        {
            cout << "P is of order 2 for n= " << n << endl;
            continue;
        }

        Q+=Q; 
        if (Q.iszero())
        {
            cout << "P is of order 4 for n= " << n << endl;
            continue;
        }

        tate(P,P,r);     

// first check that pairing value is a root of unity

        isprime=TRUE;
        
        if (pow(r,n+1)!=1) isprime=FALSE; 

// second... a simple bilinearity check.... ecap(2P,P) = ecap(P,2P)

        if (isprime)
        {
            tate(2*P,P,r2);
            if (r2!=r*r) isprime=FALSE;
        }

        if (isprime)
        {
            tate(P,2*P,r2);
            if (r2!=r*r) isprime=FALSE;
        }

        if (prime(n))
        {
            if (!isprime) cout << "Whoops= " << n << " r= " << r << endl;      // should not happen
        }
        else
        {
            if (isprime)  cout << "Pseudoprime= " << n << " r= " << r << endl; // pseudoprime
        }              
    }

    return 0;
}
