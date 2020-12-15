
//
//  Bigcount, John Manferdelli
//

#include "BigCount.h"
#ifndef NULL
#define NULL (unsigned*)0
#endif
#include "stdio.h"

// --------------------------------------------------------------


BigCount::BigCount(int iTabSize)
{
    m_pHead= new unsigned [iTabSize];
    m_ptmpHead= new unsigned [iTabSize];
    m_pCounts= new Counts[iTabSize];
    m_iTabSize= iTabSize;
    m_iNumEnts= 0;
    m_iCountSize= 0;
}


BigCount::~BigCount()
{
    delete m_pHead;
    delete m_ptmpHead;
    delete m_pCounts;
    m_pHead= NULL;
    m_ptmpHead= NULL;
    m_pCounts= (Counts*)NULL;
    m_iTabSize= 0;
}


void BigCount::ReInit()
{
    m_iCountSize= 0;
    m_iNumEnts= 0;
}


bool BigCount::AddEnt(unsigned uE)
{
    if(m_iNumEnts>=m_iTabSize)
        return false;
    m_pHead[m_iNumEnts++]= uE;
    return true;
}


bool BigCount::MergeSort(int iBeg, int iMid, int iEnd)
{
    int         iCur1= iBeg;
    int         iCur2= iMid;
    int         iTop= 0;
    int         i;
    int         n= iEnd-iBeg;
    int         iMid1, iMid2;

    if(n<SMALLSORT) {
        return SmallSort(iBeg, iEnd);
    }

    iMid1= (iMid-iBeg)/2+iBeg;
    iMid2= (iEnd-iMid)/2+iMid;
    if(!MergeSort(iBeg, iMid1, iMid) || !MergeSort(iMid, iMid2, iEnd))
        return false;

    for(;;) {
        if(iCur1>=iMid) {
            while(iCur2<iEnd)
                m_ptmpHead[iTop++]= m_pHead[iCur2++];
            break;
        }
        if(iCur2>=iEnd) {
            while(iCur1<iMid)
                m_ptmpHead[iTop++]= m_pHead[iCur1++];
            break;
        }
        if(m_pHead[iCur2]>=m_pHead[iCur1])
            m_ptmpHead[iTop++]= m_pHead[iCur2++];
        else
            m_ptmpHead[iTop++]= m_pHead[iCur1++];
    }
    
    for(i= 0; i<n; i++)
        m_pHead[i+iBeg]= m_ptmpHead[i];
    return true;
}


bool BigCount::SmallSort(int iBeg, int iEnd)
{
    int         i, j;
    unsigned    uM, u;

    for(i=iBeg; i<iEnd; i++) {
        uM= m_pHead[i];
        for(j=i+1; j<iEnd; j++) {
            if(m_pHead[j]>uM) {
                uM= m_pHead[j];
                m_pHead[j]= m_pHead[i];
                m_pHead[i]= uM;
            }
        }
    }
    return true;
}


bool BigCount::LocalSort(int iBeg, int iEnd)
{
    int     n= iEnd-iBeg;
    int     iMid;

    iMid= n/2;
    return MergeSort(iBeg, iMid, iEnd);
}


bool BigCount::CountSort()
{
    unsigned        u= 0xffffffff;
    int             i, j, n;

    for(i=0; i<m_iNumEnts;i++) {
        if(m_pHead[i]!=u || i==(m_iNumEnts-1)) {
            if(u!=0xffffffff || i==(m_iNumEnts-1)) {
                m_pCounts[m_iCountSize].uValue= u;
                m_pCounts[m_iCountSize].iCount= n;
                m_iCountSize++;
            }
            u= m_pHead[i];
            n= 0;
        }
        n++;
    }

    for(i=0; i<m_iCountSize;i++) {
        n= m_pCounts[i].iCount;

        for(j=i+1; j<m_iCountSize;j++) {

            if(m_pCounts[j].iCount>n) {
                n= m_pCounts[j].iCount;
                m_pCounts[j].iCount= m_pCounts[i].iCount;
                m_pCounts[i].iCount= n;
                u= m_pCounts[j].uValue;
                m_pCounts[j].uValue= m_pCounts[i].uValue;
                m_pCounts[i].uValue= u;
            }

        }
    }

    return true;
}


bool BigCount::Sort()
{
    LocalSort(0, m_iNumEnts);
    CountSort();
}


// --------------------------------------------------------------


