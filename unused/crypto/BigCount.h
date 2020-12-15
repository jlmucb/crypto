
//
//  Bigcount, John Manferdelli
//

// --------------------------------------------------------------


#define SMALLSORT  50

class Counts {
public:
    unsigned    uValue;
    int         iCount;
};


class BigCount {
private:
    bool        LocalSort(int iBeg, int iEnd);
    bool        SmallSort(int iBeg, int iEnd);
    bool        MergeSort(int iBeg, int iMid, int iEnd);
    bool        CountSort();

public:
    int         m_iCountSize;
    int         m_iTabSize;
    int         m_iNumEnts;
    unsigned*   m_pHead;
    unsigned*   m_ptmpHead;
    Counts*     m_pCounts;

    BigCount(int iTabSize);
    ~BigCount();

    bool        AddEnt(unsigned uE);
    bool        Sort();
    void        ReInit();
};

// --------------------------------------------------------------


