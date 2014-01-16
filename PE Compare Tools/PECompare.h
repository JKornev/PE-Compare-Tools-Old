#ifndef __H_PECMP
#define __H_PECMP

#include "PEManager.h"
#include <list>
#include <map>

using namespace std;

enum _OpenPE_ID {
	PE_PRIMARY,
	PE_SECONDARY
};

enum _OpenPE_Type {
	OPT_PROC,
	OPT_FILE
};

typedef struct {
	UINT id;
	_OpenPE_Type type;
	CPEManagerInterface *mngr;
	PIMAGE_FILE_HEADER pimg;
	PIMAGE_SECTION_HEADER psect;
	UINT sect_cnt;
	PBYTE sect_scan;
} _Compare_Elem, *_PCompare_Elem;

typedef struct {
	DWORD voffset;
	UINT size;
	char name[10];
} _Compare_SectList, *_PCompare_SectList;

typedef struct {
	DWORD id;
	DWORD offset;
	UINT size;
} _Compare_Result, *_PCompare_Result;

typedef struct {
	UINT id;
	UINT size;
} _Compare_ResultInside, *_PCompare_ResultInside;

#define CMP_INVALID_ID -1


class CPECompare {
	list<_Compare_Elem> _apps;
	UINT _guid;

	bool _started;

	UINT _base_id;
	DWORD _base_addr;
	list<_Compare_Elem>::iterator _base_it;
	_PCompare_SectList _base_sects;

	PBYTE _cmp_buff[2];

	multimap<DWORD, _Compare_ResultInside> _result;
public:
	CPECompare();
	~CPECompare();

	UINT OpenApp( _OpenPE_Type type, LPVOID obj_name);
	bool CloseApp(UINT id);
	bool CloseAllApps();

	bool SetPrimaryApp(UINT id);

	UINT GetSectionsCount(UINT id);
	UINT GetSectionsList(UINT id, _PCompare_SectList list_buff, UINT max_count);

	bool SetScanSection(UINT pos, bool scan = true);

	bool Start();
	void Stop();
	UINT Compare();

	void ClearResults();
	UINT GetResultsCount();
	UINT GetResults(_PCompare_Result list_buff, UINT max_count);

private:
	UINT GetGuid();
	list<_Compare_Elem>::iterator GetElemById(UINT id);

	bool InsertResult(UINT id, DWORD voffset, UINT size);
};

#endif