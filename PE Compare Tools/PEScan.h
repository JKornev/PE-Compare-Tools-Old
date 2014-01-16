#ifndef __H_PESCAN
#define __H_PESCAN

#include "PEManager.h"
#include "ErrorHandler.h"
#include <list>
#include <vector>

// wikipedia.org
#include <stddef.h>
#include <stdint.h>
#define checksum32(buf, len) _Crc32((const unsigned char *)(buf), (size_t)(len))
uint_least32_t _Crc32(const unsigned char * buf, size_t len);

typedef struct {
	unsigned int id;
	void *addr;
	unsigned int size;
	union {
		unsigned int u_checksum;
		unsigned int u_orig;
		void *u_buf;
	};
} Lock_Info, *PLock_Info;

enum Lock_Type {
	LT_VRANGE,
	//LT_IATLOCK,
	LT_IATHOOK,
	LT_VFRANGE,
};

enum LockFV_Params {
	LFV_NONE = 0,
	LFV_SYSTEMDIR = _BIT(0),
	LFV_HEADER = _BIT(1)
};

enum _VPage_Type {
	VPT_TOFIX,
	VPT_FIXED
};

typedef struct {
	_VPage_Type type;
	void *addr;
	unsigned int size;
	unsigned int protect_mask;
} _Protect_VPage, *_PProtect_VPage;

class CPEScan : protected CPEInfo {
private:
	unsigned int _guid_counter;

	std::list<Lock_Info> _lrange;//lock virtual range
	std::list<Lock_Info> _lfrange;//lock virtual and file compare
	std::vector<_Protect_VPage> _lpages;
	std::list<Lock_Info> _lihook;
	std::vector<Lock_Info> _lignore;

	/* Openned image information */
	unsigned int _img;//image offset
	//import
	PIMAGE_IMPORT_DESCRIPTOR _pimport;
	unsigned int _imp_count;

	/* File compare information */
	CPEFileManager _pefile;

	unsigned int GenGuid();

	bool FindRange(Lock_Type type, unsigned int voffset, unsigned int size, std::list<Lock_Info>::iterator &it);

protected:
	unsigned int GetOpenImageOffset();

	//BOOL IsReadOnlySection(UINT inx);
	BOOL IsCodeSection(UINT inx);
	BOOL IsWritebleSection(UINT inx);

public:
	CPEScan();
	~CPEScan();

	/* Open virtual image and parse PE header */
	bool OpenVirtualImage(unsigned int img_offst);
	/* Set virtual read access */
	bool SetVirtualAccess(unsigned int voffset, unsigned int size);
	/* Remove locks and hooks by ID */
	bool Remove(Lock_Type type, unsigned int id);
	/* Remove all locks and hooks by ID */
	void RemoveAll(Lock_Type type);

//CRC32 check
	/* Snapshot virtual memory range checksum and add to check list */
	bool LockVirtualRange(unsigned int voffset, unsigned int size, unsigned int *pvr_lock_id);
	/* Scan virtual memory checksum list */
	bool ScanRanges();

//Ignore ranges
	/* Add ignored range */
	bool AddIgnoreRange(unsigned int voffset, unsigned int size, unsigned int *pign_lock_id);
	/* Commit ignored ranges */
	bool CommitIgnoreRange();

//IAT procedures
	/* Search .dll from Import Table
	   Virtual image must be opened through OpenVirtualImage() function */
	bool IssetImportDll(void *dllname, unsigned int *inx);
	/* Search procedure IAT offset from Import Table
	   Virtual image must be opened through OpenVirtualImage() function
	   Arguments:
		name - ANSI name of procedure
		inx - IMAGE_IMPORT_DESCRIPTOR index
		addr - (out) offset for IAT procedure address */
	bool IssetImportProc(void *name, unsigned int inx, LPVOID addr);
	bool IssetExportProc(void *name, LPVOID addr);
	bool IssetExportOrdinal(DWORD ordinal, LPVOID name);

	bool IsImportSection(unsigned int inx);
	unsigned int GetSectionSize(unsigned int inx);

	DWORD GetKernelCurrentProc(LPSTR procname);

	//New hook functional
	bool HookImportProc(HMODULE hmod, void *dllname, void *procname, void *new_addr, unsigned int *piat_hook_id);
	bool UnhookImportProc(HMODULE hmod, void *dllname, void *procname);

//File\virtual compare
	/* Snapshot memory range checksum from PE file image and add to check list */
	bool LockFVRange(wchar_t *dllname, Mask_Type params, unsigned int voffset, unsigned int size, unsigned int *pfv_lock_id);
	/* Scan virtual memory and file checksum */
	bool ScanFVRanges();

	void CloseFileImage();

//Lock virtual access
	void LockVirtualPage(void *addr, unsigned int size, _VPage_Type type);
	bool FixCodeMemoryAccess();
	bool ScanVirtualPages();

	//STATIC
protected:
	static LPVOID GetKenrel32Addr();
	static bool GetModuleName(DWORD virt_addr, PVOID buffer, UINT size);
	DWORD _kerneladdr;
};


#endif