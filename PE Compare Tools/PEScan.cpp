#include "PEScan.h"
#include "PEManager.h"

#include <list>
#include <TlHelp32.h>

using namespace std;

// ======================= CPEScan :: PUBLIC =======================

CPEScan::CPEScan() : _guid_counter(0), _kerneladdr(NULL)
{
	_lignore.reserve(20);
	_lpages.reserve(20);
}

CPEScan::~CPEScan()
{
	CloseFileImage();
	RemoveAll(LT_VRANGE);
	RemoveAll(LT_VFRANGE);
	RemoveAll(LT_IATHOOK);
}

bool CPEScan::SetVirtualAccess(unsigned int voffset, unsigned int size)
{
	MEMORY_BASIC_INFORMATION mbinfo;
	DWORD new_access, old_access;

	//Проверка на доступноть чтения
	if (!VirtualQuery((LPVOID)voffset, &mbinfo, sizeof(MEMORY_BASIC_INFORMATION))) {
		return false;
	}

	if (IsBadReadPtr((LPVOID)voffset, size) != 0) {//Warning! IsBadReadPtr depricated procedure
		switch (mbinfo.Protect)
		{
		case PAGE_EXECUTE:
			new_access = PAGE_EXECUTE_READ;
			break;
		case PAGE_NOACCESS:
			new_access = PAGE_READONLY;
			break;
			//maybe need more
		default:
			new_access = 0;
		}
		if (new_access) {
			VirtualProtect((LPVOID)voffset, size, new_access, &old_access);
		}
	}

	return true;
}

bool CPEScan::LockVirtualRange(unsigned int voffset, unsigned int size, unsigned int *pvr_lock_id)
{
	Lock_Info range;

	if (!SetVirtualAccess(voffset, size)) {
		return SetError(E_ACCESS_DENIED, GetLastError());
	}

	//Генерация Checksum участка
	range.u_checksum = checksum32(voffset, size);

	//Добавление в список
	range.id = GenGuid();
	range.addr = (LPVOID)voffset;
	range.size = size;
	_lrange.push_back(range);

	if (pvr_lock_id) {
		*pvr_lock_id = range.id;
	}
	return SetError(E_OK);
}

bool CPEScan::ScanRanges()
{
	list<Lock_Info>::iterator it = _lrange.begin();
	while (it != _lrange.end()) {
		//printf("Memory V: %04X (%d)\n", it->addr, it->size);
		if (it->u_checksum != checksum32(it->addr, it->size)) {
			//DebugLog(1, "Memory V inject: %04X (%d %x)\n", it->addr, it->size, it->size);
			printf("Memory V inject: %04X (%d)\n", it->addr, it->size);
			return false;
		}
		++it;
	}
	return true;
}

bool CPEScan::OpenVirtualImage(unsigned int img_offst)
{
	DWORD offset;
	bool result;

	if (!SetVirtualAccess(img_offst, PE_HEADER_SIZE)) {
		return false;
	}

	if (result = ParseHeader((void *)img_offst)) {
		if (GetArch() == PE_X86) {
			offset = _popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		} else {
			return SetError(E_UNKNOWN, __LINE__);//x64 not supported
		}

		_imp_count = 0;
		_pimport = (PIMAGE_IMPORT_DESCRIPTOR)(img_offst + offset);
		while (_pimport[_imp_count].Characteristics != NULL) {
			_imp_count++;
		}

		_img = img_offst;
	}

	return result;
}

bool CPEScan::IssetImportDll(void *dllname, unsigned int *inx)
{//TODO заменить stricmp
	if (!HeaderIsLoaded()) {
		return false;
	}

	UINT len = strlen((char *)dllname) + 1;
	for (int i = 0; i < _imp_count; i++) {
		if (!_stricmp((char *)dllname, (char *)(_img + _pimport[i].Name))) {
			if (inx) {
				*inx = i;
			}
			return true;
		}
	}
	return false;
}

bool CPEScan::IssetImportProc(void *name, unsigned int inx, LPVOID addr)
{
	if (!HeaderIsLoaded()) {
		return false;
	}

	PIMAGE_IMPORT_DESCRIPTOR pdescr = &_pimport[inx];
	PDWORD pthunk;
	DWORD thunk = pdescr->OriginalFirstThunk;
	HMODULE hmod = NULL;
	CPEScan *pscan = NULL;
	LPSTR proc;

	pthunk = (PDWORD)(_img + pdescr->OriginalFirstThunk);
	for (int i = 0; pthunk[i] != 0; i++) {
		if (_BIT(31) & (_img + pthunk[i] + 2)) {
			if ((LPSTR)(_img + pdescr->Name) != NULL) {
				if (!hmod) {
					hmod = GetModuleHandleA((LPSTR)(_img + pdescr->Name));
					pscan = new CPEScan();
					pscan->OpenVirtualImage((UINT)hmod);
				}

				if (pscan->IssetExportOrdinal((_img + pthunk[i] + 2), &proc)) {
					if (stricmp(proc, (char *)name) == 0) {
						if (addr) {
							*(DWORD *)addr = _img + pdescr->FirstThunk + (i * 4);
						}

						delete pscan;
						return true;
					}
				}
			}
		} else if (!strcmp((char *)name, (char *)(_img + pthunk[i] + 2))) {
			if (addr) {
				*(DWORD *)addr = _img + pdescr->FirstThunk + (i * 4);
			}
			if(pscan) {
				delete pscan;
			}
			return true;
		}
	}
	if(pscan) {
		delete pscan;
	}
	return false;
}

bool CPEScan::IssetExportProc(void *name, LPVOID addr)
{//x64 not supported
	PIMAGE_OPTIONAL_HEADER32 popt;
	PIMAGE_EXPORT_DIRECTORY pexp;
	if (!HeaderIsLoaded()) {
		return false;
	}

	popt = GetHOpt32();
	if (popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0) {
		return false;
	}
	pexp = (PIMAGE_EXPORT_DIRECTORY)(popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + _img);
	char **name_table = (char **)(_img + pexp->AddressOfNames);
	for (int i = 0; i < pexp->NumberOfNames; i++) {
		if (!strcmp((const char *)name, (const char *)name_table[i] + _img)) {
			if (addr) {
				*(DWORD *)addr = _img + *(DWORD *)(_img + pexp->AddressOfFunctions + (i * 4));
			}
			return true;
		}
		//printf("%d %s\n", i, (const char *)name_table[i] + _img);
	}

	return false;
}

bool CPEScan::IssetExportOrdinal(DWORD ordinal, LPVOID name)
{
	PIMAGE_OPTIONAL_HEADER32 popt;
	PIMAGE_EXPORT_DIRECTORY pexp;
	if (!HeaderIsLoaded()) {
		return false;
	}
	
	ordinal = (ordinal << 16) >> 16;
	ordinal -= 3;

	popt = GetHOpt32();
	if (popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0) {
		return false;
	}

	pexp = (PIMAGE_EXPORT_DIRECTORY)(popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + _img);
	if (ordinal >  pexp->NumberOfNames || ordinal < 0) {
		return false;
	}

	char **name_table = (char **)(_img + pexp->AddressOfNames);
	WORD *ord_table = (WORD *)(_img + pexp->AddressOfNameOrdinals);

	for (int i = 0; i < pexp->NumberOfNames; i++) {
		if (ord_table[i] == ordinal) {
			*(char **)name = (char *)(name_table[i] + _img);
			//DebugLog(1,"- %x %s", ord_table[i], (char *)(name_table[i] + _img));
			return true;
		}
	}

	return false;
}

bool CPEScan::IsImportSection(unsigned int inx)
{
	unsigned int count;
	PIMAGE_SECTION_HEADER psec;

	psec = GetSectsPtr(&count);
	if (count <= inx) {
		return false;
	}
	psec = &psec[inx];

	/*if (psec->SizeOfRawData == 0) {
		return false;
	}*/

	for (int i = 0; i < _imp_count; i++) {
		if (_pimport[i].FirstThunk >= psec->VirtualAddress 
			&& (_pimport[i].FirstThunk < psec->VirtualAddress + psec->SizeOfRawData
				/*|| _pimport[i].FirstThunk < psec->VirtualAddress + psec->Misc.VirtualSize*/)) {
			return true;
		}
	}

	return false;
}

unsigned int CPEScan::GetSectionSize(unsigned int inx)
{//x64 not supported
	//PIMAGE_OPTIONAL_HEADER32 popt;
	unsigned int count, size;
	PIMAGE_SECTION_HEADER psec;

	psec = GetSectsPtr(&count);
	if (count <= inx) {
		return 0;
	}
	psec = &psec[inx];

	size = (psec->Misc.VirtualSize >= psec->SizeOfRawData ? psec->Misc.VirtualSize : psec->SizeOfRawData);
	//popt = GetHOpt32();

	//fix aligment
	if (size % 0x1000 > 0) {
		size += 0x1000 - (size % 0x1000);
	}

	return size;
}

bool CPEScan::LockFVRange(wchar_t *dllname, Mask_Type params, unsigned int voffset, unsigned int size, unsigned int *pfv_lock_id)
{
	static wchar_t last_file[512] = {0};
	DWORD offset;
	Lock_Info fvrange;

	if (dllname && wcscmp(dllname, last_file) != 0) {
		_pefile.Close();
		wcscpy_s(last_file, dllname);
		if (params & LFV_SYSTEMDIR) {//load from System32
			wchar_t *system_path = new wchar_t[512], 
				*path = new wchar_t[512];
			bool result;

			GetSystemDirectoryW(system_path, 512);
			wsprintfW(path, L"%s\\%s", system_path, dllname);
			result = _pefile.Open(path, false);

			delete[] system_path;
			delete[] path;
			if (!result) {
				return SetError(E_NOT_FOUND, __LINE__);
			}

			//x64 not supported
			if (_pefile.GetArch() != PE_X86) {
				return SetError(E_NOT_FOUND, __LINE__);
			}
		} else if (!_pefile.Open(dllname, false)) {//load from normal path
			return SetError(E_NOT_FOUND, __LINE__);
		}
	} else if (!_pefile.IsOpened()) {
		return SetError(E_UNKNOWN, __LINE__);
	}

	if (!SetVirtualAccess(voffset, size)) {
		return SetError(E_ACCESS_DENIED, GetLastError());
	}

	if (params & LFV_HEADER) {//Если сравнение заголовка
		//Add checksum DOS header
		PIMAGE_DOS_HEADER pdos = _pefile.GetHDos();
		//offset = (DWORD)pdos;
		fvrange.u_checksum = checksum32(pdos, sizeof(IMAGE_DOS_HEADER));
		fvrange.id = GenGuid();
		fvrange.addr = (LPVOID)voffset;
		fvrange.size = sizeof(IMAGE_DOS_HEADER);
		_lfrange.push_back(fvrange);

		//Add checksum PE file header
		PIMAGE_FILE_HEADER pimg = _pefile.GetHImg();
		//offset = (DWORD)pimg;
		fvrange.u_checksum = checksum32(pimg, sizeof(IMAGE_FILE_HEADER));
		fvrange.id = GenGuid();
		fvrange.addr = (LPVOID)GetHImg();
		fvrange.size = sizeof(IMAGE_FILE_HEADER);
		_lfrange.push_back(fvrange);

		//Add checksum optional header(data directory) and sections
		//x64 not supported
		DWORD tsize;
		PIMAGE_OPTIONAL_HEADER32 popt32 = _pefile.GetHOpt32();
		tsize = (IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY))
				+ (sizeof(IMAGE_SECTION_HEADER) * pimg->NumberOfSections);
		fvrange.u_checksum = checksum32(popt32->DataDirectory, tsize);
		fvrange.id = GenGuid();
		fvrange.addr = (LPVOID)GetHOpt32()->DataDirectory;
		fvrange.size = tsize;
		_lfrange.push_back(fvrange);

	} else {//Если сравнение данных из секций
		offset = voffset - _img;
		PBYTE buffer = new BYTE[size];

		DWORD inx;
		bool load_relocs = false;
	
		if (!_pefile.FindRawOffset(offset, 0, &inx)) {
			delete[] buffer; return SetError(E_UNKNOWN, __LINE__);
		}
		if (!IsImportSection(inx)) {
			load_relocs = true;
		}
		if (!_pefile.ReadVirtualData(offset, buffer, size, _img, load_relocs)) {
			delete[] buffer; return SetError(E_UNKNOWN, __LINE__);
		}

		//Генерация Checksum участка
		fvrange.u_checksum = checksum32(buffer, size);
		delete[] buffer;

		//Добавление в список
		fvrange.id = GenGuid();
		fvrange.addr = (LPVOID)voffset;
		fvrange.size = size;
		_lfrange.push_back(fvrange);

		if (pfv_lock_id) {
			*pfv_lock_id = fvrange.id;
		}
	}
	return SetError(E_OK);
}

bool CPEScan::ScanFVRanges()
{
	DWORD crc;
	list<Lock_Info>::iterator it = _lfrange.begin();
	while (it != _lfrange.end()) {
		crc = checksum32(it->addr, it->size);
		if (it->u_checksum != checksum32(it->addr, it->size)) {
			//DebugLog(1, "Memory FV inject: %04X (%d %x)\n", it->addr, it->size, it->size);
			printf("Memory FV inject: %04X (%d %x)\n", it->addr, it->size, it->size);
			return false;
		}
		++it;
	}
	return true;
}

void CPEScan::CloseFileImage()
{
	_pefile.Close();
}

bool CPEScan::Remove(Lock_Type type, unsigned int id)
{
	std::list<Lock_Info>::iterator it;
	std::list<Lock_Info> *lobj;
	switch (type) {
	case LT_VRANGE:
		lobj = &_lrange;
		break;
	case LT_VFRANGE:
		lobj = &_lfrange;
		break;
	case LT_IATHOOK:
		lobj = &_lihook;
		break;
	default:
		return false;
	}
	it = lobj->begin();
	while (it != lobj->end()) {
		if (it->id == id) {
			if (type == LT_IATHOOK) {//restore hook
				DWORD old_prot, new_prot;
				if (!VirtualProtect(it->addr, 4, PAGE_EXECUTE_READWRITE, &old_prot)) {
					return false;
				}
				*(DWORD *)it->addr = it->u_orig;
				if (!VirtualProtect(it->addr, 4, old_prot, &new_prot)) {
					return false;
				}
			}
			lobj->erase(it);
			return true;
		}
		++it;
	}
	return false;
}

void CPEScan::RemoveAll(Lock_Type type)
{
	switch (type) {
	case LT_VRANGE:
		_lrange.clear();
		break;
	case LT_VFRANGE:
		_lfrange.clear();
		break;
	case LT_IATHOOK: {
		std::list<Lock_Info>::iterator it = _lihook.begin();
		while (it != _lihook.end()) {
			DWORD old_prot, new_prot;
			if (!VirtualProtect(it->addr, 4, PAGE_EXECUTE_READWRITE, &old_prot)) {
				it++;
				continue;
			}
			*(DWORD *)it->addr = it->u_orig;
			VirtualProtect(it->addr, 4, old_prot, &new_prot);
			it++;
		}
		_lihook.clear();
		} break;
	default:
		break;
	}
}

void CPEScan::LockVirtualPage(void *addr, unsigned int size, _VPage_Type type)
{
	_Protect_VPage page;
	page.addr = (LPVOID)addr;
	page.size = (UINT)size;
	page.type = type;
	_lpages.push_back(page);
}

bool CPEScan::FixCodeMemoryAccess()
{
	MEMORY_BASIC_INFORMATION mbinfo;
	DWORD old_access;

	for (int i = 0; i < _lpages.size(); i++) {
		if (_lpages[i].type == VPT_TOFIX) {
			if (!VirtualQueryEx(GetCurrentProcess(), _lpages[i].addr, &mbinfo, sizeof(MEMORY_BASIC_INFORMATION))) {
				return SetError(E_UNKNOWN, __LINE__);
			}

			switch (mbinfo.Protect) {
			case PAGE_EXECUTE_READWRITE:
			case PAGE_EXECUTE_WRITECOPY:
				_lpages[i].protect_mask = PAGE_EXECUTE_READ;
				break;
			case PAGE_READWRITE:
			case PAGE_WRITECOPY:
				_lpages[i].protect_mask = PAGE_READONLY;
				break;
			default:
				_lpages[i].protect_mask = mbinfo.Protect;
			}

			_lpages[i].size = mbinfo.RegionSize;
			if (mbinfo.Protect != _lpages[i].protect_mask) {
				if (!VirtualProtectEx(GetCurrentProcess(), _lpages[i].addr, mbinfo.RegionSize, _lpages[i].protect_mask, &old_access)) {
					return SetError(E_UNKNOWN, __LINE__);
				}
			}

			_lpages[i].type = VPT_FIXED;
		}
	}

	return SetError(E_OK);
}

bool CPEScan::ScanVirtualPages()
{
	MEMORY_BASIC_INFORMATION mbinfo;
	for (int i = 0; i < _lpages.size(); i++) {
		if (_lpages[i].type == VPT_FIXED && VirtualQueryEx(GetCurrentProcess(), _lpages[i].addr, &mbinfo, sizeof(MEMORY_BASIC_INFORMATION))) {
			if (mbinfo.Protect != _lpages[i].protect_mask) {
				return false;
			}
		}
	}
	return true;
}

DWORD CPEScan::GetKernelCurrentProc(LPSTR procname)
{
	DWORD addr;
	if (!IssetExportProc(procname, &addr)) {
		return NULL;
	}
	return addr;
}

bool CPEScan::HookImportProc(HMODULE hmod, void *dllname, void *procname, void *new_addr, unsigned int *piat_hook_id)
{
	bool reopen = false;
	unsigned int inx, addr;
	Lock_Info elem;

	if (!HeaderIsLoaded() && !hmod) {//need hmod
		return false;
	} else if (!HeaderIsLoaded() && hmod) {//not opened
		reopen = true;
	} else if ((unsigned int)hmod != _img) {//different hmod
		reopen = true;
	}
	if (reopen && !OpenVirtualImage((unsigned int)hmod)) {
		return false;
	}

	if (!IssetImportDll(dllname, &inx)) {
		return false;
	}
	if (!IssetImportProc(procname, inx, &addr)) {
		return false;
	}
	
	DWORD old_prot, new_prot;
	if (!VirtualProtect((LPVOID)addr, 4, PAGE_EXECUTE_READWRITE, &old_prot)) {
		return false;
	}

	elem.id = GenGuid();
	elem.addr = (void *)addr;
	elem.u_orig = *(DWORD *)addr;
	_lihook.push_back(elem);
	*(DWORD *)addr = (unsigned int)new_addr;
	
	if (!VirtualProtect((LPVOID)addr, 4, old_prot, &new_prot)) {
		return false;
	}
	return true;
}

bool CPEScan::UnhookImportProc(HMODULE hmod, void *dllname, void *procname)
{
	bool reopen = false;
	unsigned int inx, addr;

	if (!HeaderIsLoaded() && !hmod) {//need hmod
		return false;
	} else if (!HeaderIsLoaded() && hmod) {//not opened
		reopen = true;
	} else if ((unsigned int)hmod != _img) {//different hmod
		reopen = true;
	}
	if (reopen && !OpenVirtualImage((unsigned int)hmod)) {
		return false;
	}

	if (!IssetImportDll(dllname, &inx)) {
		return false;
	}
	if (!IssetImportProc(procname, inx, &addr)) {
		return false;
	}

	std::list<Lock_Info>::iterator it = _lihook.begin();
	while (it != _lihook.end()) {
		if (it->addr == (void *)addr) {
			DWORD old_prot, new_prot;
			if (!VirtualProtect(it->addr, 4, PAGE_EXECUTE_READWRITE, &old_prot)) {
				return false;
			}
			*(DWORD *)it->addr = it->u_orig;
			if (!VirtualProtect(it->addr, 4, old_prot, &new_prot)) {
				return false;
			}

			_lihook.erase(it);
			return true;
		}
		++it;
	}
	return false;
}

bool CPEScan::AddIgnoreRange(unsigned int voffset, unsigned int size, unsigned int *pign_lock_id)
{
	Lock_Info range;

	if (!SetVirtualAccess(voffset, size)) {
		return SetError(E_ACCESS_DENIED, GetLastError());
	}

	//Добавление в список
	range.id = GenGuid();
	range.addr = (LPVOID)voffset;
	range.size = size;
	_lignore.push_back(range);

	if (pign_lock_id) {
		*pign_lock_id = range.id;
	}
	return SetError(E_OK);
}

bool CPEScan::CommitIgnoreRange()
{
	std::list<Lock_Info>::iterator it;
	unsigned int id, ldiff, hdiff;
	if (_lignore.size() == 0) {
		return true;
	}
	for (int i = _lignore.size() - 1; i >= 0; i--) {
		if (FindRange(LT_VRANGE, (unsigned int)_lignore[i].addr, _lignore[i].size, it)) {
			ldiff = (unsigned int)_lignore[i].addr - (unsigned int)it->addr;
			hdiff = ldiff + _lignore[i].size;
			if (ldiff > 0) {
				if (!LockVirtualRange((unsigned int)it->addr, ldiff, &id)) {
					return false;
				}
			} 
			if (hdiff < it->size) {
				if (!LockVirtualRange(((unsigned int)it->addr + hdiff), (it->size - hdiff), &id)) {
					return false;
				}
			}

			Remove(LT_VRANGE, it->id);
		}
		
		if (FindRange(LT_VFRANGE, (unsigned int)_lignore[i].addr, _lignore[i].size, it)) {
			ldiff = (unsigned int)_lignore[i].addr - (unsigned int)it->addr;
			hdiff = ldiff + _lignore[i].size;
			if (ldiff > 0) {
				LockVirtualRange((unsigned int)it->addr, ldiff, &id);
			} 
			if (hdiff < it->size) {
				LockVirtualRange(((unsigned int)it->addr + hdiff), (it->size - hdiff), &id);
			}

			Remove(LT_VFRANGE, it->id);
			//printf("Found LT_VFRANGE %x %d \n", it->addr, it->size);
		}
		_lignore.pop_back();
	}

	return true;
}

bool CPEScan::FindRange(Lock_Type type, unsigned int voffset, unsigned int size, std::list<Lock_Info>::iterator &it)
{
	unsigned int vend = voffset + size;
	//std::list<Lock_Info>::iterator it;
	std::list<Lock_Info> *lobj;
	switch (type) {
	case LT_VRANGE:
		lobj = &_lrange;
		break;
	case LT_VFRANGE:
		lobj = &_lfrange;
		break;
	default:
		return false;
	}

	it = lobj->begin();
	while (it != lobj->end()) {
		if ((unsigned int)it->addr <= voffset && ((unsigned int)it->addr + it->size) > vend) {
			return true;
		}
		++it;
	}
	return false;
}

LPVOID CPEScan::GetKenrel32Addr()
{/* WARNING: Undocumented feature
	- x64 not supported
	- for Windows 7 return address for KernelBase.dll
	- for Windows XP must return address for Kernel32.dll
	- for Windows 8 unknown return, mb address for KernelBase.dll
 */
	LPVOID result = NULL;
	__asm {
		mov eax, dword ptr fs:[0x30]
		test eax, eax
		js retn_label
		mov eax, dword ptr ds:[eax + 0x0C]
		mov eax, dword ptr ds:[eax + 0x1C]
		mov eax, dword ptr ds:[eax]
		mov eax, dword ptr ds:[eax + 0x08]
		mov result, eax
	}
retn_label:
	return result;
}

bool CPEScan::GetModuleName(DWORD virt_addr, PVOID buffer, UINT size)
{
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(NULL));
	MODULEENTRY32W mod;
	int len;

	memset(buffer, 0, size);

	if (hsnap == INVALID_HANDLE_VALUE) {
		return false;
	}

	mod.dwSize = sizeof(MODULEENTRY32W);
	if (!Module32FirstW(hsnap, &mod)) {
		return false;
	}

	do {
		if (virt_addr >= (DWORD)mod.modBaseAddr && (virt_addr - (DWORD)mod.modBaseAddr) <= mod.modBaseSize) {
			len = wcslen(mod.szModule) * 2;
			if (len >= size - 2) {
				len = size - 2;
			}

			memcpy(buffer, mod.szModule, len);
			return true;
		}
	} while (Module32NextW(hsnap, &mod));

	wcscpy((PWCHAR)buffer, L"[Unknown]");
	return true;
}

// ======================= CPEScan :: PRIVATE =======================

unsigned int CPEScan::GenGuid()
{
	return _guid_counter++;
}

// ======================= CPEScan :: PROTECTED =======================

unsigned int CPEScan::GetOpenImageOffset()
{
	return _img;
}

BOOL CPEScan::IsWritebleSection(UINT inx)
{
	if (_sect_count <= inx) {
		return false;
	}

	return (_psects[inx].Characteristics & IMAGE_SCN_MEM_WRITE);
}

BOOL CPEScan::IsCodeSection(UINT inx)
{
	DWORD offset = 0, exp_addr = 0, proc = 0;
	PIMAGE_EXPORT_DIRECTORY pexp;

	if (_sect_count <= inx) {
		return false;
	}

	if (!(_psects[inx].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
		return false;
	}

	if (!(_psects[inx].Characteristics & IMAGE_SCN_CNT_CODE)) {//code access
		return true;
	}

	//Check entry point
	if (GetArch() == PE_X86) {
		PIMAGE_OPTIONAL_HEADER32 popt = GetHOpt32();
		offset = popt->AddressOfEntryPoint;
		exp_addr = popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	} else if(GetArch() == PE_X64) {
		PIMAGE_OPTIONAL_HEADER64 popt = GetHOpt64();
		offset = popt->AddressOfEntryPoint;
		exp_addr = popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}
	if (INSEC_RAW == CheckInSectionOffset(offset, inx)) {
		return true;
	}

	//check export
	pexp = (PIMAGE_EXPORT_DIRECTORY)(exp_addr + _img);
	proc = pexp->AddressOfFunctions;
	for (int i = 0; i < pexp->NumberOfFunctions; i++) {
		if (INSEC_RAW == CheckInSectionOffset(*(DWORD *)(proc + (i * sizeof(DWORD)) + _img), inx)) {
			return true;
		}
	}

	return false;
}



// wikipedia.org
const uint_least32_t Crc32Table[256] = {
	0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
	0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
	0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
	0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
	0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
	0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
	0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
	0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
	0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
	0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
	0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
	0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
	0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
	0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
	0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
	0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
	0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
	0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
	0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
	0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
	0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
	0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
	0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
	0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
	0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
	0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
	0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
	0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
	0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
	0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
	0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
	0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
	0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
	0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
	0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
	0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
	0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
	0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
	0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
	0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
	0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
	0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
	0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
	0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
	0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
	0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
	0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
	0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
	0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
	0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
	0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
	0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
	0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
	0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
	0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
	0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
	0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
	0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
	0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
	0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
	0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
	0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
	0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
	0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

uint_least32_t _Crc32(const unsigned char * buf, size_t len)
{
	uint_least32_t crc = 0xFFFFFFFF;
	while (len--)
		crc = (crc >> 8) ^ Crc32Table[(crc ^ *buf++) & 0xFF];
	return crc ^ 0xFFFFFFFF;
}