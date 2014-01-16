#include "PECompare.h"

CPECompare::CPECompare() : _guid(0), _base_id(CMP_INVALID_ID), _started(false)
{
}

CPECompare::~CPECompare()
{
}

UINT CPECompare::OpenApp(_OpenPE_Type type, LPVOID obj_name)
{
	_Compare_Elem elem;
	elem.id = GetGuid();
	elem.type = type;

	if (_started) {
		return CMP_INVALID_ID;
	}

	switch (type) {
	case OPT_FILE:
		elem.mngr = new CPEFileManager();
		break;
	case OPT_PROC:
		elem.mngr = new CPEVirtualManager();
		break;
	default:
		return CMP_INVALID_ID;
	}

	if (!elem.mngr->Open(obj_name, false)) {
		delete elem.mngr;
		return CMP_INVALID_ID;
	}

	switch (type) {
	case OPT_FILE:
		elem.pimg = ((CPEFileManager *)elem.mngr)->GetHImg();
		elem.psect = ((CPEFileManager *)elem.mngr)->GetSectsPtr(&elem.sect_cnt);
		break;
	case OPT_PROC:
		elem.pimg = ((CPEVirtualManager *)elem.mngr)->GetHImg();
		elem.psect = ((CPEVirtualManager *)elem.mngr)->GetSectsPtr(&elem.sect_cnt);
		break;
	default:
		break;
	}

	if (!elem.sect_cnt || elem.sect_cnt > 20) {
		delete elem.mngr;
		return CMP_INVALID_ID;
	}
	elem.sect_scan = new BYTE[elem.sect_cnt + 1];
	memset(elem.sect_scan, 0, elem.sect_cnt + 1);

	_apps.push_back(elem);
	return elem.id;
}

bool CPECompare::CloseApp(UINT id)
{
	list<_Compare_Elem>::iterator it = GetElemById(id);
	if (_started || it == _apps.end()) {
		return false;
	}

	if (_base_id == id) {
		_base_id = false;
	}
	it->mngr->Close();
	delete it->mngr;
	_apps.erase(it);
	return true;
}

bool CPECompare::CloseAllApps()
{
	list<_Compare_Elem>::iterator it = _apps.begin();
	if (_started) {
		return false;
	}
	while (it != _apps.end()) {
		if (_base_id == it->id) {
			_base_id = CMP_INVALID_ID;
		}
		it->mngr->Close();
		delete it->mngr;
		_apps.erase(it);
		it++;
	}
	return true;
}

bool CPECompare::SetPrimaryApp(UINT id)
{
	list<_Compare_Elem>::iterator it = GetElemById(id);
	if (_started || it == _apps.end()) {
		return false;
	}
	_base_id = id;
	_base_addr = it->mngr->GetImagebase();
	return true;
}

UINT CPECompare::GetSectionsCount(UINT id)
{
	list<_Compare_Elem>::iterator it = GetElemById(id);
	if (it == _apps.end()) {
		return CMP_INVALID_ID;
	}
	return it->sect_cnt + 1;
}

UINT CPECompare::GetSectionsList(UINT id, _PCompare_SectList list_buff, UINT max_count)
{
	int i = 0;
	list<_Compare_Elem>::iterator it = GetElemById(id);
	if (max_count < 1 || it == _apps.end()) {
		return CMP_INVALID_ID;
	}

	list_buff[0].voffset = 0;
	list_buff[0].size = PE_HEADER_SIZE;
	memcpy(&list_buff[0].name, "[header]", 9);
	i++;

	for (; i < (it->sect_cnt + 1) && i < max_count; i++) {
		list_buff[i].voffset = it->psect[i - 1].VirtualAddress;
		list_buff[i].size = it->psect[i - 1].Misc.VirtualSize;
		memset(&list_buff[i].name, 0, 10);
		memcpy(&list_buff[i].name, &it->psect[i - 1].Name, 8);
	}

	return i;
}

bool CPECompare::SetScanSection(UINT pos, bool scan)
{
	if (_started || _base_id == CMP_INVALID_ID) {
		return false;
	}
	list<_Compare_Elem>::iterator it = GetElemById(_base_id);
	if (it == _apps.end()) {
		return false;
	}

	if (pos > it->sect_cnt) {
		return false;
	}

	it->sect_scan[pos] = scan ? 1 : 0;
	return true;
}

bool CPECompare::Start()
{
	unsigned int count = 0;
	if (_started || _base_id == CMP_INVALID_ID) {
		return false;
	}
	_base_it = GetElemById(_base_id);
	if (_base_it == _apps.end()) {
		return false;
	}

	for (int i = 0; i < _base_it->sect_cnt; i++) {
		if (_base_it->sect_scan[i]) {
			count++;
		}
	}
	if (!count) {
		return false;
	}

	_cmp_buff[0] = new BYTE[PE_DEFAULT_VIRTUAL_ALIGMENT];
	_cmp_buff[1] = new BYTE[PE_DEFAULT_VIRTUAL_ALIGMENT];

	_started = true;
	return true;
}

void CPECompare::Stop()
{
	if (!_started) {
		return;
	}

	delete[] _cmp_buff[0];
	delete[] _cmp_buff[1];
	delete[] _base_sects;
	_started = false;
}

UINT CPECompare::Compare()
{
	DWORD voffset, vcurr_ofst, vsize, count, diff_ofst, size;
	UINT ssize, result = 0;
	PBYTE pfirst, psecond;
	list<_Compare_Elem>::iterator it;
	if (!_started) {
		return 0;
	}

	//scan sections
	for (int i = 0; i <= _base_it->sect_cnt; i++) {
		if (!_base_it->sect_scan[i]) {
			continue;
		}
		
		if (i == 0) {
			voffset = 0;
			vsize = PE_DEFAULT_VIRTUAL_ALIGMENT;
		} else {
			voffset = _base_it->psect[i - 1].VirtualAddress;
			vsize = _base_it->psect[i - 1].Misc.VirtualSize;
		}
		

		size = PE_DEFAULT_VIRTUAL_ALIGMENT;
		count = vsize / size;
		for (int a = 0; a <= count; a++) {
			//calc last non-fully part
			if (a == count) {
				size = vsize % size;
				if (size == 0) {
					break;
				}
			}

			if (i == 0) {//if must loading header
				if (!_base_it->mngr->ReadHeaderData(&pfirst, (PUINT)&size)) {
					continue;
				}
				vcurr_ofst = 0;
			} else {//if must loading section
				vcurr_ofst = voffset + (PE_DEFAULT_VIRTUAL_ALIGMENT * a);
				if (!_base_it->mngr->ReadVirtualData(vcurr_ofst, _cmp_buff[0], size, _base_addr, true)) {
					continue;
				}
				pfirst = _cmp_buff[0];
			}
			
			it = _apps.begin();
			while (it != _apps.end()) {
				if (it->id == _base_id) {
					it++;
					continue;
				}

				if (i == 0) {//if must loading header
					if (!it->mngr->ReadHeaderData(&psecond, &ssize)) {
						it++;
						continue;
					}
					if (ssize < size) {//Warning. Second data too small
						size = ssize;
					}
				} else {//if must loading section
					if (!it->mngr->ReadVirtualData(vcurr_ofst, _cmp_buff[1], size, _base_addr, true)) {
						it++;
						continue;
					}
					psecond = _cmp_buff[1];
				}
				
				bool diff_flag = false;
				for (int b = 0; b < size; b++) {
					if (!diff_flag) {//search different offset
						if (pfirst[b] != psecond[b]) {
							diff_ofst = b;
							diff_flag = true;
						}
					} else {//search end of diff
						if (pfirst[b] == psecond[b]) {
							if (InsertResult(it->id, vcurr_ofst + diff_ofst, b - diff_ofst)) {
								result++;
							}
							diff_flag = false;
						}
					}
				}

				if (i == 0) {
					free(psecond);
				}
				it++;
			}

			if (i == 0) {
				free(pfirst);
			}
		}
	}

	return result;
}

bool CPECompare::InsertResult(UINT id, DWORD voffset, UINT size)
{
	_Compare_ResultInside elem;
	multimap<DWORD, _Compare_ResultInside>::iterator it = _result.begin();
	DWORD top_offset = (voffset + size), top_offset_it;

	for (it = _result.begin(); it != _result.end(); it++ )
	{
		if (id != it->second.id)
			continue;

		top_offset_it = (it->first + it->second.size);

		if (top_offset < voffset) {
			break;
		}

		if (voffset < it->first && top_offset >= it->first) {
			size = (top_offset_it >= top_offset ? top_offset_it - voffset : size);
			_result.erase(it);
			it = _result.begin();
		} else if (voffset >= it->first && voffset < top_offset_it) {
			if (top_offset <= top_offset_it) {
				return false;
			}
			voffset = it->first;
			size = (top_offset_it >= top_offset ? top_offset_it - voffset : size);
			_result.erase(it);
			it = _result.begin();
		}
	}


	elem.id = id;
	elem.size = size;
	_result.insert(pair<DWORD, _Compare_ResultInside>(voffset, elem));
	return true;
}

void CPECompare::ClearResults()
{
	if (_started) {
		return;
	}
	_result.clear();
}

UINT CPECompare::GetResultsCount()
{
	return _result.size();
}

UINT CPECompare::GetResults(_PCompare_Result list_buff, UINT max_count)
{
	multimap<DWORD, _Compare_ResultInside>::iterator it = _result.begin();
	UINT i = 0;
	if (_started) {
		return 0;
	}

	while (it != _result.end() && i < max_count) {
		list_buff[i].id = it->second.id;
		list_buff[i].offset = it->first;
		list_buff[i].size = it->second.size;
		i++;
		it++;
	}
	return i;
}

UINT CPECompare::GetGuid()
{
	return _guid++;
}

list<_Compare_Elem>::iterator CPECompare::GetElemById(UINT id)
{
	list<_Compare_Elem>::iterator it = _apps.begin();

	while (it != _apps.end()) {
		if (it->id == id) {
			return it;
		}
		it++;
	}
	return it;
}