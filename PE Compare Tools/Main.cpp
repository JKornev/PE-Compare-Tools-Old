#include "PEManager.h"
#include "PECompare.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <process.h>

using namespace std;

bool _active;
CPECompare compare;

bool DisplayProcesses()
{
	HANDLE hsnap;
	PROCESSENTRY32 proc32;

	hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hsnap == INVALID_HANDLE_VALUE) {
		return false;
	}

	if (!Process32First(hsnap, &proc32)) {
		CloseHandle(hsnap);
		return false;
	}

	do {
		cout << " " << proc32.szExeFile << ":" << proc32.th32ProcessID << endl;
	} while (Process32Next(hsnap, &proc32));

	CloseHandle(hsnap);

	return true;
}

unsigned int __stdcall WorkThreadProc(void *param)
{
	while (_active) {
		compare.Compare();
		Sleep(10);
	}
	
	//_endthreadex(0);
	return 0;
}


int main(int argc, char* argv[])
{
	DWORD pid, sectors;
	HANDLE hthread;
	UINT id1, id2, tid, count;
	DWORD sect;
	string path, cmd;
	wstring wpath;
	fstream file;
	_PCompare_Result rlist;
	_PCompare_SectList psect;

	cout << "PE Compare v0.1 by JKornev, visit our website: http://k0rnev.blogspot.com" << endl;

	if (argc < 2) {
		cout << "Enter filename:" << endl << ">";
		getline(std::cin, path);
	} else {
		path = argv[1];
	}

	wpath.append(path.begin(), path.end());

	cout << "File " << path.c_str() << " successful openned" << endl;

	id1 = compare.OpenApp(OPT_FILE, (LPVOID)wpath.c_str());
	if (id1 == CMP_INVALID_ID) {
		cout << "Error, can't open compare object for " << path << endl;
		return 2;
	}

	//Load process
	if (argc < 3) {
		while (true) {
			cout << "Enter process PID or type 'list' for display processes list:" << endl << ">";
			getline(std::cin, cmd);
			if (cmd == "list") {
				if (!DisplayProcesses()) {
					cout << "Error, can't display processes" << endl;
				}
			} else {
				pid = atoi(cmd.c_str());
				cout << "Choosed PID:" << pid << endl;
				break;
			}
		}
	} else {
		pid = atoi(argv[2]);
	}
	
	id2 = compare.OpenApp(OPT_PROC, (LPVOID)pid);
	if (id2 == CMP_INVALID_ID) {
		cout << "Error, can't open compare process for " << pid << endl;
		return 3;
	}

	compare.SetPrimaryApp(id2);

	//Load sector list
	sectors = compare.GetSectionsCount(id1);
	psect = new _Compare_SectList[sectors];
	if (compare.GetSectionsList(id1, psect, sectors) != sectors) {
		cout << "Error, can't load sections" << endl;
		return 5;
	}
	cout << "Enter section numbers to scan" << endl << "Type 'list' for sections processes list or 'end' for continue:" << endl;
	while (true) {
		cout << ">";
		getline(std::cin, cmd);
		if (cmd == "list") {
			cout << "Command: list, OK!" << endl;
			for (unsigned int i = 0; i < sectors; i++) {
				printf("%3d. %8s %08X %08X\n", i, &psect[i].name, psect[i].voffset, psect[i].size);
			}
		} else if (cmd == "end") {
			cout << "Command: continue, OK!" << endl;
			break;
		} else {
			sect = atoi(cmd.c_str());
			if (sect < 0 || sect > sectors || !compare.SetScanSection(sect)) {
				cout << "Error, incorrect section number" << endl;
				continue;
			}
			cout << "Sector " << sect << " added" << endl;
		}
	}
	delete[] psect;

	if (!compare.Start()) {
		cout << "Error, can't open compare process for " << pid << endl;
		return 4;
	}

	_active = true;
	hthread = (HANDLE)_beginthreadex(NULL, 0, WorkThreadProc, 0, NULL, &tid);

	cout << "Scan started. Type 'stop' for stopping scan or press enter for look to results" << endl;
	while (true) {
		cout << ">";
		getline(std::cin, cmd);
		if (cmd == "stop") {
			cout << "Scan stopped." << endl;
			_active = false;
			WaitForSingleObject(hthread, INFINITE);
			break;
		}
		cout << "Found " << compare.GetResultsCount() << " differences" << endl;
	}

	compare.Stop();
	count = compare.GetResultsCount();
	cout << "Total found " << count << " differences" << endl;

	if (count == 0) {
		cout << "Differences not found, save not need" << endl 
			<< "Compare complite" << endl;
		return 0;
	}

	cout << "[num] [offset] [size]" << endl;
	rlist = new _Compare_Result[count];
	compare.GetResults(rlist, count);

	FILE *pfile = fopen("output.txt", "wb");
	if (!pfile) {
		cout << "Error, can't open output file" << endl;
	}
	for (DWORD i = 0; i < count; i++) {
		printf("%d. %08X %d\n", i + 1, rlist[i].offset, rlist[i].size);
		if (pfile) {
			fprintf(pfile, "0x%08X %d,\r\n", rlist[i].offset, rlist[i].size);
		}
	}

	cout << "Compare complite" << endl;
	delete[] rlist;
	//getchar();
	return 0;
}

