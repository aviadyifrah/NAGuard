#include <Windows.h>
#include <stdio.h>
#include <fltUser.h>
#include "../inc/SharedData.h"
#include <heapapi.h>
#include <inttypes.h>
#include <mutex>
#include <iostream>
#include "naGuardApp.h"
#include <set>
#include "psapi.h"
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <stdlib.h>
using namespace std;

#define signtoolPath "sigcheck.exe "

#pragma warning(disable: 4311)
#pragma warning(disable: 4302)

#if defined(UNICODE) || defined(_UNICODE)
#define tcout std::wcout
#else
#define tcout std::cout
#endif

typedef struct r_data_t {
	FILTER_MESSAGE_HEADER MessageHeader;
	NAGUARD_FMESSAGE content;
}R_DATA, *PR_DATA;

/*bool in_array(const wchar_t &value, const std::vector<wchar_t> &array)
{
	return std::find(array.begin(), array.end(), value) != array.end();
}*/


std::string exec(const char* cmd) {
	std::array<char, 128> buffer;
	std::string result;
	std::shared_ptr<FILE> pipe(_popen(cmd, "r"), _pclose);
	if (!pipe) throw std::runtime_error("popen() failed!");
	while (!feof(pipe.get())) {
		if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
			result += buffer.data();
	}
	return result;
}
bool chekSign(char *exePath)
{
	std::string exeFile(exePath);
	std::string all = signtoolPath + exeFile;
	const char * allCommand = all.c_str();
	std::string mainResult = exec(allCommand);
	// c:\\Windows\\System32\\calc.exe"

	size_t verified = mainResult.find("Verified") + 10;
	std::string fileSigned = "Signed";
	if (mainResult.compare(verified, 6, fileSigned) == 0) {
		//printf("file is signed\n");
		return true;
	}
	return false;
}


void securityWorker(SecurityDatabase &db, std::set<HANDLE> &handles, std::mutex &mtx, HANDLE &hPort)
{
	HRESULT hr = S_OK;
	PR_DATA msg = (PR_DATA)HeapAlloc(GetProcessHeap(), 0, sizeof(R_DATA));

	while (true)
	{
		hr = FilterGetMessage(hPort, &msg->MessageHeader, sizeof(R_DATA), NULL);
		if (!FAILED(hr)) {			
			/*std::cout << "db.recordOperation(" << msg->content.process_id << ", "
				<< msg->content.opcode << ", " << msg->content.preop_entropy << ", "
				<< msg->content.postop_entropy << ")" << std::endl;
			printf("preop_filename: %S\n", msg->content.preop_filename);
			printf("postop_filename: %S\n", msg->content.postop_filename);*/
			if ((msg->content.postop_entropy == msg->content.preop_entropy)&&msg->content.opcode==1) {
				//printf("\n entropy equal bypass \n");
				continue;
			}
			wchar_t * pwc = wcsrchr(msg->content.preop_filename, L'.') + 1;
			//std::vector<wchar_t> tab { L'doc',  L'docx', L'xls' ,L'xlsx',  L'pdf', L'ppt' ,L'pptx'};
			//if (!in_array(pwc, tab)) {
				
			//}
			bool Exist = false;
			wchar_t extList[14][5] = { L"doc", L"docx", L"xls",L"xlsx",L"pdf", L"ppt" ,L"pptx", L"txt",L"png", L"gif", L"bmp", L"jpg", L"jpeg" ,L"zip"};
			for (int i = 0; i < size(extList); i++) {
				//printf("%S\n", extList[i]);
				//printf("%S\n", pwc);
				if (wcscmp(extList[i], pwc) == 0) {
					Exist = true;
				}
			}
			/*if (!Exist) {
				//printf("\n extension not in list \n");
				continue;
			}*/
			mtx.lock();
			handles.insert(msg->content.process_id);
			mtx.unlock();
			db.recordOperation(msg->content.process_id, msg->content.opcode, msg->content.preop_filename, msg->content.preop_entropy, msg->content.postop_entropy, Exist);
			
		}

	}
}


void scheduler(SecurityDatabase &db, std::set<HANDLE> &handles, std::mutex &mtx)
{
	float WriteDeltaEntropy = 0;
	float WriteEndEntropy = 0;
	float NewWriteEntropy = 0;
	unsigned long NotExtInListWrite = 0;
	int score = 0;
	unsigned int total_writes = 0, total_renames = 0, total_deletes = 0, total_new_write = 0;
	unsigned int writes = 0, renames = 0, deletes = 0, new_writes = 0;
	unsigned long honeyPots;
	std::cout << "scheduler started..." << std::endl;
	while (true) {
		mtx.lock();
		std::cout << "handles.size(): " << handles.size() << std::endl;
		for (HANDLE element : handles) {

			NotExtInListWrite = db.getNotExtInListWrite(element);
			WriteDeltaEntropy = db.getAverageDeltaWriteEntropy(element);
			WriteEndEntropy = db.getAverageEndWriteEntropy(element);
			NewWriteEntropy = db.getAverageNewWriteEntropy(element);
			total_new_write = db.getTotalOps(element, 0);
			total_writes = db.getTotalOps(element, 1);
			total_renames = db.getTotalOps(element, 2);
			total_deletes = db.getTotalOps(element, 3);
			new_writes = db.getOps(element, 0);
			writes = db.getOps(element, 1);
			renames = db.getOps(element, 2);
			deletes = db.getOps(element, 3);
			honeyPots = db.getHoneyPots(element);
			char buf[100];
			snprintf(buf, 100, "%" PRIuPTR, (uintptr_t)element);
			//printf("%s--- \n", buf);
			//int pid = *reinterpret_cast<int *>((uintptr_t)msg->content.process_id);
			int pid = atoi(buf);
			HANDLE Handle = OpenProcess(
				PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
				FALSE,
				pid /* This is the PID, you can find one from windows task manager */
			);
			char PathBuffer[500];
			if (Handle)
			{
				TCHAR Buffer[MAX_PATH];
				if (GetModuleFileNameEx(Handle, 0, Buffer, MAX_PATH))
				{
					tcout << "proc name: " << Buffer << "  " ;
				}
				DWORD value = MAX_PATH;
				LPWSTR path = new WCHAR[MAX_PATH];
				if (QueryFullProcessImageName(Handle, 0, path, &value)) {
					wcstombs(PathBuffer, path, 500);
				}
			}
			score = db.getScore(element);
			std::cout << "proc_id: " << element <<
				", NotExtInListWrite: "<<NotExtInListWrite <<
				", honeyPots: " << honeyPots <<
				", WriteEndentropy: " << WriteEndEntropy <<
				", WriteDeltaentropy: " << WriteDeltaEntropy <<
				", nweWriteEntropy: " << NewWriteEntropy <<
				", total writes: " << total_writes <<
				", total new writes: " << total_new_write <<
				", total renames: " << total_renames <<
				", total deletes: " << total_deletes <<
				", writes: " << writes <<
				", renames: " << renames <<
				", newWrites: " << new_writes <<
				", score: " << score <<
				", deletes: " << deletes << std::endl;
			
			/*if (WriteEntropy > 4) {
				db.updateScore(element, 15);
			} else {
				db.updateScore(element, -15);
			}*/
			if (NotExtInListWrite > 30) {
				if (WriteEndEntropy > 4) {
					db.updateScore(element, 10);
				}
			}
			else {
				db.updateScore(element, -5);
			}
			if (honeyPots > 0) {
				db.updateScore(element, honeyPots*15);
			}
			else {
				db.updateScore(element, -1);
			}
			if (writes > 10) {
				db.updateScore(element, 5);
				if (WriteEndEntropy > 4) {
					db.updateScore(element, 10);
				}
			}else {
				db.updateScore(element, -2);
			}
			if (new_writes > 10) {
				db.updateScore(element, 10);
				if (WriteEndEntropy > 4) {
					db.updateScore(element, 10);
				}
			}else {
				db.updateScore(element, -2);
			}
		    if (renames > 10) {
				db.updateScore(element, 10);
				if (WriteEndEntropy > 4) {
					db.updateScore(element, 10);
				}
			}else {
				db.updateScore(element, -2);
			}
			if (deletes > 10) {
				db.updateScore(element, 5);
			}else {
				db.updateScore(element, -1);
			}
			std::cout << "proc_id: " << element <<
			", score: " << db.getScore(element) << std::endl;
			if (db.getScore(element) > 100) {
				HANDLE tmpHandle;
				try {
					tmpHandle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, (DWORD)element);
				}
				catch (const std::exception&) {
					std::cout << "unable to open process" << std::endl;
				}

				if (NULL != tmpHandle)
				{
					
					bool signOrNot = false;
					/*try
					{
						signOrNot = chekSign(PathBuffer);
					}
					catch (const std::exception&)
					{
						std::cout << "problem in check signature in path " << PathBuffer << std::endl;
					}*/
					if (!signOrNot) {
						try
						{
							if (!TerminateProcess(tmpHandle, 0)) {
								std::cout << "unsuccess terminate process in path" << PathBuffer << std::endl;
							}
							else {
								//handles.erase(element);
								std::cout << "Malware detected!!! Terminating malicios process!!!" << "process num: " << element << "\n\r" << std::endl;
								Beep(523, 500);
							}
							
						}
						catch (const std::exception&) {
							std::cout << "unable to terminate process in path" << PathBuffer << std::endl;
						}

					}
				}
			}
		}
		db.zeroOperations();
		mtx.unlock();
		Sleep(3000);
	}
	
}



int main(int argc, char *argv[])
{
	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	SecurityDatabase db;
	std::set<HANDLE> handles;
	std::mutex mtx;
	HANDLE hPort;
	HRESULT hr;

	hr = FilterConnectCommunicationPort(NAGUARD_PORT_NAME, 0, NULL, 0, NULL, &hPort);
	if (FAILED(hr))	{
		printf("ERROR: FilterConnectCommunicationPort() \n");
		return 1;
	} else {
		printf("Port connected!\n");
	}

	



	
	//std::thread t(func, std::ref(db));
	std::thread t1(securityWorker, std::ref(db), std::ref(handles), std::ref(mtx), std::ref(hPort));
	std::thread t2(scheduler, std::ref(db), std::ref(handles), std::ref(mtx));
	t1.join();
	t2.join();
	return 0;
}