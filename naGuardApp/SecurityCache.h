/*
Date: 25.12.2018
Date updated: 25.12.2018
Author: Naftaly Avadiaev

TODO:


Comments to self:

*/
#ifndef __SECURITYMANAGER_H__
#define __SECURITYMANAGER_H__
#include "naGuardApp.h"
#include <stdlib.h>
#include <fltUser.h>
#include <iostream>
#include "../inc/SharedData.h"
#include <set>






class SecurityManager {
private:
	SecurityDatabase db;
	std::set<HANDLE> handles;
	std::mutex mtx;

	void securityWorker()
	{
		HANDLE hPort;
		HRESULT hr = S_OK;
		PR_DATA msg = (PR_DATA)HeapAlloc(GetProcessHeap(), 0, sizeof(R_DATA));

		while (true)
		{
			hr = FilterGetMessage(hPort, &msg->MessageHeader, sizeof(R_DATA), NULL);
			if (!FAILED(hr)) {
				db.recordOperation(msg->content.process_id, msg->content.opcode, abs(msg->content.postop_entropy - msg->content.preop_entropy));
				std::cout << "db.recordOperation(" << msg->content.process_id << ", " 
												   << msg->content.opcode << ", " 
												   << abs(msg->content.postop_entropy - msg->content.preop_entropy) << ")" << std::endl;
				mtx.lock();
				handles.insert(msg->content.process_id);
				mtx.unlock();
			}

		}
	}
	void scheduler() 
	{
		float entropy = 0;
		int score = 0;
		unsigned int total_writes = 0, total_renames = 0, total_deletes = 0;
		unsigned int writes = 0, renames = 0, deletes = 0;
		while (true) {
			for (HANDLE element : handles) {
				score = 0;
				entropy = db.getAverageWriteEntropy(element);
				total_writes = db.getTotalOps(element, 1);
				total_renames = db.getTotalOps(element, 2);
				total_deletes = db.getTotalOps(element, 3);
				writes = db.getOps(element, 1);
				renames = db.getOps(element, 2);
				deletes = db.getOps(element, 3);
			}
		}
	}

public:
	void startMonitoring() 
	{
		std::thread t1(&SecurityManager::securityWorker);
	}
	void stopMonitoring() {}
};

#endif
