/*
	Date: 24.12.2018
	Date updated: 25.12.2018
	Author: Naftaly Avadiaev
	
	TODO:
	1. Do self code review. []
	2. 

	Comments to self:
	1. In the future "bool isSuspected(...)" and "bool isMalicious()" will have different behavior.
	2. In the future SecurityDatabase will be implemented in more fine-grained sync mechanism.
	3. Redundant code should be removed. Don't remove anything before submission unless 100% sure, it is really redundant.
*/
#ifndef __NAGUARDAPP_H__
#define __NAGUARDAPP_H__
#include <Windows.h>
#include <unordered_map>
#include <mutex>
#include <string>
#include <iostream>
using namespace std;

#define OPS_NUM 4
#define honeypot_a
#define honeypot_z 
#define honeypot_0 00000_honeypot_1qaz2wsx

class ThreadInfo {
private:
	unsigned long m_jiffies;
	unsigned long not_ext_m_jiffies;
	unsigned long honey_m_jiffies;
	int m_score;
	unsigned long honeyPotsCounter;
	float write_end_entropy;
	float write_delta_entropy;
	float new_write_entropy;
	unsigned long notExtInListWrite;
	unsigned long honey_pots_touched;
	unsigned long m_total_ops[OPS_NUM];
	unsigned long m_ops[OPS_NUM];
	

public:
	ThreadInfo() : m_score(0), m_jiffies(0), not_ext_m_jiffies(0), honey_m_jiffies(0), honeyPotsCounter(0), write_end_entropy(0), write_delta_entropy(0), new_write_entropy(0), notExtInListWrite(0), honey_pots_touched(0), m_total_ops{ 0, 0, 0, 0 }, m_ops{ 0, 0, 0, 0 } {};
	unsigned long getTotalOps() 
	{
		unsigned int sum = 0;
		for (int i = 0; i < OPS_NUM; i++)
			sum += m_total_ops[i];
		return sum;
	};
	unsigned long getOps()
	{
		unsigned int sum = 0;
		for (int i = 0; i < OPS_NUM; i++)
			sum += m_ops[i];
		return sum;
	};
	void increaseScore(int score) { m_score += score; m_score = max(m_score, 0); }
	void increaseWriteEntropy(float entropy, float deltaEntropy) {
		write_end_entropy += entropy;
		write_delta_entropy += deltaEntropy;
	}
	void increaseNewWriteEntropy(float entropy) { new_write_entropy += entropy; }
	void increaseTotalOps(int opcode) { m_total_ops[opcode]++; }
	unsigned long getTotalOps(int opcode) const { return m_total_ops[opcode]; }
	void increaseOps(int opcode, unsigned long jiffies) 
	{ 
		if (jiffies > m_jiffies) {
			m_ops[0] = 0;
			m_ops[1] = 0;
			m_ops[2] = 0;
			m_ops[3] = 0;
			m_ops[opcode]++;
		} else {
			m_ops[opcode]++;
		}
		m_jiffies = jiffies;
	}
	void increaseHoneyPots(unsigned long jiffies)
	{
		if (jiffies > honey_m_jiffies) {
			honeyPotsCounter = 1;
		}
		else {
			honeyPotsCounter++;
		}
		honey_m_jiffies = jiffies;
	}
	void increaseNotExtInListWrite(unsigned long jiffies)
	{
		if (jiffies > not_ext_m_jiffies) {
			notExtInListWrite = 1;
		}
		else {
			notExtInListWrite++;
		}
		not_ext_m_jiffies = jiffies;
	}
	unsigned long getOps(int opcode, unsigned long jiffies) 
	{ 
		if (jiffies > m_jiffies)
			return 0;
		else
			return m_ops[opcode]; 
	}
	void zeroTotalOps(int opcode) { m_total_ops[opcode] = 0; }
	void zeroOps(int opcode) { m_ops[opcode] = 0; }
	float getWriteEndEntropy() const { return write_end_entropy; }
	unsigned long getHoneyPots() const { return honeyPotsCounter; }
	float getWriteDeltaEntropy() const { return write_delta_entropy; }
	unsigned long getNotExtInListWrite() const { return notExtInListWrite; }
	float getNewWriteEntropy() const { return new_write_entropy; }
	int getScore() const { return m_score; }

};

class SecurityDatabase {
private:
	std::mutex mtx;
	//unsigned int jiffies;
	unsigned long record_jiffies;
	unsigned long zero_jiffies;
	std::unordered_map<HANDLE, ThreadInfo> db;
public:
	SecurityDatabase() : record_jiffies(0), zero_jiffies(0) {};
	~SecurityDatabase() {};
	void zeroOperations() {	zero_jiffies = record_jiffies + 1; }
	void removeItem(HANDLE h) { db.erase(h); }
	void recordOperation(HANDLE process_id, int opcode, WCHAR* preFileName, float pre_entropy, float post_entropy, bool exist)
	{
		std::wstring ws(preFileName);
		string strFileName(ws.begin(), ws.end());

		std::lock_guard<std::mutex> lock(mtx);
		record_jiffies = zero_jiffies + 1;
		std::unordered_map<HANDLE, ThreadInfo>::iterator it = db.find(process_id);
		float DeltaEntropy = post_entropy - pre_entropy;
		float entropy = post_entropy;
		int NewOpcode = opcode;
		//if opcode = 1 means write & if start entropy = 0 it means we writing to a new file
		if (NewOpcode == 1 && pre_entropy == 0) {
			NewOpcode = 0;
		}
		if (it == db.end()) { /* new entry */
			ThreadInfo threadInfo;
			if (!exist) {
				if (NewOpcode == 1 || NewOpcode == 0) {
					if (entropy > 3.5) {
						threadInfo.increaseNotExtInListWrite(record_jiffies);
					}
				}
				db.insert(std::make_pair(process_id, threadInfo));
			}
			else {
				if (NewOpcode == 1) {
					threadInfo.increaseWriteEntropy(entropy, DeltaEntropy);
				}
				else if (NewOpcode == 0) {
					threadInfo.increaseNewWriteEntropy(DeltaEntropy);
				}

				threadInfo.increaseTotalOps(NewOpcode);
				threadInfo.increaseOps(NewOpcode, record_jiffies);
				std::cout << strFileName;
				if ((strFileName.find("zzzzz_honeypot_1qaz2wsx") != std::string::npos) || (strFileName.find("aaaaa_honeypot_1qaz2wsx") != std::string::npos) || (strFileName.find("00000_honeypot_1qaz2wsx") != std::string::npos)) {
					//printf("/n!!!honeypot touched !!!/n");
					//std::cout << strFileName;
					threadInfo.increaseHoneyPots(record_jiffies);
				}
				db.insert(std::make_pair(process_id, threadInfo));
			}
		} else { /* know process */
			if (!exist) {
				if (NewOpcode == 1 || NewOpcode == 0) {
					if (entropy > 4) {
						it->second.increaseNotExtInListWrite(record_jiffies);
					}
				}
			}
			else
			{
				if (NewOpcode == 1) {
					it->second.increaseWriteEntropy(entropy, DeltaEntropy);
				}
				else if (NewOpcode == 0) {
					it->second.increaseNewWriteEntropy(DeltaEntropy);
				}
				it->second.increaseTotalOps(NewOpcode);
				it->second.increaseOps(NewOpcode, max(record_jiffies, zero_jiffies));
				if ((strFileName.find("zzzzz_honeypot_1qaz2wsx") != std::string::npos) || (strFileName.find("aaaaa_honeypot_1qaz2wsx") != std::string::npos) || (strFileName.find("00000_honeypot_1qaz2wsx") != std::string::npos)) {
					//printf("/n!!!honeypot touched !!!/n");
					//std::cout << strFileName;
					it->second.increaseHoneyPots(record_jiffies);
				}
			}
		}
		
	}
 	//void updateScore(HANDLE process_id) {}
	int getScore(HANDLE process_id) 
	{
		std::lock_guard<std::mutex> lock(mtx);
		std::unordered_map<HANDLE, ThreadInfo>::iterator it = db.find(process_id);
		if (it != db.end())
			return it->second.getScore();
		return -1;
	}
	void updateScore(HANDLE process_id, int score)
	{
		std::lock_guard<std::mutex> lock(mtx);
		std::unordered_map<HANDLE, ThreadInfo>::iterator it = db.find(process_id);
		if (it != db.end())
			it->second.increaseScore(score);
	}
	/*float getWriteEndEntropy() const { return write_end_entropy; }
	float getWriteDeltaEntropy() const { return write_delta_entropy; }
	float getNewWriteEntropy() const { return new_write_entropy; }*/
	float getWriteEndEntropy(HANDLE process_id)
	{
		std::lock_guard<std::mutex> lock(mtx);
		std::unordered_map<HANDLE, ThreadInfo>::iterator it = db.find(process_id);
		if (it != db.end())
			return it->second.getWriteEndEntropy();
		return -1;
	}
	float getWriteDeltaEntropy(HANDLE process_id)
	{
		std::lock_guard<std::mutex> lock(mtx);
		std::unordered_map<HANDLE, ThreadInfo>::iterator it = db.find(process_id);
		if (it != db.end())
			return it->second.getWriteDeltaEntropy();
		return -1;
	}
	float getNewWriteEntropy(HANDLE process_id)
	{
		std::lock_guard<std::mutex> lock(mtx);
		std::unordered_map<HANDLE, ThreadInfo>::iterator it = db.find(process_id);
		if (it != db.end())
			return it->second.getNewWriteEntropy();
		return -1;
	}
	unsigned int getTotalOps(HANDLE process_id, int opcode) 
	{
		std::lock_guard<std::mutex> lock(mtx);
		std::unordered_map<HANDLE, ThreadInfo>::iterator it = db.find(process_id);
		if (it != db.end())
			return it->second.getTotalOps(opcode);
		return 0;
	}
	unsigned int getOps(HANDLE process_id, int opcode)
	{
		std::lock_guard<std::mutex> lock(mtx);
		std::unordered_map<HANDLE, ThreadInfo>::iterator it = db.find(process_id);
		if (it != db.end()) {
			return it->second.getOps(opcode, max(record_jiffies, zero_jiffies));
		} else {
			return 0;
		}
	}
	unsigned long getHoneyPots(HANDLE process_id)
	{
		std::lock_guard<std::mutex> lock(mtx);
		std::unordered_map<HANDLE, ThreadInfo>::iterator it = db.find(process_id);
		if (it != db.end()) {
			return it->second.getHoneyPots();
		}
		else {
			return 0;
		}
	}
	unsigned long getNotExtInListWrite(HANDLE process_id)
	{
		std::lock_guard<std::mutex> lock(mtx);
		std::unordered_map<HANDLE, ThreadInfo>::iterator it = db.find(process_id);
		if (it != db.end()) {
			return it->second.getNotExtInListWrite();
		}
		else {
			return 0;
		}
	}
	
	/*float getWriteEndEntropy() const { return write_end_entropy; }
	float getWriteDeltaEntropy() const { return write_delta_entropy; }
	float getNewWriteEntropy() const { return new_write_entropy; }*/
	float getAverageEndWriteEntropy(HANDLE process_id) 
	{
		unsigned long totalOps = getTotalOps(process_id, 1);
		//totalOps = totalOps + getTotalOps(process_id, 0);
		if (totalOps == 0) return 0;
		return getWriteEndEntropy(process_id) / totalOps;
	}
	float getAverageDeltaWriteEntropy(HANDLE process_id)
	{
		unsigned long totalOps = getTotalOps(process_id, 1);
		//totalOps = totalOps + getTotalOps(process_id, 0);
		if (totalOps == 0) return 0;
		return getWriteDeltaEntropy(process_id) / totalOps;
	}
	float getAverageNewWriteEntropy(HANDLE process_id)
	{
		unsigned long totalOps = getTotalOps(process_id, 0);
		//totalOps = totalOps + getTotalOps(process_id, 0);
		if (totalOps == 0) return 0;
		return getNewWriteEntropy(process_id) / totalOps;
	}
	bool isSuspected(HANDLE process_id) 
	{
		return isMalicious(process_id); 
	}
	bool isMalicious(HANDLE process_id)  
	{
		int score = getScore(process_id);
		if (score >= 100) return true;
		return false;
	}
};

#endif