// ProcessNetRateDemo.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <iostream>
#include <vector>
#include <map>
#include <memory>
#include <algorithm>  
//#include <stdlib.h>

#include <tlhelp32.h>
void PrintProcessList();

using namespace std;
#include "CpuCheck.h"

#include "utils/ProcessModel.h"

#include "utils/PortCache.h"
#include "utils/ProcessCache.h"

#include "traffic-src/PcapSource.h"
#include "traffic-src/VirtualSource.h"


std::vector<ProcessParam> _processlist;

CRITICAL_SECTION _property_cs;

// Capture thread
HANDLE         g_hCaptureThread;
bool           g_bCapture = false;

// Capture thread
HANDLE         g_hCpuThread;
bool           g_bCpu = false;

// Adapter
int            g_iAdapter = 0;



#pragma endregion

MMRESULT      m_KeepActiveTimer = NULL;



std::vector<CPUusage *> _processcpulist;


void ProcessLock()
{
	EnterCriticalSection(&_property_cs);
}

void ProcessUnlock()
{
	LeaveCriticalSection(&_property_cs);
}
void ProcessExport(std::vector<ProcessParam> &items)
{
	ProcessLock();
	items = _processlist;
	ProcessUnlock();
}
//根据进程ID杀进程  
int pskill(int id)   
{
	HANDLE hProcess = NULL;
	//打开目标进程  
	hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, id);
	if (hProcess == NULL) {
		wprintf(L"\nOpen Process fAiled:%d\n", GetLastError());
		return -1;
	}
	//结束目标进程  
	DWORD ret = TerminateProcess(hProcess, 0);
	if (ret == 0) {
		wprintf(L"%d", GetLastError());
	}
	return -1;
}
//----------------------------------------------------------------------------------------------//
//                                   Capture Thread                                            //
//----------------------------------------------------------------------------------------------//
static DWORD WINAPI CaptureThread(LPVOID lpParam)
{
	// VirtualSource source;
	PcapSource source;
	PacketInfo pi;
	PacketInfoEx pie;

	PortCache pc;

	// Init Filter ------------------------------------------------------------
	if (!source.Initialize())
	{
		return 1;
	}
	// Find Devices -----------------------------------------------------------
	if (!source.EnumDevices())
	{
		return 2;
	}

	// Select a Device --------------------------------------------------------
	if (!source.SelectDevice(g_iAdapter))
	{
		return 3;
	}

	// Capture Packets --------------------------------------------------------
	while (g_bCapture)
	{
		int pid = -1;
		int processUID = -1;
		TCHAR processName[MAX_PATH] = TEXT("Unknown");
		TCHAR processFullPath[MAX_PATH] = TEXT("-");

		// - Get a Packet (Process UID or PID is not Provided Here)
		bool timeout = false;
		if (!source.Capture(&pi, &timeout))
		{
			if (timeout) // Timeout
			{
				if (!g_bCapture) // Stop when user clicks "Stop"
				{
					break;
				}
				else // Just try again
				{
					continue;
				}
			}
			else // Error
			{
				if (source.Reconnect(g_iAdapter))
				{
					continue; // Auto-reconnect succeeded
				}
			}
		}

		// - Get PID
		if (pi.trasportProtocol == TRA_TCP)
		{
			pid = pc.GetTcpPortPid(pi.local_port);
			pid = (pid == 0) ? -1 : pid;
		}
		else if (pi.trasportProtocol == TRA_UDP)
		{
			pid = pc.GetUdpPortPid(pi.local_port);
			pid = (pid == 0) ? -1 : pid;
		}

		// - Get Process Name & Full Path
		if (pid != -1)
		{
			ProcessCache::instance()->GetName(pid, processName, MAX_PATH);
			ProcessCache::instance()->GetFullPath(pid, processFullPath, MAX_PATH);

			if (processName[0] == TEXT('\0')) // Cannot get process name from the table
			{
				pid = -1;
				_tcscpy_s(processName, MAX_PATH, TEXT("Unknown"));
				_tcscpy_s(processFullPath, MAX_PATH, TEXT("-"));

				// Map from Port -> PID is successful, but pid does not exist, rebuild cache
				if (pi.trasportProtocol == TRA_TCP)
				{
					pc.RebuildTcpTable();
				}
				else if (pi.trasportProtocol == TRA_UDP)
				{
					pc.RebuildUdpTable();
				}
			}
		}
		// else
		//    it's likely to be an ICMP packet or something else, 
		//    processName is still "Unknown" and processFullPath is still "-"

		// - Get Process UID
		processUID = ProcessModel::GetProcessUid(processName);

		// - Fill PacketInfoEx
		memcpy(&pie, &pi, sizeof(pi));

		pie.pid = pid;
		pie.puid = processUID;

		_tcscpy_s(pie.name, MAX_PATH, processName);
		_tcscpy_s(pie.fullPath, MAX_PATH, processFullPath);

		// - Update Process List
		ProcessModel::OnPacket(&pie);


		// - Dump
#ifdef DUMP_PACKET
		{
			TCHAR msg[128];
			TCHAR *protocol = (pi.networkProtocol == NET_ARP) ? TEXT("ARP") :
				(pi.trasportProtocol == TRA_TCP) ? TEXT("TCP") :
				(pi.trasportProtocol == TRA_UDP) ? TEXT("UDP") :
				(pi.trasportProtocol == TRA_ICMP) ? TEXT("ICMP") :
				(pi.trasportProtocol == TRA_IGMP) ? TEXT("IGMP") : TEXT("Other");
			TCHAR *dir = (pi.dir == DIR_UP) ? TEXT("Up") :
				(pi.dir == DIR_DOWN) ? TEXT("Down") : TEXT("");
			_stprintf_s(msg, _countof(msg),
				TEXT("[Time = %d.%06d] [Size = %4d Bytes] [Port = %d, %d] %s %s\n"),
				pi.time_s, pi.time_us, pi.size, pi.remote_port, pi.local_port, dir, protocol);

			OutputDebugString(msg);
		}
#endif
	}

	return 0;
}
//自定义排序函数  
bool SortByCpu(const ProcessParam &v1, const ProcessParam &v2) 
{
	return v1.cpu > v2.cpu;//降序排列  
}

bool SortByTxRate(const ProcessParam &v1, const ProcessParam &v2)
{
	return v1.prevTxRate > v2.prevTxRate;//降序排列  
}

void PrintVector(std::vector<ProcessParam> & vec)
{
	printf("\n\n\n\n\n\n");
	SYSTEMTIME time;
	GetLocalTime(&time);
	printf("%d/%d/%d %d:%d:%d\n", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
	float cputotal = 0.0;
	for (std::vector<ProcessParam>::iterator it = vec.begin(); it != vec.end(); it++)
	{
		printf("%s,cpu:%.2f,ProcessID: %d,mem:%uM,vmem:%uM ", (it)->name, (it)->cpu, (it)->pid, (it)->memsize, (it)->vmemsize);
		printf("rate tx: %dKB/s ,rx: %dKB/s \n", (it)->prevTxRate, (it)->prevRxRate);
		cputotal = cputotal + (it)->cpu;
	}

	printf("\n cputotal : %f\n", cputotal);
}


void WINAPI TimerKeepActive(UINT uTimerID, UINT uMsg, DWORD_PTR dwUser, DWORD_PTR dw1, DWORD_PTR dw2)
{

	std::vector<ProcessParam> items;
	ProcessExport(items);
	std::sort(items.begin(), items.end(), SortByCpu);
	PrintVector(items);
}



//心跳定时器，使用
void  StartKeepActiveTimer(void)
{
	//以毫秒指定延时的精度，数值越小定时器事件分辨率越高,缺省值为1ms 
	UINT wAccuracy = 1;
	//定时器时间间隔
	UINT uDelay = 1000;   //ms
	//创建定时器
	m_KeepActiveTimer = timeSetEvent(uDelay, wAccuracy, TimerKeepActive, NULL, TIME_PERIODIC);//DWORD(1)
	if (NULL == m_KeepActiveTimer)
	{
		printf("Timer failed with error %d\n", GetLastError());
	}
}




void  StopKeepActiveTimer(void)
{

	if (m_KeepActiveTimer != NULL)
	{
		timeKillEvent(m_KeepActiveTimer);
		m_KeepActiveTimer = NULL;
	}
}


//windows 内存 使用率  
DWORD getWin_MemUsage()
{
	MEMORYSTATUS ms;
	::GlobalMemoryStatus(&ms);
	return ms.dwMemoryLoad;
}

__int64 CompareFileTime(FILETIME time1, FILETIME time2)
{
	__int64 a = time1.dwHighDateTime << 32 | time1.dwLowDateTime;
	__int64 b = time2.dwHighDateTime << 32 | time2.dwLowDateTime;

	return (b - a);
}
//WIN CPU使用情况  
void getWin_CpuUsage(){
	HANDLE hEvent;
	BOOL res;
	FILETIME preidleTime;
	FILETIME prekernelTime;
	FILETIME preuserTime;
	FILETIME idleTime;
	FILETIME kernelTime;
	FILETIME userTime;

	res = GetSystemTimes(&idleTime, &kernelTime, &userTime);
	preidleTime = idleTime;
	prekernelTime = kernelTime;
	preuserTime = userTime;

	hEvent = CreateEventA(NULL, FALSE, FALSE, NULL); // 初始值为 nonsignaled ，并且每次触发后自动设置为nonsignaled  

	//while (true)
	{
		WaitForSingleObject(hEvent, 1000);
		res = GetSystemTimes(&idleTime, &kernelTime, &userTime);

		__int64 idle = CompareFileTime(preidleTime, idleTime);
		__int64 kernel = CompareFileTime(prekernelTime, kernelTime);
		__int64 user = CompareFileTime(preuserTime, userTime);

		__int64 cpu = (kernel + user - idle) * 100 / (kernel + user);
		__int64 cpuidle = (idle)* 100 / (kernel + user);
		cout << "CPU利用率:" << cpu << "%" << " CPU空闲率:" << cpuidle << "%" << endl;

		preidleTime = idleTime;
		prekernelTime = kernelTime;
		preuserTime = userTime;
	}
}
//将TCHAR转为char   
//*tchar是TCHAR类型指针，*_char是char类型指针   
void TcharToChar(const TCHAR * tchar, char * _char)
{
	int iLength;
	//获取字节长度   
	iLength = WideCharToMultiByte(CP_ACP, 0, tchar, -1, NULL, 0, NULL, NULL);
	//将tchar值赋给_char    
	WideCharToMultiByte(CP_ACP, 0, tchar, -1, _char, iLength, NULL, NULL);
}

//----------------------------------------------------------------------------------------------//
//                                   Capture Thread                                            //
//----------------------------------------------------------------------------------------------//
static DWORD WINAPI CpuThread(LPVOID lpParam)
{
	//system("WMIC diskdrive get Name, Manufacturer, Model");
//	InitializeCriticalSection(&);
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	int cpunum = info.dwNumberOfProcessors;
	printf("cpu num :%d \n", cpunum);

	DWORD usemem = getWin_MemUsage();
	printf("usemem:%d%\n", usemem);
	getWin_CpuUsage();
	HANDLE pHandle;
	PROCESSENTRY32 proc;
	DWORD procId;
	while (true)
	{
		ProcessModel::OnTimer();
		std::vector<ProcessModel::ProcessItem> processes;
		ProcessModel::Export(processes);


		pHandle = CreateToolhelp32Snapshot(0x2, 0x0);
		if (pHandle == INVALID_HANDLE_VALUE){
			return 0;
		}
		proc.dwSize = sizeof(PROCESSENTRY32);
		while (Process32Next(pHandle, &proc)){


			char chExeFile[256];
			sprintf_s(chExeFile, "%ws", proc.szExeFile);
			CPUusage *usg = new CPUusage(proc.th32ProcessID, chExeFile);
			usg->get_cpu_usage();
			for (unsigned int i = 0; i < processes.size(); i++)
			{
				if (processes[i].pid == proc.th32ProcessID)
				{
					usg->set_process_rxrate(processes[i].prevRxRate);
					usg->set_process_txrate(processes[i].prevTxRate);
					break;
				}
			}
			_processcpulist.push_back(usg);
		}
		Sleep(500);
		ProcessLock();
		_processlist.clear();
		float cputotal = 0.0;
		for (unsigned int i = 0; i < _processcpulist.size(); i++)
		{

			float cpu = 0.0;
			unsigned long long mem = 0;
			unsigned long long vmem = 0;
			_processcpulist[i]->get_memory_usage(_processcpulist[i]->get_process_pid(), &mem, &vmem);
			cpu = _processcpulist[i]->get_cpu_usage();
			
			ProcessParam pProcessParam; //= new ProcessParam;

			RtlZeroMemory(&pProcessParam, sizeof(ProcessParam));
			pProcessParam.pid = _processcpulist[i]->get_process_pid();
			char *pchProcessName = _processcpulist[i]->get_process_name();
			strncpy_s(pProcessParam.name, pchProcessName, sizeof(pProcessParam.name)-1);
			pProcessParam.cpu = (cpu > 0) ? cpu:0;
			pProcessParam.memsize = mem / 1024 / 1024;
			pProcessParam.vmemsize = vmem / 1024 / 1024;

			char szColumn[2][MAX_PATH] = {0};
			sprintf_s(szColumn[0], MAX_PATH, "%d.%d",_processcpulist[i]->get_process_txrate() / 1024, ((_processcpulist[i]->get_process_txrate()) % 1024 + 51) / 108);
			sprintf_s(szColumn[1], MAX_PATH, "%d.%d",_processcpulist[i]->get_process_rxrate() / 1024, ((_processcpulist[i]->get_process_rxrate()) % 1024 + 51) / 108);
			//printf("%s,cpu:%.2f,ProcessID: %d,mem:%uM,vmem:%uM ", _processcpulist[i]->get_process_name(), cpu, _processcpulist[i]->get_process_pid(), mem / 1024 / 1024, vmem / 1024 / 1024);
			//printf("rate tx: %sKB/s ,rx: %sKB/s \n", szColumn[2], szColumn[3]);
			pProcessParam.prevRxRate = atoi(szColumn[1]);
			pProcessParam.prevTxRate = atoi(szColumn[0]);
			cputotal = cputotal + pProcessParam.cpu;
			
			_processlist.push_back(pProcessParam);			
			delete _processcpulist[i];
		}

		ProcessUnlock();
		_processcpulist.clear();
		CloseHandle(pHandle);
		Sleep(500);
	}


	return 0;
}



int _tmain(int argc, _TCHAR* argv[])
{
	InitializeCriticalSection(&_property_cs);
	StartKeepActiveTimer();
	ProcessModel::Init();
	// Start Thread
	g_bCapture = true;
	g_hCaptureThread = CreateThread(0, 0, CaptureThread, 0, 0, 0);
	g_hCpuThread = CreateThread(0, 0, CpuThread, 0, 0, 0);

	while (true)
	{
		Sleep(100);
	}
	return 0;

}








