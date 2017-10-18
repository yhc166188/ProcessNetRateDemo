#include "stdafx.h"
#include "CpuCheck.h"
#include <windows.h>  
#include <psapi.h>  
#include <assert.h>  


float CPUusage::get_cpu_usage()
{

	FILETIME now;
	FILETIME creation_time;
	FILETIME exit_time;
	FILETIME kernel_time;
	FILETIME user_time;
	int64_t system_time;
	int64_t time;
	int64_t system_time_delta;
	int64_t time_delta;

	DWORD exitcode;

	float cpu = -1;

	if (!_hProcess)
	{
		return -1;
	}


	GetSystemTimeAsFileTime(&now);

	//判断进程是否已经退出  
	GetExitCodeProcess(_hProcess, &exitcode);
	if (exitcode != STILL_ACTIVE) {
		clear();
		printf("exitcode:%d process exit\n", exitcode);
		return -1;
	}

	//计算占用CPU的百分比  
	if (!GetProcessTimes(_hProcess, &creation_time, &exit_time, &kernel_time, &user_time))
	{
		DWORD lasterr = GetLastError();
		clear();
		printf("lasterr:%d process cpu\n", lasterr);
		return -1;
	}
	system_time = (file_time_2_utc(&kernel_time) + file_time_2_utc(&user_time))
		/ _processor;
	time = file_time_2_utc(&now);

	//判断是否为首次计算  
	if ((_last_system_time == 0) || (_last_time == 0))
	{
		_last_system_time = system_time;
		_last_time = time;
		return -2;
	}

	system_time_delta = system_time - _last_system_time;
	time_delta = time - _last_time;

	if (time_delta == 0) {
		return -1;
	}

	cpu = (float)system_time_delta * 100 / (float)time_delta;
	_last_system_time = system_time;
	_last_time = time;
	return cpu;
}

CPUusage::uint64_t CPUusage::file_time_2_utc(const FILETIME* ftime)
{
	LARGE_INTEGER li;

	li.LowPart = ftime->dwLowDateTime;
	li.HighPart = ftime->dwHighDateTime;
	return li.QuadPart;
}

int CPUusage::get_processor_number()
{
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	return info.dwNumberOfProcessors;
}




int CPUusage::get_memory_usage(int pid, uint64_t* mem, uint64_t* vmem)
{
	PROCESS_MEMORY_COUNTERS pmc;
	if (GetProcessMemoryInfo(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid), &pmc, sizeof(pmc)))
	{
		if (mem) *mem = pmc.WorkingSetSize;
		if (vmem) *vmem = pmc.PagefileUsage;
		return 0;
	}
	return -1;
}



int CPUusage::get_io_bytes(uint64_t* read_bytes, uint64_t* write_bytes)
{
	IO_COUNTERS io_counter;
	if (GetProcessIoCounters(GetCurrentProcess(), &io_counter))
	{
		if (read_bytes) *read_bytes = io_counter.ReadTransferCount;
		if (write_bytes) *write_bytes = io_counter.WriteTransferCount;
		return 0;
	}
	return -1;
}