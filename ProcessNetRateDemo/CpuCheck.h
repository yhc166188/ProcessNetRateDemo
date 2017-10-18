#ifndef CPUCHECK_H  
#define CPUCHECK_H  
#include <Windows.h>   
//ԭ������GetProcessTimes()�������ϴε��õõ��Ľ����������õ�ĳ��ʱ����CPU��ʹ��ʱ��  
//C++ ��ȡ�ض����̹涨CPUʹ����  



class CPUusage {
private:
	typedef long long          int64_t;
	typedef unsigned long long uint64_t;
	HANDLE _hProcess;
	unsigned long iprocess_pid;
	int iPrevTxRate;
	int iPrevRxRate;
	char   chprocess_name[256];
	int _processor;    //cpu����    
	int64_t _last_time;         //��һ�ε�ʱ��    
	int64_t _last_system_time;


	// ʱ��ת��    
	uint64_t file_time_2_utc(const FILETIME* ftime);

	// ���CPU�ĺ���    
	int get_processor_number();

	//��ʼ��  
	void init()
	{
		_last_system_time = 0;
		_last_time = 0;
		_hProcess = 0;
	}

	//�رս��̾��  
	void clear()
	{
		if (_hProcess) {
			CloseHandle(_hProcess);
			_hProcess = 0;
		}
	}

public:
	CPUusage(DWORD ProcessID,char *pchProcessName):
		iPrevRxRate(0),
		iPrevTxRate(0)
	{
		iprocess_pid = ProcessID;
		strcpy_s(chprocess_name, pchProcessName);
		init();
		_processor = get_processor_number();
		setpid(ProcessID);

	}
	CPUusage() { init(); _processor = get_processor_number(); }
	~CPUusage() { clear(); }

	//����ֵΪ���̾�������ж�OpenProcess�Ƿ�ɹ�  
	HANDLE setpid(DWORD ProcessID) {
		clear();    //���֮ǰ���ӹ���һ�����̣����ȹر����ľ��  
		init();
		return _hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, ProcessID);
	}

	char * get_process_name(){ return chprocess_name; }
	unsigned long get_process_pid(){ return iprocess_pid; }
	void set_process_txrate(int iratedata){ iPrevTxRate = iratedata; }
	int get_process_txrate(){ return iPrevTxRate; }
	void set_process_rxrate(int iratedata){ iPrevRxRate = iratedata; }
	int get_process_rxrate(){ return iPrevRxRate; }
	//-1 ��Ϊʧ�ܻ�������˳��� ����ɹ����״ε��û᷵��-2����;��setpid������PID���״ε���Ҳ�᷵��-2��  
	float get_cpu_usage();

	/// ��ȡ��ǰ�����ڴ�������ڴ�ʹ����������-1ʧ�ܣ�0�ɹ�  
	int get_memory_usage(int pid, uint64_t* mem, uint64_t* vmem);


	/// ��ȡ��ǰ�����ܹ�����д��IO�ֽ���������-1ʧ�ܣ�0�ɹ�  
	int get_io_bytes(uint64_t* read_bytes, uint64_t* write_bytes);
};





#endif