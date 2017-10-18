// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

//#pragma once
//
//#include "targetver.h"
//
//#include <stdio.h>
//#include <tchar.h>
//#include <time.h>



#pragma once

#define WIN32_LEAN_AND_MEAN

#pragma region TCP/UDP Table Size Definition

#define  ANY_SIZE 1024

#pragma endregion

#include <winsock2.h>
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <shellapi.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <uxtheme.h>

#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <assert.h>
#include <math.h>
#include <time.h>

// we use "tstring" that works with TCHARs
#include <string>
#include <xstring>

#ifdef _UNICODE
#define tstring wstring
#else
#define tstring string
#endif

#include <vector>
#include <map>

#include <tcpmib.h>

//#include "targetver.h"
#include <mmsystem.h>

#pragma comment(lib,"winmm")  //lib file
// TODO: reference additional headers your program requires here

//#define SCWEB_DEBUG(n,...) do{\
//	char     szBuffer[1024];\
//	sprintf_s(szBuffer, "debugtest[%s(%d) %s ] : "n , __FILE__,__LINE__, __FUNCTION__, __VA_ARGS__);\
//
//}while(0);


typedef struct tagProcessParam
{
	// Static Parameters

	int  puid;
	char name[MAX_PATH];
	char fullPath[MAX_PATH];

	int prevTxRate;
	int prevRxRate;

	int pid;
	float cpu;
	unsigned long long memsize;
	unsigned long long vmemsize;

} ProcessParam;


