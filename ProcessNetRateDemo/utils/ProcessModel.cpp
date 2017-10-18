// Copyright (C) 2012-2014 F32 (feng32tc@gmail.com)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 3 as
// published by the Free Software Foundation;
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 

#include "stdafx.h"
#include "ProcessModel.h"
#include "ProcessCache.h"

#pragma region Members of Process

std::vector<ProcessModel::ProcessItem> ProcessModel::_processes;
CRITICAL_SECTION ProcessModel::_cs;

#pragma endregion

//extern Profile g_profile;

 void ProcessModel::Init()
{
    // Init Critical Section
    InitializeCriticalSection(&_cs);

}

void ProcessModel::Lock()
{
    EnterCriticalSection(&_cs);
}

void ProcessModel::Unlock()
{
    LeaveCriticalSection(&_cs);
}

// Event handlers
void ProcessModel::OnPacket(PacketInfoEx *pi)
{
	int index = pi->puid;//GetProcessIndex(pi->puid);

    if (index == -1) // A new process
    {
        // Insert a ProcessItem
        ProcessItem item;

        RtlZeroMemory(&item, sizeof(item));
        item.pid = pi->pid; // The first pid is logged
		item.puid = index;
        _tcscpy_s(item.name, MAX_PATH, pi->name);
        _tcscpy_s(item.fullPath, MAX_PATH, pi->fullPath);

        item.txRate = 0;
        item.rxRate = 0;
        item.prevTxRate = 0;
        item.prevRxRate = 0;

        // Add to process list
        Lock();
        _processes.push_back(item);
        Unlock();
    }
    else
    {
        Lock();

        // Update the ProcessItem that already Exists
        ProcessItem &item = _processes[index];

        if (pi->dir == DIR_UP)
        {
            item.txRate += pi->size;
        }
        else if (pi->dir == DIR_DOWN)
        {
            item.rxRate += pi->size;
        }

        Unlock();
    }
}

void ProcessModel::OnTimer()
{
    Lock();
    // Update Rate
    for(unsigned int i = 0; i < _processes.size(); i++)
    {
        ProcessItem &item = _processes[i];

        item.prevTxRate = item.txRate;
        item.prevRxRate = item.rxRate;

        item.txRate = 0;
        item.rxRate = 0;
	}
	Unlock();
}

void ProcessModel::Export(std::vector<ProcessModel::ProcessItem> &items)
{
	Lock();
	items = _processes;
	Unlock();
}

// Utils
int ProcessModel::GetProcessUid(int index)
{
    Lock();
    int puid = _processes[index].puid;
    Unlock();
    return puid;
}

int ProcessModel::GetProcessCount()
{
    Lock();
    int size = _processes.size();
    Unlock();
    return size;
}

int ProcessModel::GetProcessUid(const TCHAR *name)
{
    int puid = -1;
    Lock();
    for(unsigned int i = 0; i < _processes.size(); i++)
    {
        if (_tcscmp(_processes[i].name, name) == 0 )
        {
			puid = i;//_processes[i].puid;
            break;
        }
    }
    Unlock();
    return puid;
}

bool ProcessModel::GetProcessName(int puid, TCHAR *buf, int len)
{
    bool result = false;
    Lock();
    for(unsigned int i = 0; i < _processes.size(); i++)
    {
        if (_processes[i].puid == puid )
        {
            _tcscpy_s(buf, len, _processes[i].name);
            result = true;
            break;
        }
    }
    Unlock();
    return result;
}

int ProcessModel::GetProcessIndex(int puid)
{
    int index = -1;
    Lock();
    for(unsigned int i = 0; i < _processes.size(); i++)
    {
        if (_processes[i].puid == puid )
        {
            index = i;
            break;
        }
    }
    Unlock();
    return index;
}

bool ProcessModel::GetProcessRate(int puid, int *txRate, int *rxRate)
{
    int index = GetProcessIndex(puid);

    if (index == -1 )
    {
        return false;
    }
    else
    {
        Lock();
        *txRate = _processes[index].prevTxRate;
        *rxRate = _processes[index].prevRxRate;
        Unlock();
        return true;
    }
}
