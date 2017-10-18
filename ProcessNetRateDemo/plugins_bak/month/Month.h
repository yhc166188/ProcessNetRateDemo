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

#ifndef MONTH_PLUGIN_H
#define MONTH_PLUGIN_H

#include "../Plugin.h"
#include "MonthModel.h"
#include "MonthView.h"

class MonthPlugin : public Plugin
{
private:
    MonthModel *model;
    MonthView *view;

public:
    MonthPlugin();
    virtual ~MonthPlugin();

    virtual void InsertPacket(PacketInfoEx *pi);
    virtual void SetProcess(int puid);
    virtual void SaveDatabase();
    virtual void ClearDatabase();

    virtual const TCHAR * GetName();
    virtual const TCHAR * GetTemplateName();
    virtual DLGPROC GetDialogProc();
};

#endif
