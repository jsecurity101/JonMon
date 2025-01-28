#pragma once
#include <string>

struct EventSchema_KM {
	bool ConfigSet;
	bool ProcessCreation;
	bool ProcessTermination;
	bool ProcessHandleCreation;
	bool ProcessHandleDuplication;
	bool RemoteThreadCreation;
	bool ImageLoad;
	bool File;
	bool Registry;
	int ConfigVersion;
	int JonMonVersion;
};

struct EventSchema_Full {
	bool ConfigSet;
	bool ProcessCreation_Events; // KM Event
	bool ProcessTermination_Events; // KM Event
	bool ProcessHandleCreation_Events; // KM Event
	bool ProcessHandleDuplication_Events; // KM Event
	bool RemoteThreadCreation_Events; // KM Event
	bool ImageLoad_Events; // KM Event
	bool File_Events; // KM Event
	bool Registry_Events; // KM Event
	bool RPC_Events; // UM Event
	bool Network_Events; // UM Event
	bool DotNetLoad_Events; // UM Event
	bool AMSI_Events; // UM Event
	bool SchedTask_Events; // UM Event
	bool WMIEventSubscription_Events; // UM Event
	bool CryptUnprotect_Events; // UM Event
	bool ThreatIntelligence_Events; // UM Event
	bool ThreatIntelligence_Events_RemoteReadProcessMemory; // UM Event
	bool ThreatIntelligence_Events_RemoteWriteProcessMemory; // UM Event
	bool ThreatIntelligence_Events_RemoteVirtualAllocation; // UM Event
	bool ThreatIntelligence_Events_RemoteQueueUserAPC; // UM Event
	bool TokenImpersonation_Events; // UM Event
	int ConfigVersion;
	int JonMonVersion;
};


int ConfigFile(
	_In_ std::wstring ConfigFile,
	_Out_ EventSchema_Full* EventSchemaStruct
);