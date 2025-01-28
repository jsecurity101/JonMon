#include "config.h"
#include <iostream>
#include <fstream>
#include "nlohmann/json.hpp"

using json = nlohmann::json;


int ConfigFile(
    _In_ std::wstring ConfigFile,
    _Out_ EventSchema_Full* EventSchemaStruct
)
{
    //
    // Initialize the EventSchema structure
    //
    EventSchemaStruct->ConfigSet = true;
    EventSchemaStruct->ProcessCreation_Events = false;
    EventSchemaStruct->ProcessTermination_Events = false;
    EventSchemaStruct->File_Events = false;
    EventSchemaStruct->Registry_Events = false;
    EventSchemaStruct->ProcessHandleCreation_Events = false;
    EventSchemaStruct->ProcessHandleDuplication_Events = false;
    EventSchemaStruct->RemoteThreadCreation_Events = false;
    EventSchemaStruct->ImageLoad_Events = false;
    EventSchemaStruct->RPC_Events = false;
    EventSchemaStruct->Network_Events = false;
    EventSchemaStruct->DotNetLoad_Events = false;
    EventSchemaStruct->AMSI_Events = false;
    EventSchemaStruct->SchedTask_Events = false;
    EventSchemaStruct->WMIEventSubscription_Events = false;
    EventSchemaStruct->CryptUnprotect_Events = false;
    EventSchemaStruct->ThreatIntelligence_Events = false;
	EventSchemaStruct->ThreatIntelligence_Events_RemoteReadProcessMemory = false;
	EventSchemaStruct->ThreatIntelligence_Events_RemoteWriteProcessMemory = false;
	EventSchemaStruct->ThreatIntelligence_Events_RemoteVirtualAllocation = false;
	EventSchemaStruct->ThreatIntelligence_Events_RemoteQueueUserAPC = false;
    EventSchemaStruct->TokenImpersonation_Events = false;
    EventSchemaStruct->ConfigVersion = 0;
    EventSchemaStruct->JonMonVersion = 0;


    //
    // Open the JSON configuration file
    //
    std::ifstream jsonFile(ConfigFile);
    if (!jsonFile.is_open()) {
        std::wcerr << "Failed to open file: " << ConfigFile << std::endl;
        return 1;
    }

    json jsonData;
    jsonFile >> jsonData;

    if (jsonData.contains("ConfigVersion")) {
        std::string ConfigVersion = jsonData["ConfigVersion"];
        EventSchemaStruct->ConfigVersion = std::stoi(ConfigVersion);
    }

    if (jsonData.contains("JonMonVersion")) {
        std::string JonMonVersion = jsonData["JonMonVersion"];
        EventSchemaStruct->JonMonVersion = std::stoi(JonMonVersion);
    }

    if (jsonData.contains("ProcessCreation_Events")) {
        EventSchemaStruct->ProcessCreation_Events = jsonData["ProcessCreation_Events"];
    }

    if (jsonData.contains("File_Events")) {
        EventSchemaStruct->File_Events = jsonData["File_Events"];
    }

    if (jsonData.contains("Registry_Events")) {
        EventSchemaStruct->Registry_Events = jsonData["Registry_Events"];
	}

    if (jsonData.contains("ProcessTermination_Events")) {
        EventSchemaStruct->ProcessTermination_Events = jsonData["ProcessTermination_Events"];
	}

    if (jsonData.contains("ProcessHandleCreation_Events")) {
        EventSchemaStruct->ProcessHandleCreation_Events = jsonData["ProcessHandleCreation_Events"];
        }

    if (jsonData.contains("ProcessHandleDuplication_Events")) {
        EventSchemaStruct->ProcessHandleDuplication_Events = jsonData["ProcessHandleDuplication_Events"];
	}

    if (jsonData.contains("RemoteThreadCreation_Events")) {
        EventSchemaStruct->RemoteThreadCreation_Events = jsonData["RemoteThreadCreation_Events"];
    }

    if (jsonData.contains("ImageLoad_Events")) {
        EventSchemaStruct->ImageLoad_Events = jsonData["ImageLoad_Events"];
    }

    if(jsonData.contains("RPC_Events")) {
        EventSchemaStruct->RPC_Events = jsonData["RPC_Events"];
	}

    if(jsonData.contains("Network_Events")) {
        EventSchemaStruct->Network_Events = jsonData["Network_Events"];
	}

    if(jsonData.contains("DotNetLoad_Events")) {
        EventSchemaStruct->DotNetLoad_Events = jsonData["DotNetLoad_Events"];
	}

    if(jsonData.contains("AMSI_Events")) {
        EventSchemaStruct->AMSI_Events = jsonData["AMSI_Events"];
	}

    if(jsonData.contains("SchedTask_Events")) {
        EventSchemaStruct->SchedTask_Events = jsonData["SchedTask_Events"];
	}

    if (jsonData.contains("WMIEventSubscription_Events")) {
        EventSchemaStruct->WMIEventSubscription_Events = jsonData["WMIEventSubscription_Events"];
    }

    if (jsonData.contains("CryptUnprotect_Events")) {
        EventSchemaStruct->CryptUnprotect_Events = jsonData["CryptUnprotect_Events"];
	}

    if (jsonData.contains("ThreatIntelligence_Events")) {
        EventSchemaStruct->ThreatIntelligence_Events_RemoteReadProcessMemory = jsonData["ThreatIntelligence_Events"]["RemoteReadProcessMemory"];
        EventSchemaStruct->ThreatIntelligence_Events_RemoteWriteProcessMemory = jsonData["ThreatIntelligence_Events"]["RemoteWriteProcessMemory"];
        EventSchemaStruct->ThreatIntelligence_Events_RemoteVirtualAllocation = jsonData["ThreatIntelligence_Events"]["RemoteVirtualAllocation"];
        EventSchemaStruct->ThreatIntelligence_Events_RemoteQueueUserAPC = jsonData["ThreatIntelligence_Events"]["RemoteQueueUserAPC"];
		if (EventSchemaStruct->ThreatIntelligence_Events_RemoteReadProcessMemory || EventSchemaStruct->ThreatIntelligence_Events_RemoteWriteProcessMemory || EventSchemaStruct->ThreatIntelligence_Events_RemoteVirtualAllocation || EventSchemaStruct->ThreatIntelligence_Events_RemoteQueueUserAPC) {
            EventSchemaStruct->ThreatIntelligence_Events = true;
		}
    }

    if (jsonData.contains("TokenImpersonation_Events")) {
        EventSchemaStruct->TokenImpersonation_Events = jsonData["TokenImpersonation_Events"];
    } 
    return 0;
}