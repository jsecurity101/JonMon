#ifdef JONMON_EXPORTS
#define JONMON_EXPORTS __declspec(dllexport)
#else
#define JONMON_EXPORTS __declspec(dllimport)
#endif

#include "Windows.h"
#include "evntprov.h"
#include "stdio.h"
#include <TraceLoggingProvider.h> 

//
// Export function that will query process tokens 
//
extern "C" JONMON_EXPORTS void TokenImpersonationCheck();

