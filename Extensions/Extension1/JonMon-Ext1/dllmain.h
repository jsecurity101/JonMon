#ifdef JONMON_EXPORTS
#define JONMON_EXPORTS __declspec(dllexport)
#else
#define JONMON_EXPORTS __declspec(dllimport)
#endif

#include "Windows.h"
#include "evntprov.h"
#include "stdio.h"

//
// Export function that will query process tokens 
//
extern "C" JONMON_EXPORTS void TokenImpersonationCheck();

static GUID JonMonProvider = { 0xd8909c24, 0x5be9, 0x4502, { 0x98, 0xca, 0xab, 0x7b, 0xdc, 0x24, 0x89, 0x9d } };

const EVENT_DESCRIPTOR ThreadTokenImpersonation = { 0x1f, 0x0, 0x10, 0x4, 0x0, 0x0, 0x8000000000000000 };
#define ThreadTokenImpersonation_value 0x1f