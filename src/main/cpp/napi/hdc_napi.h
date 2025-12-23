/**
 * HDC NAPI Interface Header
 * 
 * Defines all NAPI methods for HDC client library.
 */
#ifndef HDC_NAPI_H
#define HDC_NAPI_H

#include <napi/native_api.h>

#ifdef __cplusplus
extern "C" {
#endif

// Module initialization
napi_value Init(napi_env env, napi_value exports);

// Lifecycle management
napi_value HdcInit(napi_env env, napi_callback_info info);
napi_value HdcCleanup(napi_env env, napi_callback_info info);
napi_value HdcIsInitialized(napi_env env, napi_callback_info info);

// Connection management
napi_value HdcConnect(napi_env env, napi_callback_info info);
napi_value HdcDisconnect(napi_env env, napi_callback_info info);
napi_value HdcListTargets(napi_env env, napi_callback_info info);
napi_value HdcWaitForDevice(napi_env env, napi_callback_info info);
napi_value HdcCheckDevice(napi_env env, napi_callback_info info);
napi_value HdcDiscover(napi_env env, napi_callback_info info);

// Command execution
napi_value HdcShell(napi_env env, napi_callback_info info);
napi_value HdcExecute(napi_env env, napi_callback_info info);
napi_value HdcTargetBoot(napi_env env, napi_callback_info info);
napi_value HdcTargetMount(napi_env env, napi_callback_info info);
napi_value HdcSmode(napi_env env, napi_callback_info info);
napi_value HdcTmode(napi_env env, napi_callback_info info);

// File transfer
napi_value HdcFileSend(napi_env env, napi_callback_info info);
napi_value HdcFileRecv(napi_env env, napi_callback_info info);

// App management
napi_value HdcInstall(napi_env env, napi_callback_info info);
napi_value HdcUninstall(napi_env env, napi_callback_info info);
napi_value HdcSideload(napi_env env, napi_callback_info info);

// Port forwarding
napi_value HdcForward(napi_env env, napi_callback_info info);
napi_value HdcReverse(napi_env env, napi_callback_info info);
napi_value HdcForwardList(napi_env env, napi_callback_info info);
napi_value HdcForwardRemove(napi_env env, napi_callback_info info);

// Logging and debug
napi_value HdcHilog(napi_env env, napi_callback_info info);
napi_value HdcBugreport(napi_env env, napi_callback_info info);
napi_value HdcJpid(napi_env env, napi_callback_info info);

// Key management
napi_value HdcKeygen(napi_env env, napi_callback_info info);

// Info and error
napi_value HdcVersion(napi_env env, napi_callback_info info);
napi_value HdcHelp(napi_env env, napi_callback_info info);
napi_value HdcGetLastError(napi_env env, napi_callback_info info);
napi_value HdcGetErrorMessage(napi_env env, napi_callback_info info);

#ifdef __cplusplus
}
#endif

#endif // HDC_NAPI_H
