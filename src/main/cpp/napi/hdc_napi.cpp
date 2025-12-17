/**
 * HDC NAPI Module Entry
 * 
 * This file provides the NAPI interface for HDC client library.
 * It bridges ArkTS/JavaScript calls to the native HDC core functionality.
 */

#include "hdc_napi.h"
#include "hdc_client_wrapper.h"
#include <hilog/log.h>
#include <string>
#include <cstring>
#include <vector>

#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0x0001
#define LOG_TAG "HdcNapi"

using namespace HdcWrapper;

// Helper functions for NAPI type conversion
static bool GetStringArg(napi_env env, napi_value value, std::string& result) {
    napi_valuetype valueType;
    if (napi_typeof(env, value, &valueType) != napi_ok || valueType != napi_string) {
        return false;
    }
    
    size_t bufSize = 0;
    if (napi_get_value_string_utf8(env, value, nullptr, 0, &bufSize) != napi_ok) {
        return false;
    }
    
    // bufSize=0 表示空字符串，这是有效的
    std::vector<char> buf(bufSize + 1);
    size_t copied = 0;
    if (napi_get_value_string_utf8(env, value, buf.data(), buf.size(), &copied) != napi_ok) {
        return false;
    }
    
    result = std::string(buf.data(), copied);
    return true;
}

static bool GetInt32Arg(napi_env env, napi_value value, int32_t& result) {
    napi_valuetype valueType;
    if (napi_typeof(env, value, &valueType) != napi_ok || valueType != napi_number) {
        return false;
    }
    return napi_get_value_int32(env, value, &result) == napi_ok;
}

static bool GetUint32Arg(napi_env env, napi_value value, uint32_t& result) {
    napi_valuetype valueType;
    if (napi_typeof(env, value, &valueType) != napi_ok || valueType != napi_number) {
        return false;
    }
    return napi_get_value_uint32(env, value, &result) == napi_ok;
}

static bool GetBoolArg(napi_env env, napi_value value, bool& result) {
    napi_valuetype valueType;
    if (napi_typeof(env, value, &valueType) != napi_ok || valueType != napi_boolean) {
        return false;
    }
    return napi_get_value_bool(env, value, &result) == napi_ok;
}

static napi_value CreateStringResult(napi_env env, const std::string& str) {
    napi_value result = nullptr;
    if (napi_create_string_utf8(env, str.c_str(), str.length(), &result) != napi_ok) {
        napi_get_undefined(env, &result);
    }
    return result;
}

static napi_value CreateInt32Result(napi_env env, int32_t value) {
    napi_value result = nullptr;
    if (napi_create_int32(env, value, &result) != napi_ok) {
        napi_get_undefined(env, &result);
    }
    return result;
}

static napi_value CreateBoolResult(napi_env env, bool value) {
    napi_value result = nullptr;
    if (napi_get_boolean(env, value, &result) != napi_ok) {
        napi_get_undefined(env, &result);
    }
    return result;
}

// Create result object with code and output
static napi_value CreateCommandResult(napi_env env, int code, const std::string& output) {
    napi_value result = nullptr;
    if (napi_create_object(env, &result) != napi_ok) {
        napi_get_undefined(env, &result);
        return result;
    }
    
    napi_value codeValue = nullptr;
    if (napi_create_int32(env, code, &codeValue) == napi_ok) {
        napi_set_named_property(env, result, "code", codeValue);
    }
    
    napi_value outputValue = nullptr;
    if (napi_create_string_utf8(env, output.c_str(), output.length(), &outputValue) == napi_ok) {
        napi_set_named_property(env, result, "output", outputValue);
    }
    
    return result;
}

/**
 * HdcInit - Initialize HDC library
 * @param logLevel (optional) - Log level 0-5, default 3
 * @param sandboxPath (optional) - App sandbox path for storing keys
 * @returns int - 0 on success, error code on failure
 */
napi_value HdcInit(napi_env env, napi_callback_info info) {
    OH_LOG_INFO(LOG_APP, "HdcInit called");
    
    size_t argc = 2;
    napi_value args[2];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    int logLevel = 3;  // default log level
    std::string sandboxPath;
    
    if (argc > 0) {
        int32_t level;
        if (GetInt32Arg(env, args[0], level)) {
            logLevel = level;
        }
    }
    
    if (argc > 1) {
        GetStringArg(env, args[1], sandboxPath);
        OH_LOG_INFO(LOG_APP, "Sandbox path: %{public}s", sandboxPath.c_str());
    }
    
    int result = HdcClientWrapper::GetInstance().Init(logLevel, sandboxPath);
    return CreateInt32Result(env, result);
}

/**
 * HdcCleanup - Cleanup HDC library and release resources
 * @returns int - 0 on success
 */
napi_value HdcCleanup(napi_env env, napi_callback_info info) {
    OH_LOG_INFO(LOG_APP, "HdcCleanup called");
    HdcClientWrapper::GetInstance().Cleanup();
    return CreateInt32Result(env, 0);
}

/**
 * HdcIsInitialized - Check if HDC library is initialized
 * @returns boolean - true if initialized
 */
napi_value HdcIsInitialized(napi_env env, napi_callback_info info) {
    bool initialized = HdcClientWrapper::GetInstance().IsInitialized();
    OH_LOG_INFO(LOG_APP, "HdcIsInitialized: %{public}d", initialized);
    return CreateBoolResult(env, initialized);
}

// Async work data for HdcConnect
struct ConnectAsyncData {
    napi_async_work work;
    napi_deferred deferred;
    std::string host;
    uint16_t port;
    int32_t timeoutMs;
    int result;
};

// Execute callback - runs in worker thread
static void ConnectExecute(napi_env env, void* data) {
    ConnectAsyncData* asyncData = static_cast<ConnectAsyncData*>(data);
    OH_LOG_INFO(LOG_APP, "ConnectExecute: connecting to %{public}s:%{public}u", 
                asyncData->host.c_str(), asyncData->port);
    asyncData->result = HdcClientWrapper::GetInstance().Connect(
        asyncData->host, asyncData->port, asyncData->timeoutMs);
}

// Complete callback - runs in main thread
static void ConnectComplete(napi_env env, napi_status status, void* data) {
    ConnectAsyncData* asyncData = static_cast<ConnectAsyncData*>(data);
    
    napi_value result;
    napi_create_int32(env, asyncData->result, &result);
    
    if (asyncData->result == 0) {
        napi_resolve_deferred(env, asyncData->deferred, result);
    } else {
        // Still resolve with error code, let JS handle it
        napi_resolve_deferred(env, asyncData->deferred, result);
    }
    
    napi_delete_async_work(env, asyncData->work);
    delete asyncData;
}

/**
 * HdcConnect - Connect to device (async version, returns Promise)
 * @param host - Device IP address
 * @param port - Device port (default 8710)
 * @param timeoutMs (optional) - Connection timeout in ms
 * @returns Promise<int> - 0 on success, error code on failure
 */
napi_value HdcConnect(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value args[3];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    if (argc < 2) {
        OH_LOG_ERROR(LOG_APP, "HdcConnect: missing arguments");
        napi_value promise;
        napi_deferred deferred;
        napi_create_promise(env, &deferred, &promise);
        napi_value errorResult;
        napi_create_int32(env, static_cast<int>(ErrorCode::ERR_INVALID_COMMAND), &errorResult);
        napi_resolve_deferred(env, deferred, errorResult);
        return promise;
    }
    
    std::string host;
    uint32_t port = 8710;
    int32_t timeoutMs = 30000;
    
    GetStringArg(env, args[0], host);
    GetUint32Arg(env, args[1], port);
    if (argc > 2) {
        GetInt32Arg(env, args[2], timeoutMs);
    }
    
    OH_LOG_INFO(LOG_APP, "HdcConnect: %{public}s:%{public}u timeout=%{public}d", 
                host.c_str(), port, timeoutMs);
    
    // Create promise
    napi_value promise;
    napi_deferred deferred;
    napi_create_promise(env, &deferred, &promise);
    
    // Create async data
    ConnectAsyncData* asyncData = new ConnectAsyncData();
    asyncData->deferred = deferred;
    asyncData->host = host;
    asyncData->port = static_cast<uint16_t>(port);
    asyncData->timeoutMs = timeoutMs;
    
    // Create async work
    napi_value resourceName;
    napi_create_string_utf8(env, "HdcConnect", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(env, nullptr, resourceName, 
                           ConnectExecute, ConnectComplete, 
                           asyncData, &asyncData->work);
    
    // Queue the work
    napi_queue_async_work(env, asyncData->work);
    
    return promise;
}

/**
 * HdcDisconnect - Disconnect from device
 * @param connId (optional) - Connection ID
 * @returns int - 0 on success
 */
napi_value HdcDisconnect(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string connId;
    if (argc > 0) {
        GetStringArg(env, args[0], connId);
    }
    
    OH_LOG_INFO(LOG_APP, "HdcDisconnect: %{public}s", connId.c_str());
    int result = HdcClientWrapper::GetInstance().Disconnect(connId);
    return CreateInt32Result(env, result);
}

/**
 * HdcListTargets - List connected devices
 * @returns object - {count: number, data: string}
 */
napi_value HdcListTargets(napi_env env, napi_callback_info info) {
    OH_LOG_INFO(LOG_APP, "HdcListTargets called");
    
    auto devices = HdcClientWrapper::GetInstance().ListTargets();
    
    napi_value result;
    napi_create_object(env, &result);
    
    napi_value countValue;
    napi_create_int32(env, static_cast<int32_t>(devices.size()), &countValue);
    napi_set_named_property(env, result, "count", countValue);
    
    std::string data;
    for (const auto& device : devices) {
        if (!data.empty()) data += "\n";
        data += device.connectKey + "\t" + device.state;
    }
    
    napi_value dataValue;
    napi_create_string_utf8(env, data.c_str(), data.length(), &dataValue);
    napi_set_named_property(env, result, "data", dataValue);
    
    return result;
}

/**
 * HdcWaitForDevice - Wait for device to be available
 */
napi_value HdcWaitForDevice(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value args[3];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string host;
    uint32_t port = 8710;
    int32_t timeoutMs = 30000;
    
    if (argc > 0) GetStringArg(env, args[0], host);
    if (argc > 1) GetUint32Arg(env, args[1], port);
    if (argc > 2) GetInt32Arg(env, args[2], timeoutMs);
    
    int result = HdcClientWrapper::GetInstance().WaitForDevice(host, static_cast<uint16_t>(port), timeoutMs);
    return CreateInt32Result(env, result);
}

/**
 * HdcCheckDevice - Check if device is responsive
 */
napi_value HdcCheckDevice(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string connId;
    if (argc > 0) GetStringArg(env, args[0], connId);
    
    int result = HdcClientWrapper::GetInstance().CheckDevice(connId);
    
    napi_value retObj;
    napi_create_object(env, &retObj);
    
    napi_value responsive;
    napi_create_int32(env, result == 0 ? 1 : 0, &responsive);
    napi_set_named_property(env, retObj, "responsive", responsive);
    
    napi_value status;
    napi_create_string_utf8(env, result == 0 ? "device" : "offline", NAPI_AUTO_LENGTH, &status);
    napi_set_named_property(env, retObj, "status", status);
    
    return retObj;
}

/**
 * HdcDiscover - Discover devices on LAN
 */
napi_value HdcDiscover(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    int32_t timeoutMs = 5000;
    if (argc > 0) GetInt32Arg(env, args[0], timeoutMs);
    
    auto devices = HdcClientWrapper::GetInstance().Discover(timeoutMs);
    
    napi_value result;
    napi_create_array_with_length(env, devices.size(), &result);
    
    for (size_t i = 0; i < devices.size(); i++) {
        napi_value deviceObj;
        napi_create_object(env, &deviceObj);
        
        napi_value key;
        napi_create_string_utf8(env, devices[i].connectKey.c_str(), NAPI_AUTO_LENGTH, &key);
        napi_set_named_property(env, deviceObj, "connectKey", key);
        
        napi_set_element(env, result, i, deviceObj);
    }
    
    return result;
}

/**
 * HdcShell - Execute shell command
 */
napi_value HdcShell(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string command, connId;
    if (argc > 0) GetStringArg(env, args[0], command);
    if (argc > 1) GetStringArg(env, args[1], connId);
    
    OH_LOG_INFO(LOG_APP, "HdcShell: %{public}s", command.c_str());
    auto result = HdcClientWrapper::GetInstance().Shell(command, connId);
    return CreateCommandResult(env, result.code, result.output);
}

/**
 * HdcTargetBoot - Reboot device
 */
napi_value HdcTargetBoot(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string mode, connId;
    if (argc > 0) GetStringArg(env, args[0], mode);
    if (argc > 1) GetStringArg(env, args[1], connId);
    
    auto result = HdcClientWrapper::GetInstance().TargetBoot(mode, connId);
    return CreateCommandResult(env, result.code, result.output);
}

/**
 * HdcTargetMount - Mount device
 */
napi_value HdcTargetMount(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string connId;
    if (argc > 0) GetStringArg(env, args[0], connId);
    
    auto result = HdcClientWrapper::GetInstance().TargetMount(connId);
    return CreateCommandResult(env, result.code, result.output);
}

/**
 * HdcSmode - Set startup mode
 */
napi_value HdcSmode(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    bool enable = true;
    std::string connId;
    if (argc > 0) GetBoolArg(env, args[0], enable);
    if (argc > 1) GetStringArg(env, args[1], connId);
    
    auto result = HdcClientWrapper::GetInstance().Smode(enable, connId);
    return CreateCommandResult(env, result.code, result.output);
}

/**
 * HdcTmode - Set target mode
 */
napi_value HdcTmode(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string mode, connId;
    if (argc > 0) GetStringArg(env, args[0], mode);
    if (argc > 1) GetStringArg(env, args[1], connId);
    
    auto result = HdcClientWrapper::GetInstance().Tmode(mode, connId);
    return CreateCommandResult(env, result.code, result.output);
}

/**
 * HdcFileSend - Send file to device
 */
napi_value HdcFileSend(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value args[3];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string localPath, remotePath, connId;
    if (argc > 0) GetStringArg(env, args[0], localPath);
    if (argc > 1) GetStringArg(env, args[1], remotePath);
    if (argc > 2) GetStringArg(env, args[2], connId);
    
    OH_LOG_INFO(LOG_APP, "HdcFileSend: %{public}s -> %{public}s", localPath.c_str(), remotePath.c_str());
    int result = HdcClientWrapper::GetInstance().FileSend(localPath, remotePath, connId);
    return CreateInt32Result(env, result);
}

/**
 * HdcFileRecv - Receive file from device
 */
napi_value HdcFileRecv(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value args[3];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string remotePath, localPath, connId;
    if (argc > 0) GetStringArg(env, args[0], remotePath);
    if (argc > 1) GetStringArg(env, args[1], localPath);
    if (argc > 2) GetStringArg(env, args[2], connId);
    
    OH_LOG_INFO(LOG_APP, "HdcFileRecv: %{public}s -> %{public}s", remotePath.c_str(), localPath.c_str());
    int result = HdcClientWrapper::GetInstance().FileRecv(remotePath, localPath, connId);
    return CreateInt32Result(env, result);
}

/**
 * HdcInstall - Install application
 */
napi_value HdcInstall(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value args[3];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string hapPath, options, connId;
    if (argc > 0) GetStringArg(env, args[0], hapPath);
    if (argc > 1) GetStringArg(env, args[1], options);
    if (argc > 2) GetStringArg(env, args[2], connId);
    
    OH_LOG_INFO(LOG_APP, "HdcInstall: %{public}s", hapPath.c_str());
    auto result = HdcClientWrapper::GetInstance().Install(hapPath, options, connId);
    return CreateCommandResult(env, result.code, result.output);
}

/**
 * HdcUninstall - Uninstall application
 */
napi_value HdcUninstall(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value args[3];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string packageName, options, connId;
    if (argc > 0) GetStringArg(env, args[0], packageName);
    if (argc > 1) GetStringArg(env, args[1], options);
    if (argc > 2) GetStringArg(env, args[2], connId);
    
    OH_LOG_INFO(LOG_APP, "HdcUninstall: %{public}s", packageName.c_str());
    auto result = HdcClientWrapper::GetInstance().Uninstall(packageName, options, connId);
    return CreateCommandResult(env, result.code, result.output);
}

/**
 * HdcSideload - Sideload package
 */
napi_value HdcSideload(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string packagePath, connId;
    if (argc > 0) GetStringArg(env, args[0], packagePath);
    if (argc > 1) GetStringArg(env, args[1], connId);
    
    auto result = HdcClientWrapper::GetInstance().Sideload(packagePath, connId);
    return CreateCommandResult(env, result.code, result.output);
}

/**
 * HdcForward - Forward port
 */
napi_value HdcForward(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value args[3];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string localPort, remotePort, connId;
    if (argc > 0) GetStringArg(env, args[0], localPort);
    if (argc > 1) GetStringArg(env, args[1], remotePort);
    if (argc > 2) GetStringArg(env, args[2], connId);
    
    int result = HdcClientWrapper::GetInstance().Forward(localPort, remotePort, connId);
    return CreateInt32Result(env, result);
}

/**
 * HdcReverse - Reverse port forward
 */
napi_value HdcReverse(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value args[3];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string remotePort, localPort, connId;
    if (argc > 0) GetStringArg(env, args[0], remotePort);
    if (argc > 1) GetStringArg(env, args[1], localPort);
    if (argc > 2) GetStringArg(env, args[2], connId);
    
    int result = HdcClientWrapper::GetInstance().Reverse(remotePort, localPort, connId);
    return CreateInt32Result(env, result);
}

/**
 * HdcHilog - Get device hilog
 */
napi_value HdcHilog(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string hilogArgs, connId;
    if (argc > 0) GetStringArg(env, args[0], hilogArgs);
    if (argc > 1) GetStringArg(env, args[1], connId);
    
    auto result = HdcClientWrapper::GetInstance().Hilog(hilogArgs, connId);
    return CreateCommandResult(env, result.code, result.output);
}

/**
 * HdcBugreport - Generate bug report
 */
napi_value HdcBugreport(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string outputPath, connId;
    if (argc > 0) GetStringArg(env, args[0], outputPath);
    if (argc > 1) GetStringArg(env, args[1], connId);
    
    auto result = HdcClientWrapper::GetInstance().Bugreport(outputPath, connId);
    return CreateCommandResult(env, result.code, result.output);
}

/**
 * HdcJpid - List Java PIDs
 */
napi_value HdcJpid(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string connId;
    if (argc > 0) GetStringArg(env, args[0], connId);
    
    auto result = HdcClientWrapper::GetInstance().Jpid(connId);
    return CreateCommandResult(env, result.code, result.output);
}

/**
 * HdcKeygen - Generate key pair
 */
napi_value HdcKeygen(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    std::string keyPath;
    if (argc > 0) GetStringArg(env, args[0], keyPath);
    
    int result = HdcClientWrapper::GetInstance().Keygen(keyPath);
    return CreateInt32Result(env, result);
}

/**
 * HdcVersion - Get HDC version
 */
napi_value HdcVersion(napi_env env, napi_callback_info info) {
    std::string version = HdcClientWrapper::GetInstance().GetVersion();
    return CreateStringResult(env, version);
}

/**
 * HdcHelp - Get help message
 */
napi_value HdcHelp(napi_env env, napi_callback_info info) {
    std::string help = HdcClientWrapper::GetInstance().GetHelp();
    return CreateStringResult(env, help);
}

/**
 * HdcGetLastError - Get last error code
 */
napi_value HdcGetLastError(napi_env env, napi_callback_info info) {
    int errorCode = HdcClientWrapper::GetInstance().GetLastError();
    return CreateInt32Result(env, errorCode);
}

/**
 * HdcGetErrorMessage - Get error message for error code
 */
napi_value HdcGetErrorMessage(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    int32_t errorCode = 0;
    if (argc > 0) GetInt32Arg(env, args[0], errorCode);
    
    std::string message = HdcClientWrapper::GetInstance().GetErrorMessage(errorCode);
    return CreateStringResult(env, message);
}

/**
 * Module initialization - registers all NAPI methods
 */
napi_value Init(napi_env env, napi_value exports) {
    OH_LOG_INFO(LOG_APP, "HdcNapi module initializing...");
    
    napi_property_descriptor desc[] = {
        // Lifecycle management
        {"hdcInit", nullptr, HdcInit, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcCleanup", nullptr, HdcCleanup, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcIsInitialized", nullptr, HdcIsInitialized, nullptr, nullptr, nullptr, napi_default, nullptr},
        // Connection management
        {"hdcConnect", nullptr, HdcConnect, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcDisconnect", nullptr, HdcDisconnect, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcListTargets", nullptr, HdcListTargets, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcWaitForDevice", nullptr, HdcWaitForDevice, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcCheckDevice", nullptr, HdcCheckDevice, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcDiscover", nullptr, HdcDiscover, nullptr, nullptr, nullptr, napi_default, nullptr},
        // Command execution
        {"hdcShell", nullptr, HdcShell, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcTargetBoot", nullptr, HdcTargetBoot, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcTargetMount", nullptr, HdcTargetMount, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcSmode", nullptr, HdcSmode, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcTmode", nullptr, HdcTmode, nullptr, nullptr, nullptr, napi_default, nullptr},
        // File transfer
        {"hdcFileSend", nullptr, HdcFileSend, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcFileRecv", nullptr, HdcFileRecv, nullptr, nullptr, nullptr, napi_default, nullptr},
        // App management
        {"hdcInstall", nullptr, HdcInstall, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcUninstall", nullptr, HdcUninstall, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcSideload", nullptr, HdcSideload, nullptr, nullptr, nullptr, napi_default, nullptr},
        // Port forwarding
        {"hdcForward", nullptr, HdcForward, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcReverse", nullptr, HdcReverse, nullptr, nullptr, nullptr, napi_default, nullptr},
        // Logging and debug
        {"hdcHilog", nullptr, HdcHilog, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcBugreport", nullptr, HdcBugreport, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcJpid", nullptr, HdcJpid, nullptr, nullptr, nullptr, napi_default, nullptr},
        // Key management
        {"hdcKeygen", nullptr, HdcKeygen, nullptr, nullptr, nullptr, napi_default, nullptr},
        // Info and error
        {"hdcVersion", nullptr, HdcVersion, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcHelp", nullptr, HdcHelp, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcGetLastError", nullptr, HdcGetLastError, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"hdcGetErrorMessage", nullptr, HdcGetErrorMessage, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    
    OH_LOG_INFO(LOG_APP, "HdcNapi module initialized with %{public}zu methods", sizeof(desc) / sizeof(desc[0]));
    return exports;
}

// NAPI module registration
EXTERN_C_START
static napi_module hdcModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "hdc_napi",
    .nm_priv = nullptr,
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterHdcNapiModule(void) {
    napi_module_register(&hdcModule);
}
EXTERN_C_END
