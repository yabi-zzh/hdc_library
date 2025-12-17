/**
 * HDC Client Wrapper
 * 
 * Wraps the original HDC client functionality for NAPI usage.
 * Provides a simplified C++ interface for the NAPI layer.
 */
#ifndef HDC_CLIENT_WRAPPER_H
#define HDC_CLIENT_WRAPPER_H

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>
#include <uv.h>

namespace HdcWrapper {

// Error codes (consistent with HdcError.ets)
enum class ErrorCode : int {
    SUCCESS = 0,
    // Connection errors (-1001 ~ -1005)
    ERR_CONNECTION_FAILED = -1001,
    ERR_CONNECTION_TIMEOUT = -1002,
    ERR_CONNECTION_REFUSED = -1003,
    ERR_CONNECTION_CLOSED = -1004,
    ERR_HANDSHAKE_FAILED = -1005,
    // Protocol errors (-2001 ~ -2003)
    ERR_PROTOCOL_ERROR = -2001,
    ERR_INVALID_COMMAND = -2002,
    ERR_INVALID_RESPONSE = -2003,
    // File errors (-3001 ~ -3003)
    ERR_FILE_NOT_FOUND = -3001,
    ERR_PERMISSION_DENIED = -3002,
    ERR_FILE_TRANSFER_FAILED = -3003,
    // Device errors (-4001 ~ -4003)
    ERR_DEVICE_NOT_FOUND = -4001,
    ERR_DEVICE_OFFLINE = -4002,
    ERR_DEVICE_BUSY = -4003,
    // App errors (-5001 ~ -5003)
    ERR_INSTALL_FAILED = -5001,
    ERR_UNINSTALL_FAILED = -5002,
    ERR_APP_NOT_FOUND = -5003,
    // Port forward errors (-6001 ~ -6002)
    ERR_PORT_IN_USE = -6001,
    ERR_FORWARD_FAILED = -6002,
    // Auth errors (-7001 ~ -7006)
    ERR_AUTH_FAILED = -7001,
    ERR_AUTH_TIMEOUT = -7002,
    ERR_AUTH_REJECTED = -7003,
    ERR_KEY_NOT_FOUND = -7004,
    ERR_KEY_INVALID = -7005,
    ERR_KEY_GENERATION_FAILED = -7006,
    // Discovery errors (-9001 ~ -9002)
    ERR_DISCOVERY_FAILED = -9001,
    ERR_DISCOVERY_TIMEOUT = -9002,
    // Internal error
    ERR_NOT_INITIALIZED = -9998,
    ERR_INTERNAL = -9999,
};

// Command execution result
struct CommandResult {
    int code;
    std::string output;
};

// Device info
struct DeviceInfo {
    std::string connectKey;  // IP:Port format
    std::string state;       // device state
    std::string deviceName;  // device name
};

/**
 * HDC Client Wrapper - Singleton class
 * 
 * Manages the HDC client lifecycle and provides a simplified interface
 * for NAPI methods to call.
 */
class HdcClientWrapper {
public:
    static HdcClientWrapper& GetInstance();
    
    // Lifecycle management
    int Init(int logLevel = 3, const std::string& sandboxPath = "");
    void Cleanup();
    bool IsInitialized() const;
    
    // Connection management
    int Connect(const std::string& host, uint16_t port, int timeoutMs = 30000);
    int Disconnect(const std::string& connId = "");
    std::vector<DeviceInfo> ListTargets();
    int WaitForDevice(const std::string& host, uint16_t port, int timeoutMs = 30000);
    int CheckDevice(const std::string& connId);
    std::vector<DeviceInfo> Discover(int timeoutMs = 5000);
    
    // Command execution
    CommandResult ExecuteCommand(const std::string& command, const std::string& connId = "");
    CommandResult Shell(const std::string& command, const std::string& connId = "");
    CommandResult TargetBoot(const std::string& mode, const std::string& connId = "");
    CommandResult TargetMount(const std::string& connId = "");
    CommandResult Smode(bool enable, const std::string& connId = "");
    CommandResult Tmode(const std::string& mode, const std::string& connId = "");
    
    // File transfer
    int FileSend(const std::string& localPath, const std::string& remotePath, 
                 const std::string& connId = "");
    int FileRecv(const std::string& remotePath, const std::string& localPath,
                 const std::string& connId = "");
    
    // App management
    CommandResult Install(const std::string& hapPath, const std::string& options,
                         const std::string& connId = "");
    CommandResult Uninstall(const std::string& packageName, const std::string& options,
                           const std::string& connId = "");
    CommandResult Sideload(const std::string& packagePath, const std::string& connId = "");
    
    // Port forwarding
    int Forward(const std::string& localPort, const std::string& remotePort,
                const std::string& connId = "");
    int Reverse(const std::string& remotePort, const std::string& localPort,
                const std::string& connId = "");
    
    // Logging and debug
    CommandResult Hilog(const std::string& args, const std::string& connId = "");
    CommandResult Bugreport(const std::string& outputPath, const std::string& connId = "");
    CommandResult Jpid(const std::string& connId = "");
    
    // Key management
    int Keygen(const std::string& keyPath);
    
    // Info and error
    std::string GetVersion();
    std::string GetHelp();
    int GetLastError() const;
    std::string GetErrorMessage(int errorCode) const;
    
    // Current connection info
    std::string GetCurrentConnectKey() const;

private:
    HdcClientWrapper();
    ~HdcClientWrapper();
    
    // Prevent copying
    HdcClientWrapper(const HdcClientWrapper&) = delete;
    HdcClientWrapper& operator=(const HdcClientWrapper&) = delete;
    
    // Internal helpers
    void SetLastError(int errorCode);
    void RunEventLoop();
    void StopEventLoop();
    int ConnectInternal(const std::string& host, uint16_t port, int timeoutMs);
    
    // State
    std::atomic<bool> initialized_{false};
    std::atomic<int> lastError_{0};
    std::string currentConnectKey_;
    
    // libuv event loop
    uv_loop_t* loop_{nullptr};
    std::atomic<bool> loopRunning_{false};
    
    // Thread safety
    mutable std::mutex mutex_;
};

} // namespace HdcWrapper

#endif // HDC_CLIENT_WRAPPER_H
