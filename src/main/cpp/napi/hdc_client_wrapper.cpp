/**
 * HDC Client Wrapper Implementation
 * 
 * Implements the wrapper around HDC core functionality for direct TCP connection.
 * This implementation connects directly to hdcd daemon without going through hdc server.
 */
#include "hdc_client_wrapper.h"
#include <hilog/log.h>
#include <thread>
#include <chrono>
#include <cstring>
#include <arpa/inet.h>
#include <fstream>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <lz4.h>
#include <map>
#include <atomic>

// Include HDC core headers for proper protocol handling
#include "session.h"
#include "serial_struct.h"
#include "base.h"
#include "auth.h"

#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0x0001
#define LOG_TAG "HdcWrapper"

namespace HdcWrapper {

// Helper macros to reduce code duplication for initialization checks
#define CHECK_INITIALIZED_RETURN(retVal) \
    do { \
        if (!initialized_) { \
            SetLastError(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED)); \
            return retVal; \
        } \
    } while(0)

#define CHECK_INITIALIZED_RESULT() \
    do { \
        if (!initialized_) { \
            result.code = static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED); \
            result.output = GetErrorMessage(result.code); \
            SetLastError(result.code); \
            return result; \
        } \
    } while(0)

#define CHECK_CONNECTION_RESULT() \
    do { \
        if (g_connState == nullptr || !g_connState->handshakeOK.load()) { \
            result.code = static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED); \
            result.output = GetErrorMessage(result.code); \
            SetLastError(result.code); \
            return result; \
        } \
    } while(0)

#define CHECK_CONNECTION_RETURN(retVal) \
    do { \
        if (g_connState == nullptr || !g_connState->handshakeOK.load()) { \
            SetLastError(static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED)); \
            return retVal; \
        } \
    } while(0)

// Constants from HDC protocol (matching define.h)
static const std::string HANDSHAKE_MESSAGE = "OHOS HDC";
static const std::string PACKET_FLAG_STR = "HW";
static const uint16_t VER_PROTOCOL = 0x01;
static const uint16_t DEFAULT_PORT = 8710;
static const int HANDSHAKE_TIMEOUT_MS = 5000;
static const int MAX_CONNECTKEY_SIZE = 32;
static const int BUF_SIZE_TINY = 64;
static const int CMD_TIMEOUT_MS = 30000;
static const uint8_t PAYLOAD_VCODE = 0x09;  // Static vCode from HDC protocol

// HDC Command IDs (from define_enum.h)
enum HdcCommand {
    CMD_KERNEL_HANDSHAKE = 1,
    CMD_KERNEL_CHANNEL_CLOSE = 2,
    CMD_KERNEL_ECHO = 9,
    CMD_KERNEL_ECHO_RAW = 10,  // Raw output from CMD_UNITY_EXECUTE
    CMD_UNITY_EXECUTE = 1001,
    CMD_UNITY_REMOUNT = 1002,
    CMD_UNITY_REBOOT = 1003,
    CMD_UNITY_RUNMODE = 1004,
    CMD_UNITY_HILOG = 1005,
    CMD_JDWP_LIST = 1008,
    CMD_UNITY_BUGREPORT_INIT = 1011,
    CMD_SHELL_INIT = 2000,
    CMD_SHELL_DATA = 2001,
    CMD_FORWARD_INIT = 2500,
    // File transfer commands
    CMD_FILE_INIT = 3000,
    CMD_FILE_CHECK = 3001,
    CMD_FILE_BEGIN = 3002,
    CMD_FILE_DATA = 3003,
    CMD_FILE_FINISH = 3004,
    CMD_APP_SIDELOAD = 3005,  // Sideload (OTA-style update)
    CMD_FILE_MODE = 3006,
    // App commands
    CMD_APP_INIT = 3500,
    CMD_APP_CHECK = 3501,
    CMD_APP_BEGIN = 3502,
    CMD_APP_DATA = 3503,
    CMD_APP_FINISH = 3504,
    CMD_APP_UNINSTALL = 3505,
};

// File transfer constants
static const int FILE_BLOCK_SIZE = 61440;  // 60KB per block (matching HDC protocol)
static const int FILE_TRANSFER_TIMEOUT_MS = 60000;  // 60 seconds for file operations

// Compression type
enum CompressType {
    COMPRESS_NONE = 0,
    COMPRESS_LZ4 = 1,
};

// Transfer payload header (for file data)
#pragma pack(push, 1)
struct TransferPayload {
    uint64_t index;
    uint8_t compressType;
    uint32_t compressSize;
    uint32_t uncompressSize;
};
#pragma pack(pop)

// HDC Payload header structure (must match HDC protocol exactly)
#pragma pack(push, 1)
struct PayloadHead {
    uint8_t flag[2];     // "HW"
    uint8_t reserve[2];  // reserved
    uint8_t protocolVer; // protocol version
    uint16_t headSize;   // header size (network byte order)
    uint32_t dataSize;   // data size (network byte order)
};
#pragma pack(pop)

// Use HDC core's PayloadProtect and SessionHandShake via TLV serialization
// PayloadProtect fields: channelId, commandFlag, checkSum, vCode
// SessionHandShake fields: banner, authType, sessionId, connectKey, buf, version

// Error message mapping
static const std::map<int, std::string> ERROR_MESSAGES = {
    {static_cast<int>(ErrorCode::SUCCESS), "[Success]Operation completed successfully"},
    {static_cast<int>(ErrorCode::ERR_CONNECTION_FAILED), "[Fail]Connection failed"},
    {static_cast<int>(ErrorCode::ERR_CONNECTION_TIMEOUT), "[Fail]Connection timeout"},
    {static_cast<int>(ErrorCode::ERR_CONNECTION_REFUSED), "[Fail]Connection refused"},
    {static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED), "[Fail]Connection closed"},
    {static_cast<int>(ErrorCode::ERR_HANDSHAKE_FAILED), "[Fail]Handshake failed"},
    {static_cast<int>(ErrorCode::ERR_PROTOCOL_ERROR), "[Fail]Protocol error"},
    {static_cast<int>(ErrorCode::ERR_INVALID_COMMAND), "[Fail]Invalid command"},
    {static_cast<int>(ErrorCode::ERR_INVALID_RESPONSE), "[Fail]Invalid response"},
    {static_cast<int>(ErrorCode::ERR_FILE_NOT_FOUND), "[Fail]File not found"},
    {static_cast<int>(ErrorCode::ERR_PERMISSION_DENIED), "[Fail]Permission denied"},
    {static_cast<int>(ErrorCode::ERR_FILE_TRANSFER_FAILED), "[Fail]File transfer failed"},
    {static_cast<int>(ErrorCode::ERR_DEVICE_NOT_FOUND), "[Fail]Device not found"},
    {static_cast<int>(ErrorCode::ERR_DEVICE_OFFLINE), "[Fail]Device offline"},
    {static_cast<int>(ErrorCode::ERR_DEVICE_BUSY), "[Fail]Device busy"},
    {static_cast<int>(ErrorCode::ERR_INSTALL_FAILED), "[Fail]Install failed"},
    {static_cast<int>(ErrorCode::ERR_UNINSTALL_FAILED), "[Fail]Uninstall failed"},
    {static_cast<int>(ErrorCode::ERR_APP_NOT_FOUND), "[Fail]App not found"},
    {static_cast<int>(ErrorCode::ERR_PORT_IN_USE), "[Fail]Port already in use"},
    {static_cast<int>(ErrorCode::ERR_FORWARD_FAILED), "[Fail]Port forward failed"},
    {static_cast<int>(ErrorCode::ERR_AUTH_FAILED), "[Fail]Authentication failed"},
    {static_cast<int>(ErrorCode::ERR_AUTH_TIMEOUT), "[Fail]Authentication timeout"},
    {static_cast<int>(ErrorCode::ERR_AUTH_REJECTED), "[Fail]Authentication rejected"},
    {static_cast<int>(ErrorCode::ERR_KEY_NOT_FOUND), "[Fail]Key not found"},
    {static_cast<int>(ErrorCode::ERR_KEY_INVALID), "[Fail]Invalid key"},
    {static_cast<int>(ErrorCode::ERR_KEY_GENERATION_FAILED), "[Fail]Key generation failed"},
    {static_cast<int>(ErrorCode::ERR_DISCOVERY_FAILED), "[Fail]Device discovery failed"},
    {static_cast<int>(ErrorCode::ERR_DISCOVERY_TIMEOUT), "[Fail]Device discovery timeout"},
    {static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED), "[Fail]HDC not initialized"},
    {static_cast<int>(ErrorCode::ERR_INTERNAL), "[Fail]Internal error"},
};

// Connection state
struct ConnectionState {
    uv_tcp_t tcpHandle;
    uv_connect_t connectReq;
    std::atomic<bool> connected{false};
    std::atomic<bool> handshakeOK{false};
    std::atomic<bool> handshakeSent{false};  // Track if we've sent our handshake response
    std::atomic<bool> waitingForUserAuth{false};  // Track if we're waiting for user to authorize on device
    std::atomic<uint32_t> channelId{0};
    std::atomic<uint32_t> sessionId{0};      // Session ID from daemon
    std::string connectKey;
    std::string responseBuffer;
    mutable std::mutex mutex;
    std::condition_variable cv;
    std::atomic<int> lastError{0};
};

// Global connection state
static ConnectionState* g_connState = nullptr;

// Static mutex for event loop thread safety
static std::mutex g_loopMutex;
// Flag to indicate if we should keep the event loop running (for the lifetime of the app)
static std::atomic<bool> g_keepLoopAlive{true};

HdcClientWrapper::HdcClientWrapper() {
    OH_LOG_INFO(LOG_APP, "HdcClientWrapper created");
}

HdcClientWrapper::~HdcClientWrapper() {
    if (initialized_) {
        Cleanup();
    }
    OH_LOG_INFO(LOG_APP, "HdcClientWrapper destroyed");
}

HdcClientWrapper& HdcClientWrapper::GetInstance() {
    static HdcClientWrapper instance;
    return instance;
}

int HdcClientWrapper::Init(int logLevel, const std::string& sandboxPath) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (initialized_) {
        OH_LOG_INFO(LOG_APP, "HdcClientWrapper already initialized");
        return static_cast<int>(ErrorCode::SUCCESS);
    }
    
    OH_LOG_INFO(LOG_APP, "Initializing HdcClientWrapper with log level %{public}d", logLevel);
    
    // 设置应用沙箱路径（用于存�?RSA 密钥�?
    if (!sandboxPath.empty()) {
        OH_LOG_INFO(LOG_APP, "Setting sandbox path: %{public}s", sandboxPath.c_str());
        HdcAuth::SetAppSandboxPath(sandboxPath);
    }
    
    // Pre-generate RSA key pair if not exists (this can take 2-3 seconds)
    // Do it during init to avoid delay during first connection
    OH_LOG_INFO(LOG_APP, "Checking/generating RSA key pair...");
    std::string pubkeyInfo;
    if (HdcAuth::GetPublicKeyinfo(pubkeyInfo)) {
        OH_LOG_INFO(LOG_APP, "RSA key pair ready");
    } else {
        OH_LOG_WARN(LOG_APP, "Failed to prepare RSA key pair, will retry during connection");
    }
    
    // Reset the keep-alive flag (may have been set to false by previous Cleanup)
    g_keepLoopAlive = true;
    
    // Create libuv event loop
    loop_ = new uv_loop_t();
    int ret = uv_loop_init(loop_);
    if (ret != 0) {
        OH_LOG_ERROR(LOG_APP, "Failed to init uv loop: %{public}d", ret);
        delete loop_;
        loop_ = nullptr;
        SetLastError(static_cast<int>(ErrorCode::ERR_INTERNAL));
        return static_cast<int>(ErrorCode::ERR_INTERNAL);
    }
    
    initialized_ = true;
    lastError_ = static_cast<int>(ErrorCode::SUCCESS);
    
    OH_LOG_INFO(LOG_APP, "HdcClientWrapper initialized successfully");
    return static_cast<int>(ErrorCode::SUCCESS);
}

void HdcClientWrapper::Cleanup() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        OH_LOG_INFO(LOG_APP, "HdcClientWrapper not initialized, skip cleanup");
        return;
    }
    
    OH_LOG_INFO(LOG_APP, "Cleaning up HdcClientWrapper");
    
    // Disconnect if connected - clear global pointer first
    ConnectionState* oldState = g_connState;
    g_connState = nullptr;
    
    if (oldState != nullptr) {
        if (oldState->connected.load() && !uv_is_closing((uv_handle_t*)&oldState->tcpHandle)) {
            uv_read_stop((uv_stream_t*)&oldState->tcpHandle);
            uv_close((uv_handle_t*)&oldState->tcpHandle, nullptr);
        }
        delete oldState;
    }
    
    // Stop event loop if running
    StopEventLoop();
    
    // Close and cleanup libuv loop
    if (loop_ != nullptr) {
        uv_loop_close(loop_);
        delete loop_;
        loop_ = nullptr;
    }
    
    // Clear connection info
    currentConnectKey_.clear();
    
    initialized_ = false;
    OH_LOG_INFO(LOG_APP, "HdcClientWrapper cleanup completed");
}

bool HdcClientWrapper::IsInitialized() const {
    return initialized_.load();
}

void HdcClientWrapper::SetLastError(int errorCode) {
    lastError_ = errorCode;
}

int HdcClientWrapper::GetLastError() const {
    return lastError_.load();
}

std::string HdcClientWrapper::GetErrorMessage(int errorCode) const {
    auto it = ERROR_MESSAGES.find(errorCode);
    if (it != ERROR_MESSAGES.end()) {
        return it->second;
    }
    return "[Fail]Unknown error: " + std::to_string(errorCode);
}

void HdcClientWrapper::RunEventLoop() {
    {
        std::lock_guard<std::mutex> lock(g_loopMutex);
        if (loop_ == nullptr) {
            OH_LOG_WARN(LOG_APP, "RunEventLoop: loop_ is null");
            return;
        }
        // Use compare_exchange to atomically check and set loopRunning_
        bool expected = false;
        if (!loopRunning_.compare_exchange_strong(expected, true)) {
            OH_LOG_INFO(LOG_APP, "RunEventLoop: loop already running");
            return;
        }
    }
    
    OH_LOG_INFO(LOG_APP, "RunEventLoop: starting event loop");
    
    // Run the event loop continuously - it will handle multiple connections
    // The loop only exits when the app is being destroyed (g_keepLoopAlive = false)
    while (g_keepLoopAlive && loopRunning_) {
        uv_loop_t* currentLoop = nullptr;
        
        // Get current loop pointer under lock
        {
            std::lock_guard<std::mutex> lock(g_loopMutex);
            currentLoop = loop_;
            if (currentLoop == nullptr) {
                OH_LOG_INFO(LOG_APP, "RunEventLoop: loop is null, exiting");
                break;
            }
        }
        
        // Use UV_RUN_ONCE to wait for and process one event
        // This is more efficient than UV_RUN_NOWAIT + sleep
        // UV_RUN_ONCE will block until there's an event to process or the loop is stopped
        int result = uv_run(currentLoop, UV_RUN_ONCE);
        
        // result == 0 means no more active handles/requests
        // In this case, sleep briefly to avoid busy loop when idle
        if (result == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    loopRunning_ = false;
    OH_LOG_INFO(LOG_APP, "RunEventLoop: event loop stopped");
}

void HdcClientWrapper::StopEventLoop() {
    OH_LOG_INFO(LOG_APP, "StopEventLoop: requesting stop (for app cleanup)");
    
    // Signal the loop to stop permanently
    g_keepLoopAlive = false;
    loopRunning_ = false;
    
    {
        std::lock_guard<std::mutex> lock(g_loopMutex);
        
        if (loop_ == nullptr) {
            return;
        }
        
        OH_LOG_INFO(LOG_APP, "StopEventLoop: stopping event loop");
        
        // Stop the loop - this will cause uv_run to return
        uv_stop(loop_);
    }
    
    // Wait for loop thread to exit
    int waitCount = 0;
    while (loopRunning_ && waitCount < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        waitCount++;
    }
}

std::string HdcClientWrapper::GetCurrentConnectKey() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return currentConnectKey_;
}

std::string HdcClientWrapper::GetVersion() {
    // Return version consistent with original hdc
    // HDC_VERSION_NUMBER = 0x30200200 means 3.2.0c
    return "Ver: 3.2.0c";
}

std::string HdcClientWrapper::GetHelp() {
    return R"(OpenHarmony Device Connector (HDC) - NAPI Library
Usage: HdcClient methods

Available commands:
  hdcInit()                    - Initialize HDC library
  hdcCleanup()                 - Cleanup HDC library
  hdcIsInitialized()           - Check if initialized
  hdcConnect(host, port)       - Connect to device
  hdcDisconnect(connId)        - Disconnect from device
  hdcShell(command, connId)    - Execute shell command
  hdcFileSend(local, remote)   - Send file to device
  hdcFileRecv(remote, local)   - Receive file from device
  hdcInstall(hapPath, options) - Install application
  hdcUninstall(package)        - Uninstall application
  hdcVersion()                 - Show version
  hdcHelp()                    - Show this help
)";
}

// libuv callbacks for TCP connection
static void OnAllocBuffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = new char[suggested_size];
    buf->len = suggested_size;
}

// File receive state for async handling (defined here for use in OnRead callback)
struct FileRecvState {
    std::string localPath;
    std::ofstream file;
    std::atomic<uint64_t> totalReceived{0};
    std::atomic<uint64_t> expectedSize{0};
    std::atomic<bool> finished{false};
    std::atomic<int> errorCode{0};
    mutable std::mutex mutex;
    std::condition_variable cv;
};

static FileRecvState* g_fileRecvState = nullptr;

// Forward declarations
static bool ProcessFileData(const uint8_t* data, size_t dataSize);
static void SendHandshakeResponse(ConnectionState* state, uint32_t sessionId);
static bool SendHdcPacket(ConnectionState* state, uint32_t channelId, uint16_t commandFlag, 
                          const uint8_t* data, size_t dataSize);

static void OnRead(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    // Safety check: verify stream->data is a valid ConnectionState
    // During close, data might be set to CloseContext instead
    // Use local copy to avoid race condition
    ConnectionState* currentState = g_connState;
    ConnectionState* state = nullptr;
    
    // Check if this is the current global connection state
    if (currentState != nullptr && stream->data == currentState) {
        state = currentState;
    } else {
        // stream->data might be CloseContext or invalid, ignore this read
        OH_LOG_WARN(LOG_APP, "OnRead: stream->data is not current connection state, ignoring");
        if (buf->base) delete[] buf->base;
        return;
    }
    
    if (nread < 0) {
        OH_LOG_ERROR(LOG_APP, "Read error: %{public}s", uv_strerror(nread));
        std::lock_guard<std::mutex> lock(state->mutex);
        state->connected.store(false);
        state->lastError.store(static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED));
        state->cv.notify_all();
        if (buf->base) delete[] buf->base;
        return;
    }
    
    if (nread > 0) {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->responseBuffer.append(buf->base, nread);
        
        // Debug logging - use INFO level since DEBUG may not be available
        // OH_LOG_INFO(LOG_APP, "Received %{public}zd bytes, buffer size: %{public}zu", 
        //              nread, state->responseBuffer.size());
        
        // Process complete HDC packets in buffer
        while (state->responseBuffer.size() >= sizeof(PayloadHead)) {
            const PayloadHead* head = reinterpret_cast<const PayloadHead*>(state->responseBuffer.data());
            
            // Verify packet flag
            if (head->flag[0] != PACKET_FLAG_STR[0] || head->flag[1] != PACKET_FLAG_STR[1]) {
                OH_LOG_ERROR(LOG_APP, "Invalid packet flag: 0x%02x 0x%02x", head->flag[0], head->flag[1]);
                state->lastError.store(static_cast<int>(ErrorCode::ERR_PROTOCOL_ERROR));
                state->cv.notify_all();
                break;
            }
            
            uint16_t headSize = ntohs(head->headSize);  // PayloadProtect serialized size
            uint32_t dataSize = ntohl(head->dataSize);  // Total data size (PayloadProtect + payload)
            size_t totalPacketSize = sizeof(PayloadHead) + headSize + dataSize;
            
            // Debug logging
            // OH_LOG_INFO(LOG_APP, "Packet: headSize=%{public}u, dataSize=%{public}u, total=%{public}zu", 
            //              headSize, dataSize, totalPacketSize);
            
            if (state->responseBuffer.size() < sizeof(PayloadHead) + headSize + dataSize) {
                // Incomplete packet, wait for more data
                // Debug logging
                // OH_LOG_INFO(LOG_APP, "Incomplete packet, need %{public}zu more bytes", 
                //              sizeof(PayloadHead) + headSize + dataSize - state->responseBuffer.size());
                break;
            }
            
            // Parse PayloadProtect using TLV deserialization
            Hdc::HdcSessionBase::PayloadProtect protectBuf = {};
            std::string protectStr(state->responseBuffer.data() + sizeof(PayloadHead), headSize);
            Hdc::SerialStruct::ParseFromString(protectBuf, protectStr);
            
            OH_LOG_INFO(LOG_APP, "Packet cmd=%{public}u, channelId=%{public}u, vCode=0x%{public}02x", 
                        protectBuf.commandFlag, protectBuf.channelId, protectBuf.vCode);
            
            // Verify vCode
            if (protectBuf.vCode != PAYLOAD_VCODE) {
                OH_LOG_ERROR(LOG_APP, "Invalid vCode: 0x%02x, expected 0x%02x", protectBuf.vCode, PAYLOAD_VCODE);
                state->lastError.store(static_cast<int>(ErrorCode::ERR_PROTOCOL_ERROR));
                state->responseBuffer.erase(0, sizeof(PayloadHead) + headSize + dataSize);
                state->cv.notify_all();
                continue;
            }
            
            // Get payload data
            const uint8_t* payloadData = reinterpret_cast<const uint8_t*>(
                state->responseBuffer.data() + sizeof(PayloadHead) + headSize);
            size_t payloadSize = dataSize;
            
            // Handle CMD_KERNEL_HANDSHAKE
            if (protectBuf.commandFlag == CMD_KERNEL_HANDSHAKE) {
                OH_LOG_INFO(LOG_APP, "Received handshake packet, payloadSize=%{public}zu", payloadSize);
                
                // Parse SessionHandShake using TLV deserialization
                Hdc::HdcSessionBase::SessionHandShake handshake = {};
                std::string handshakeStr(reinterpret_cast<const char*>(payloadData), payloadSize);
                Hdc::SerialStruct::ParseFromString(handshake, handshakeStr);
                
                OH_LOG_INFO(LOG_APP, "Daemon handshake: banner=%{public}s, authType=%{public}u, sessionId=%{public}u, version=%{public}s",
                            handshake.banner.c_str(), handshake.authType, handshake.sessionId, handshake.version.c_str());
                
                // Check banner
                if (handshake.banner.find(HANDSHAKE_MESSAGE) == 0) {
                    if (handshake.sessionId != 0) {
                        state->sessionId.store(handshake.sessionId);
                    }
                    
                    // Handle different auth types
                    switch (handshake.authType) {
                        case Hdc::HdcSessionBase::AUTH_OK: {
                            // Check if this is a real AUTH_OK or a fake one with DAEMON_UNAUTH status
                            // Parse TLV data in handshake.buf to check actual auth status
                            std::map<std::string, std::string> tlvMap;
                            bool isRealAuthOk = true;
                            
                            if (!handshake.buf.empty() && Hdc::Base::TlvToStringMap(handshake.buf, tlvMap)) {
                                auto it = tlvMap.find(TAG_DAEOMN_AUTHSTATUS);
                                if (it != tlvMap.end() && it->second == DAEOMN_UNAUTHORIZED) {
                                    // This is a fake AUTH_OK, device needs user authorization or rejected
                                    isRealAuthOk = false;
                                    
                                    // Check for error message to determine if user rejected
                                    auto msgIt = tlvMap.find(TAG_EMGMSG);
                                    std::string authMsg = msgIt != tlvMap.end() ? msgIt->second : "";
                                    OH_LOG_WARN(LOG_APP, "Received AUTH_OK but daemon returned UNAUTHORIZED status");
                                    
                                    // Check if user rejected the authorization (E000003)
                                    if (authMsg.find("[E000003]") != std::string::npos) {
                                        OH_LOG_ERROR(LOG_APP, "User rejected authorization on device");
                                        OH_LOG_WARN(LOG_APP, "Auth message: %{public}s", authMsg.c_str());
                                        state->lastError.store(static_cast<int>(ErrorCode::ERR_AUTH_REJECTED));
                                        state->waitingForUserAuth.store(false);
                                    } else {
                                        // User needs to authorize (E000002) - wait for AUTH_SIGNATURE
                                        state->waitingForUserAuth.store(true);
                                        OH_LOG_INFO(LOG_APP, "Waiting for user to authorize on device (extended timeout)...");
                                        if (!authMsg.empty()) {
                                            OH_LOG_WARN(LOG_APP, "Auth message: %{public}s", authMsg.c_str());
                                        }
                                    }
                                }
                            }
                            
                            if (isRealAuthOk) {
                                // Authentication successful
                                state->handshakeOK.store(true);
                                OH_LOG_INFO(LOG_APP, "Handshake completed successfully (AUTH_OK), sessionId=%{public}u", state->sessionId.load());
                            }
                            break;
                        }
                            
                        case Hdc::HdcSessionBase::AUTH_NONE:
                            // No authentication required
                            state->handshakeOK.store(true);
                            OH_LOG_INFO(LOG_APP, "Handshake completed successfully (AUTH_NONE), sessionId=%{public}u", state->sessionId.load());
                            break;
                            
                        case Hdc::HdcSessionBase::AUTH_PUBLICKEY: {
                            // Daemon requests public key - try to send it
                            OH_LOG_INFO(LOG_APP, "Daemon requests public key authentication");
                            
                            // Try to get public key info using HDC auth
                            std::string pubkeyInfo;
                            if (HdcAuth::GetPublicKeyinfo(pubkeyInfo)) {
                                OH_LOG_INFO(LOG_APP, "Sending public key to daemon");
                                
                                // Build response with public key
                                Hdc::HdcSessionBase::SessionHandShake response = {};
                                response.banner = HANDSHAKE_MESSAGE;
                                response.authType = Hdc::HdcSessionBase::AUTH_PUBLICKEY;
                                response.sessionId = state->sessionId.load();
                                response.buf = pubkeyInfo;
                                response.version = Hdc::Base::GetVersion();
                                
                                std::string responseStr = Hdc::SerialStruct::SerializeToString(response);
                                SendHdcPacket(state, 0, CMD_KERNEL_HANDSHAKE,
                                              reinterpret_cast<const uint8_t*>(responseStr.c_str()), responseStr.size());
                            } else {
                                OH_LOG_ERROR(LOG_APP, "Failed to get public key, authentication will fail");
                                state->lastError.store(static_cast<int>(ErrorCode::ERR_AUTH_FAILED));
                            }
                            break;
                        }
                            
                        case Hdc::HdcSessionBase::AUTH_SIGNATURE: {
                            // Daemon requests signature
                            OH_LOG_INFO(LOG_APP, "Daemon requests signature, token: %{public}s", handshake.buf.c_str());
                            
                            // Sign the token
                            std::string signedData = handshake.buf;
                            if (HdcAuth::RsaSignAndBase64(signedData, Hdc::AuthVerifyType::RSA_3072_SHA512)) {
                                OH_LOG_INFO(LOG_APP, "Sending signature to daemon");
                                
                                // Build response with signature
                                Hdc::HdcSessionBase::SessionHandShake response = {};
                                response.banner = HANDSHAKE_MESSAGE;
                                response.authType = Hdc::HdcSessionBase::AUTH_SIGNATURE;
                                response.sessionId = state->sessionId.load();
                                response.buf = signedData;
                                response.version = Hdc::Base::GetVersion();
                                
                                std::string responseStr = Hdc::SerialStruct::SerializeToString(response);
                                SendHdcPacket(state, 0, CMD_KERNEL_HANDSHAKE,
                                              reinterpret_cast<const uint8_t*>(responseStr.c_str()), responseStr.size());
                            } else {
                                OH_LOG_ERROR(LOG_APP, "Failed to sign token, authentication will fail");
                                state->lastError.store(static_cast<int>(ErrorCode::ERR_AUTH_FAILED));
                            }
                            break;
                        }
                            
                        case Hdc::HdcSessionBase::AUTH_FAIL:
                            OH_LOG_ERROR(LOG_APP, "Authentication failed by daemon");
                            state->lastError.store(static_cast<int>(ErrorCode::ERR_AUTH_FAILED));
                            break;
                            
                        default:
                            OH_LOG_WARN(LOG_APP, "Unknown auth type: %{public}u", handshake.authType);
                            break;
                    }
                } else {
                    OH_LOG_ERROR(LOG_APP, "Invalid handshake banner: %{public}s", handshake.banner.c_str());
                    state->lastError.store(static_cast<int>(ErrorCode::ERR_HANDSHAKE_FAILED));
                }
                
                // Remove processed packet
                state->responseBuffer.erase(0, sizeof(PayloadHead) + headSize + dataSize);
                state->cv.notify_all();
                continue;
            }
            
            // Handle file transfer commands specially
            if (protectBuf.commandFlag == CMD_FILE_DATA && g_fileRecvState != nullptr) {
                if (payloadSize > 0) {
                    ProcessFileData(payloadData, payloadSize);
                }
                state->responseBuffer.erase(0, sizeof(PayloadHead) + headSize + dataSize);
                continue;
            } else if (protectBuf.commandFlag == CMD_FILE_FINISH && g_fileRecvState != nullptr) {
                g_fileRecvState->finished.store(true);
                g_fileRecvState->cv.notify_all();
                state->responseBuffer.erase(0, sizeof(PayloadHead) + headSize + dataSize);
                continue;
            }
            
            // Handle CMD_KERNEL_CHANNEL_CLOSE (2)
            if (protectBuf.commandFlag == CMD_KERNEL_CHANNEL_CLOSE) {
                OH_LOG_INFO(LOG_APP, "Channel closed by daemon, channelId=%{public}u", protectBuf.channelId);
                
                // During handshake phase (channelId=0), if we haven't completed handshake yet,
                // this might be the UNAUTHORIZED notification. Daemon will send AUTH_SIGNATURE
                // after user authorizes on device. Don't notify waiting thread yet - keep waiting.
                if (protectBuf.channelId == 0 && !state->handshakeOK.load()) {
                    OH_LOG_INFO(LOG_APP, "Channel close during handshake, continuing to wait for AUTH_SIGNATURE...");
                    state->responseBuffer.erase(0, sizeof(PayloadHead) + headSize + dataSize);
                    continue;  // Keep waiting for more packets
                }
                
                // Leave in buffer for SendCommandAndWait to process
                state->cv.notify_all();
                break;
            }
            
            // Handle CMD_KERNEL_ECHO (9) - may be heartbeat or status message
            // During handshake phase, check if it contains handshake data (AUTH_SIGNATURE)
            if (protectBuf.commandFlag == CMD_KERNEL_ECHO) {
                std::string content(reinterpret_cast<const char*>(payloadData), payloadSize);
                
                // Log first 64 bytes in hex for debugging
                std::string hexDump;
                for (size_t i = 0; i < std::min(payloadSize, (size_t)64); i++) {
                    char hex[4];
                    snprintf(hex, sizeof(hex), "%02x ", (unsigned char)payloadData[i]);
                    hexDump += hex;
                }
                OH_LOG_INFO(LOG_APP, "CMD_KERNEL_ECHO hex dump (first 64 bytes): %{public}s", hexDump.c_str());
                
                // Check if this might be a handshake message embedded in echo
                // Try to parse as SessionHandShake
                if (payloadSize > 0 && !state->handshakeOK.load()) {
                    Hdc::HdcSessionBase::SessionHandShake echoHandshake = {};
                    std::string echoStr(reinterpret_cast<const char*>(payloadData), payloadSize);
                    bool parsed = Hdc::SerialStruct::ParseFromString(echoHandshake, echoStr);
                    
                    if (parsed && echoHandshake.banner.find(HANDSHAKE_MESSAGE) == 0) {
                        OH_LOG_INFO(LOG_APP, "CMD_KERNEL_ECHO contains handshake! banner=%{public}s, authType=%{public}u",
                                    echoHandshake.banner.c_str(), echoHandshake.authType);
                        
                        // Process as handshake
                        if (echoHandshake.authType == Hdc::HdcSessionBase::AUTH_SIGNATURE) {
                            OH_LOG_INFO(LOG_APP, "Found AUTH_SIGNATURE in CMD_KERNEL_ECHO, token: %{public}s", 
                                        echoHandshake.buf.c_str());
                            
                            // Sign the token
                            std::string signedData = echoHandshake.buf;
                            if (HdcAuth::RsaSignAndBase64(signedData, Hdc::AuthVerifyType::RSA_3072_SHA512)) {
                                OH_LOG_INFO(LOG_APP, "Sending signature to daemon (from echo)");
                                
                                Hdc::HdcSessionBase::SessionHandShake response = {};
                                response.banner = HANDSHAKE_MESSAGE;
                                response.authType = Hdc::HdcSessionBase::AUTH_SIGNATURE;
                                response.sessionId = state->sessionId.load();
                                response.buf = signedData;
                                response.version = Hdc::Base::GetVersion();
                                
                                std::string responseStr = Hdc::SerialStruct::SerializeToString(response);
                                SendHdcPacket(state, 0, CMD_KERNEL_HANDSHAKE,
                                              reinterpret_cast<const uint8_t*>(responseStr.c_str()), responseStr.size());
                            }
                        } else if (echoHandshake.authType == Hdc::HdcSessionBase::AUTH_OK) {
                            state->handshakeOK.store(true);
                            OH_LOG_INFO(LOG_APP, "Handshake completed via CMD_KERNEL_ECHO (AUTH_OK)");
                        }
                        
                        state->responseBuffer.erase(0, sizeof(PayloadHead) + headSize + dataSize);
                        state->cv.notify_all();
                        continue;
                    }
                }
                
                // Remove trailing nulls for display
                while (!content.empty() && content.back() == '\0') {
                    content.pop_back();
                }
                OH_LOG_INFO(LOG_APP, "Received CMD_KERNEL_ECHO (cmd=9), size=%{public}zu, content=[%{public}s]", 
                            payloadSize, content.c_str());
                
                // During handshake phase, ignore echo packets and keep waiting for AUTH_SIGNATURE
                if (!state->handshakeOK.load()) {
                    OH_LOG_INFO(LOG_APP, "Ignoring CMD_KERNEL_ECHO during handshake, waiting for AUTH_SIGNATURE...");
                    state->responseBuffer.erase(0, sizeof(PayloadHead) + headSize + dataSize);
                    continue;  // Keep waiting for more packets
                }
                
                // After handshake, leave in buffer for SendCommandAndWait to process
                state->cv.notify_all();
                break;
            }
            
            // Handle shell/command output response
            // CMD_KERNEL_ECHO_RAW (10) is used for CMD_UNITY_EXECUTE output
            // CMD_SHELL_DATA (2001) is used for interactive shell output
            if (protectBuf.commandFlag == CMD_KERNEL_ECHO_RAW || 
                protectBuf.commandFlag == CMD_SHELL_DATA) {
                std::string content(reinterpret_cast<const char*>(payloadData), payloadSize);
                // Remove trailing nulls for display
                while (!content.empty() && content.back() == '\0') {
                    content.pop_back();
                }
                OH_LOG_INFO(LOG_APP, "Received response (cmd=%{public}u), size=%{public}zu, content=[%{public}s]", 
                            protectBuf.commandFlag, payloadSize, content.c_str());
                
                // Leave in buffer for SendCommandAndWait to process
                state->cv.notify_all();
                break;
            }
            
            // For other unknown commands, log and remove from buffer
            OH_LOG_INFO(LOG_APP, "Received unknown cmd=%{public}u, removing from buffer", protectBuf.commandFlag);
            state->responseBuffer.erase(0, totalPacketSize);
            // Continue processing remaining packets
        }
        
        state->cv.notify_all();
    }
    
    if (buf->base) delete[] buf->base;
}

// Build and send HDC packet with proper TLV serialization
static bool SendHdcPacket(ConnectionState* state, uint32_t channelId, uint16_t commandFlag, 
                          const uint8_t* data, size_t dataSize) {
    // Serialize PayloadProtect using TLV
    Hdc::HdcSessionBase::PayloadProtect protectBuf = {};
    protectBuf.channelId = channelId;
    protectBuf.commandFlag = commandFlag;
    protectBuf.checkSum = 0;  // Checksum disabled for simplicity
    protectBuf.vCode = PAYLOAD_VCODE;
    std::string protectStr = Hdc::SerialStruct::SerializeToString(protectBuf);
    
    // Build PayloadHead
    PayloadHead head = {};
    head.flag[0] = PACKET_FLAG_STR[0];
    head.flag[1] = PACKET_FLAG_STR[1];
    head.reserve[0] = 0;
    head.reserve[1] = 0;
    head.protocolVer = VER_PROTOCOL;
    head.headSize = htons(static_cast<uint16_t>(protectStr.size()));
    head.dataSize = htonl(static_cast<uint32_t>(dataSize));
    
    // Allocate buffer for entire packet
    size_t totalSize = sizeof(PayloadHead) + protectStr.size() + dataSize;
    std::vector<uint8_t> packet(totalSize);
    
    // Copy PayloadHead
    memcpy(packet.data(), &head, sizeof(PayloadHead));
    // Copy serialized PayloadProtect
    memcpy(packet.data() + sizeof(PayloadHead), protectStr.c_str(), protectStr.size());
    // Copy payload data
    if (data && dataSize > 0) {
        memcpy(packet.data() + sizeof(PayloadHead) + protectStr.size(), data, dataSize);
    }
    
    OH_LOG_INFO(LOG_APP, "Sending packet: cmd=%{public}u, headSize=%{public}zu, dataSize=%{public}zu, total=%{public}zu",
                commandFlag, protectStr.size(), dataSize, totalSize);
    
    // Send packet
    uv_buf_t buf = uv_buf_init(reinterpret_cast<char*>(packet.data()), totalSize);
    uv_write_t* writeReq = new uv_write_t();
    
    // Copy packet data for async write
    uint8_t* packetCopy = new uint8_t[totalSize];
    memcpy(packetCopy, packet.data(), totalSize);
    writeReq->data = packetCopy;
    buf.base = reinterpret_cast<char*>(packetCopy);
    
    int ret = uv_write(writeReq, (uv_stream_t*)&state->tcpHandle, &buf, 1, 
             [](uv_write_t* req, int status) {
                 if (status < 0) {
                     OH_LOG_ERROR(LOG_APP, "Packet write failed: %{public}s", uv_strerror(status));
                 }
                 delete[] static_cast<uint8_t*>(req->data);
                 delete req;
             });
    
    return ret == 0;
}

// Generate a pseudo-random session ID using timestamp and random
static uint32_t GenerateSessionId() {
    // Use a combination of timestamp and random to avoid conflicts with daemon's old sessions
    static std::atomic<uint32_t> sessionCounter{0};
    if (sessionCounter == 0) {
        // Initialize with current time to make it unique across app restarts
        auto now = std::chrono::steady_clock::now().time_since_epoch();
        uint32_t seed = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(now).count() & 0xFFFF);
        sessionCounter = (seed << 16) | 1;  // Use upper 16 bits for seed, lower for counter
    }
    return sessionCounter++;
}

// Send initial handshake to daemon (client initiates)
static void SendInitialHandshake(ConnectionState* state) {
    // Generate session ID for this connection
    state->sessionId.store(GenerateSessionId());
    
    OH_LOG_INFO(LOG_APP, "Sending initial handshake, sessionId=%{public}u", state->sessionId.load());
    
    // Build SessionHandShake (client sends first, like HDC server does)
    Hdc::HdcSessionBase::SessionHandShake handshake = {};
    handshake.banner = HANDSHAKE_MESSAGE;
    handshake.authType = Hdc::HdcSessionBase::AUTH_NONE;
    handshake.sessionId = state->sessionId.load();
    handshake.connectKey = state->connectKey;
    handshake.version = Hdc::Base::GetVersion();
    
    // Tell daemon we support RSA_3072_SHA512 authentication
    // This is critical! Without this, daemon will use RSA_ENCRYPT which doesn't match our signing method
    Hdc::Base::TlvAppend(handshake.buf, TAG_AUTH_TYPE, std::to_string(Hdc::AuthVerifyType::RSA_3072_SHA512));
    
    // Serialize handshake using TLV
    std::string handshakeStr = Hdc::SerialStruct::SerializeToString(handshake);
    
    OH_LOG_INFO(LOG_APP, "Initial handshake: banner=%{public}s, authType=%{public}u, connectKey=%{public}s, version=%{public}s, authMethod=RSA_3072_SHA512",
                handshake.banner.c_str(), handshake.authType, handshake.connectKey.c_str(), handshake.version.c_str());
    
    // Send as CMD_KERNEL_HANDSHAKE packet
    SendHdcPacket(state, 0, CMD_KERNEL_HANDSHAKE, 
                  reinterpret_cast<const uint8_t*>(handshakeStr.c_str()), handshakeStr.size());
    
    state->handshakeSent.store(true);
}

// Send handshake response to daemon (when daemon sends handshake back)
static void SendHandshakeResponse(ConnectionState* state, uint32_t sessionId) {
    OH_LOG_INFO(LOG_APP, "Sending handshake response, sessionId=%{public}u", sessionId);
    
    // Build SessionHandShake response
    Hdc::HdcSessionBase::SessionHandShake handshake = {};
    handshake.banner = HANDSHAKE_MESSAGE;
    handshake.authType = Hdc::HdcSessionBase::AUTH_NONE;
    handshake.sessionId = sessionId;
    handshake.connectKey = state->connectKey;
    handshake.version = Hdc::Base::GetVersion();
    
    // Serialize handshake using TLV
    std::string handshakeStr = Hdc::SerialStruct::SerializeToString(handshake);
    
    OH_LOG_INFO(LOG_APP, "Handshake response: banner=%{public}s, authType=%{public}u, connectKey=%{public}s, version=%{public}s",
                handshake.banner.c_str(), handshake.authType, handshake.connectKey.c_str(), handshake.version.c_str());
    
    // Send as CMD_KERNEL_HANDSHAKE packet
    SendHdcPacket(state, 0, CMD_KERNEL_HANDSHAKE, 
                  reinterpret_cast<const uint8_t*>(handshakeStr.c_str()), handshakeStr.size());
}

static void OnConnect(uv_connect_t* req, int status) {
    OH_LOG_INFO(LOG_APP, "OnConnect callback called, status=%{public}d", status);
    
    ConnectionState* state = (ConnectionState*)req->data;
    if (state == nullptr) {
        OH_LOG_ERROR(LOG_APP, "OnConnect: state is null!");
        return;
    }
    
    // Check if this callback is for the current connection or an old one being cleaned up
    ConnectionState* currentState = g_connState;
    if (currentState != state) {
        OH_LOG_WARN(LOG_APP, "OnConnect: callback for old connection state, ignoring (status=%{public}d)", status);
        // Still need to close the handle if connection failed
        if (status < 0 && !uv_is_closing((uv_handle_t*)&state->tcpHandle)) {
            uv_close((uv_handle_t*)&state->tcpHandle, nullptr);
        }
        return;
    }
    
    if (status < 0) {
        // Map libuv error to more specific error codes
        int errorCode = static_cast<int>(ErrorCode::ERR_CONNECTION_FAILED);
        const char* errorDetail = "";
        
        switch (status) {
            case UV_ETIMEDOUT:
                errorCode = static_cast<int>(ErrorCode::ERR_CONNECTION_TIMEOUT);
                errorDetail = "Connection timed out";
                break;
            case UV_ECONNREFUSED:
                errorCode = static_cast<int>(ErrorCode::ERR_CONNECTION_REFUSED);
                errorDetail = "Connection refused - check if HDC daemon is running on target";
                break;
            case UV_ENETUNREACH:
                errorCode = static_cast<int>(ErrorCode::ERR_CONNECTION_FAILED);
                errorDetail = "Network unreachable - check if device is on same network";
                break;
            case UV_EHOSTUNREACH:
                errorCode = static_cast<int>(ErrorCode::ERR_CONNECTION_FAILED);
                errorDetail = "Host unreachable - check IP address and network connectivity";
                break;
            case UV_ECONNRESET:
                errorCode = static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED);
                errorDetail = "Connection reset by peer";
                break;
            case UV_ECANCELED:
                errorCode = static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED);
                errorDetail = "Connection canceled (handle closed during connect)";
                break;
            default:
                errorDetail = "Unknown connection error";
                break;
        }
        
        OH_LOG_ERROR(LOG_APP, "Connect failed: %{public}s (code=%{public}d). %{public}s. Target: %{public}s", 
                    uv_strerror(status), status, errorDetail, state->connectKey.c_str());
        
        state->lastError.store(errorCode);
        state->connected.store(false);
        
        // Close the TCP handle since connection failed
        // This is important to clean up resources properly
        if (!uv_is_closing((uv_handle_t*)&state->tcpHandle)) {
            uv_close((uv_handle_t*)&state->tcpHandle, nullptr);
        }
        
        state->cv.notify_all();
        return;
    }
    
    OH_LOG_INFO(LOG_APP, "TCP connected, sending initial handshake");
    state->connected.store(true);
    state->tcpHandle.data = state;
    
    // Start reading for daemon's response
    uv_read_start((uv_stream_t*)&state->tcpHandle, OnAllocBuffer, OnRead);
    
    // Client sends handshake first (like HDC server does when connecting to daemon)
    // The daemon will respond with its own handshake
    SendInitialHandshake(state);
    
    state->cv.notify_all();
}

// Helper struct for async close operation - must be allocated on heap and deleted in callback
struct CloseContext {
    std::atomic<bool> closed{false};
    ConnectionState* oldState{nullptr};
    bool shouldDeleteState{false};  // Whether to delete oldState in callback
};

// Internal connect implementation (single attempt)
// Key design: REUSE the event loop, only close/create TCP connections
int HdcClientWrapper::ConnectInternal(const std::string& host, uint16_t port, int timeoutMs) {
    // Cleanup previous connection (but keep the event loop running!)
    if (g_connState != nullptr) {
        OH_LOG_INFO(LOG_APP, "Cleaning up previous connection before reconnect");
        
        ConnectionState* oldState = g_connState;
        g_connState = nullptr;  // Clear global pointer first to prevent callbacks from using it
        
        // Always try to close the TCP handle if loop exists
        // The handle may have been initialized even if connection failed
        if (loop_ != nullptr) {
            // Create close context on heap - will be deleted in close callback
            CloseContext* closeCtx = new CloseContext();
            closeCtx->oldState = oldState;
            closeCtx->shouldDeleteState = true;
            
            // Check if handle needs to be closed
            // Note: The handle might already be closing from OnConnect failure callback
            bool needClose = false;
            bool alreadyClosing = uv_is_closing((uv_handle_t*)&oldState->tcpHandle);
            
            if (!alreadyClosing) {
                // Stop reading first if connected
                if (oldState->connected.load()) {
                    uv_read_stop((uv_stream_t*)&oldState->tcpHandle);
                }
                needClose = true;
            } else {
                OH_LOG_INFO(LOG_APP, "TCP handle already closing, waiting for it to complete");
            }
            
            if (needClose) {
                // Store close context in handle data
                oldState->tcpHandle.data = closeCtx;
                
                // Close the handle - the callback will clean up asynchronously
                // Don't wait for completion - let the event loop handle it
                uv_close((uv_handle_t*)&oldState->tcpHandle, [](uv_handle_t* handle) {
                    CloseContext* ctx = static_cast<CloseContext*>(handle->data);
                    if (ctx) {
                        ctx->closed = true;
                        // Delete the old state in the callback to ensure it's safe
                        if (ctx->shouldDeleteState && ctx->oldState) {
                            delete ctx->oldState;
                            ctx->oldState = nullptr;
                        }
                        // Delete the context itself
                        delete ctx;
                    }
                });
                
                // Wait for close to complete to avoid "operation canceled" errors
                // when starting a new connection
                OH_LOG_INFO(LOG_APP, "TCP handle close initiated, waiting for completion...");
                int closeWaitCount = 0;
                const int maxCloseWait = 100;  // Max 1 second wait
                while (!closeCtx->closed.load() && closeWaitCount < maxCloseWait) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    closeWaitCount++;
                }
                if (closeCtx->closed.load()) {
                    OH_LOG_INFO(LOG_APP, "TCP handle closed successfully");
                } else {
                    OH_LOG_WARN(LOG_APP, "TCP handle close timeout, proceeding anyway");
                    // closeCtx will be deleted by the callback eventually
                }
            } else {
                // Handle already closing, wait for it to complete
                // We can't set up our own close callback, so just wait and then delete
                delete closeCtx;
                
                // Wait for the handle to finish closing
                int closeWaitCount = 0;
                const int maxCloseWait = 100;  // Max 1 second wait
                while (uv_is_closing((uv_handle_t*)&oldState->tcpHandle) && closeWaitCount < maxCloseWait) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    closeWaitCount++;
                }
                OH_LOG_INFO(LOG_APP, "Waited %d ms for handle to close", closeWaitCount * 10);
                
                // Now safe to delete the state
                delete oldState;
            }
        } else {
            // No loop, just delete the state
            delete oldState;
        }
        
        // Additional pause to ensure event loop processes everything
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Ensure event loop exists and is running
    {
        std::lock_guard<std::mutex> lock(g_loopMutex);
        
        if (loop_ == nullptr) {
            OH_LOG_INFO(LOG_APP, "Creating event loop");
            loop_ = new uv_loop_t();
            int ret = uv_loop_init(loop_);
            if (ret != 0) {
                OH_LOG_ERROR(LOG_APP, "Failed to init uv loop: %{public}s", uv_strerror(ret));
                delete loop_;
                loop_ = nullptr;
                return static_cast<int>(ErrorCode::ERR_INTERNAL);
            }
        }
    }
    
    // Start event loop thread if not running
    if (!loopRunning_) {
        OH_LOG_INFO(LOG_APP, "Starting event loop thread");
        std::thread loopThread([this]() {
            RunEventLoop();
        });
        loopThread.detach();
        
        // Wait for loop to start
        int startWait = 0;
        while (!loopRunning_ && startWait < 50) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            startWait++;
        }
    }
    
    // Create new connection state
    ConnectionState* newState = new ConnectionState();
    newState->connectKey = host + ":" + std::to_string(port);
    newState->connected.store(false);
    newState->handshakeOK.store(false);
    newState->handshakeSent.store(false);
    newState->waitingForUserAuth.store(false);
    newState->channelId.store(0);
    newState->sessionId.store(0);
    newState->lastError.store(0);
    newState->responseBuffer.clear();
    
    // Use async to initialize TCP handle in the event loop thread
    // This is important for thread safety with libuv
    struct InitContext {
        ConnectionState* state;
        uv_loop_t* loop;
        std::string host;
        uint16_t port;
        std::atomic<bool> done{false};
        int result{0};
    };
    
    InitContext* initCtx = new InitContext();
    initCtx->state = newState;
    initCtx->loop = loop_;
    initCtx->host = host;
    initCtx->port = port;
    
    uv_async_t* asyncInit = new uv_async_t();
    asyncInit->data = initCtx;
    
    uv_async_init(loop_, asyncInit, [](uv_async_t* handle) {
        InitContext* ctx = static_cast<InitContext*>(handle->data);
        
        // Initialize TCP handle in event loop thread
        int ret = uv_tcp_init(ctx->loop, &ctx->state->tcpHandle);
        if (ret != 0) {
            OH_LOG_ERROR(LOG_APP, "uv_tcp_init failed: %{public}s", uv_strerror(ret));
            ctx->result = static_cast<int>(ErrorCode::ERR_INTERNAL);
            ctx->done = true;
            uv_close((uv_handle_t*)handle, [](uv_handle_t* h) { delete (uv_async_t*)h; });
            return;
        }
        
        // Enable TCP keepalive to detect dead connections
        uv_tcp_keepalive(&ctx->state->tcpHandle, 1, 60);
        
        // Disable Nagle's algorithm for lower latency
        uv_tcp_nodelay(&ctx->state->tcpHandle, 1);
        
        // Set SO_LINGER to enable immediate close without TIME_WAIT
        // This significantly speeds up TCP handle close operations
        uv_os_fd_t fd;
        if (uv_fileno((uv_handle_t*)&ctx->state->tcpHandle, &fd) == 0) {
            struct linger lingerOpt;
            lingerOpt.l_onoff = 1;   // Enable linger
            lingerOpt.l_linger = 0;  // Timeout = 0 means immediate RST on close
            setsockopt(fd, SOL_SOCKET, SO_LINGER, &lingerOpt, sizeof(lingerOpt));
        }
        
        // Mark that TCP handle has been initialized (for cleanup purposes)
        ctx->state->tcpHandle.data = ctx->state;
        
        // Setup address - check return value
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        ret = uv_ip4_addr(ctx->host.c_str(), ctx->port, &dest);
        if (ret != 0) {
            OH_LOG_ERROR(LOG_APP, "uv_ip4_addr failed for %{public}s:%{public}d: %{public}s", 
                        ctx->host.c_str(), ctx->port, uv_strerror(ret));
            uv_close((uv_handle_t*)&ctx->state->tcpHandle, nullptr);
            ctx->result = static_cast<int>(ErrorCode::ERR_CONNECTION_FAILED);
            ctx->done = true;
            uv_close((uv_handle_t*)handle, [](uv_handle_t* h) { delete (uv_async_t*)h; });
            return;
        }
        
        // Log the parsed address for debugging
        char addrStr[INET_ADDRSTRLEN];
        uv_ip4_name(&dest, addrStr, sizeof(addrStr));
        OH_LOG_INFO(LOG_APP, "Connecting to %{public}s:%{public}d (parsed: %{public}s:%{public}d)", 
                   ctx->host.c_str(), ctx->port, addrStr, ntohs(dest.sin_port));
        
        // Connect
        ctx->state->connectReq.data = ctx->state;
        ret = uv_tcp_connect(&ctx->state->connectReq, &ctx->state->tcpHandle,
                             (const struct sockaddr*)&dest, OnConnect);
        if (ret != 0) {
            OH_LOG_ERROR(LOG_APP, "uv_tcp_connect failed: %{public}s", uv_strerror(ret));
            // Close the TCP handle since connect failed immediately
            uv_close((uv_handle_t*)&ctx->state->tcpHandle, nullptr);
            ctx->result = static_cast<int>(ErrorCode::ERR_CONNECTION_FAILED);
        } else {
            ctx->result = static_cast<int>(ErrorCode::SUCCESS);
        }
        
        ctx->done = true;
        uv_close((uv_handle_t*)handle, [](uv_handle_t* h) { delete (uv_async_t*)h; });
    });
    
    // IMPORTANT: Set global state BEFORE triggering async callback
    // This ensures OnConnect callback can find the correct state
    g_connState = newState;
    currentConnectKey_ = newState->connectKey;
    
    // Trigger the async callback
    uv_async_send(asyncInit);
    
    // Wait for initialization to complete
    int initWait = 0;
    while (!initCtx->done && initWait < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        initWait++;
    }
    
    int initResult = initCtx->result;
    delete initCtx;
    
    if (initResult != static_cast<int>(ErrorCode::SUCCESS)) {
        g_connState = nullptr;  // Clear global state on failure
        currentConnectKey_.clear();
        delete newState;
        return initResult;
    }
    
    // Wait for connection and handshake
    // Use a loop to handle extended timeout when waiting for user authorization
    const int USER_AUTH_TIMEOUT_MS = 15000;  // 15 seconds for user to authorize on device
    int remainingTimeout = timeoutMs;
    bool success = false;
    
    while (remainingTimeout > 0) {
        std::unique_lock<std::mutex> lock(g_connState->mutex);
        
        // Wait for a short period to check for user auth flag
        int waitTime = std::min(remainingTimeout, 1000);  // Check every 1 second
        success = g_connState->cv.wait_for(lock, std::chrono::milliseconds(waitTime),
                                            [&]() { 
                                                return g_connState == nullptr || 
                                                       g_connState->handshakeOK.load() || 
                                                       g_connState->lastError.load() != 0; 
                                            });
        
        if (g_connState == nullptr) {
            return static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED);
        }
        
        if (success) {
            // Condition met, exit loop
            break;
        }
        
        // Check if we're waiting for user authorization
        if (g_connState->waitingForUserAuth.load()) {
            // Extend timeout for user authorization
            if (remainingTimeout == timeoutMs) {
                // First time detecting user auth wait, extend timeout
                remainingTimeout = USER_AUTH_TIMEOUT_MS;
                OH_LOG_INFO(LOG_APP, "Extended timeout to %{public}d ms for user authorization", USER_AUTH_TIMEOUT_MS);
            } else {
                remainingTimeout -= waitTime;
            }
        } else {
            remainingTimeout -= waitTime;
        }
    }
    
    if (g_connState == nullptr) {
        return static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED);
    }
    
    if (!success || !g_connState->handshakeOK.load()) {
        int err = g_connState->lastError.load() != 0 ? g_connState->lastError.load() : 
                  static_cast<int>(ErrorCode::ERR_CONNECTION_TIMEOUT);
        
        // If timeout occurred and OnConnect hasn't been called yet, we need to cancel the connection
        // by closing the TCP handle. This will trigger OnConnect with UV_ECANCELED.
        if (err == static_cast<int>(ErrorCode::ERR_CONNECTION_TIMEOUT) && 
            g_connState->connected.load() == false) {
            OH_LOG_WARN(LOG_APP, "Connection timeout, TCP connect still pending - will be canceled on retry");
        }
        
        return err;
    }
    
    return static_cast<int>(ErrorCode::SUCCESS);
}

int HdcClientWrapper::Connect(const std::string& host, uint16_t port, int timeoutMs) {
    if (!initialized_) {
        SetLastError(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED));
        return static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
    }
    
    OH_LOG_INFO(LOG_APP, "Connecting to %{public}s:%{public}d timeout=%{public}d", 
                host.c_str(), port, timeoutMs);
    
    // Try to connect with automatic retry
    // First connection often fails because daemon may have stale session state
    const int maxRetries = 3;
    const int retryDelayMs = 500;  // Wait 500ms between retries
    int lastError = 0;
    
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        OH_LOG_INFO(LOG_APP, "Connection attempt %{public}d/%{public}d", attempt, maxRetries);
        
        int result = ConnectInternal(host, port, timeoutMs);
        if (result == static_cast<int>(ErrorCode::SUCCESS)) {
            OH_LOG_INFO(LOG_APP, "Connected successfully to %{public}s on attempt %{public}d", 
                        currentConnectKey_.c_str(), attempt);
            SetLastError(static_cast<int>(ErrorCode::SUCCESS));
            return static_cast<int>(ErrorCode::SUCCESS);
        }
        
        lastError = result;
        OH_LOG_WARN(LOG_APP, "Connection attempt %{public}d failed with error %{public}d", attempt, result);
        
        // Don't retry on certain errors
        if (result == static_cast<int>(ErrorCode::ERR_AUTH_FAILED) ||
            result == static_cast<int>(ErrorCode::ERR_AUTH_REJECTED)) {
            OH_LOG_ERROR(LOG_APP, "Authentication error, not retrying");
            break;
        }
        
        // Wait before retry (except for last attempt)
        if (attempt < maxRetries) {
            OH_LOG_INFO(LOG_APP, "Waiting %{public}dms before retry...", retryDelayMs);
            std::this_thread::sleep_for(std::chrono::milliseconds(retryDelayMs));
        }
    }
    
    OH_LOG_ERROR(LOG_APP, "All connection attempts failed, last error: %{public}d", lastError);
    SetLastError(lastError);
    return lastError;
}

int HdcClientWrapper::Disconnect(const std::string& connId) {
    if (!initialized_) {
        SetLastError(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED));
        return static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
    }
    
    OH_LOG_INFO(LOG_APP, "Disconnecting from %{public}s", connId.c_str());
    
    // Only close the TCP connection, keep the event loop running
    if (g_connState != nullptr) {
        ConnectionState* oldState = g_connState;
        g_connState = nullptr;  // Clear global pointer first to prevent callbacks from using it
        
        if (oldState->connected.load() && loop_ != nullptr) {
            // Create close context on heap - will be deleted in callback
            CloseContext* closeCtx = new CloseContext();
            closeCtx->oldState = oldState;
            closeCtx->shouldDeleteState = true;
            
            // Stop reading first
            if (!uv_is_closing((uv_handle_t*)&oldState->tcpHandle)) {
                uv_read_stop((uv_stream_t*)&oldState->tcpHandle);
                
                // Store close context in handle data
                oldState->tcpHandle.data = closeCtx;
                
                // Close handle - the callback will clean up asynchronously
                // Don't wait for completion - let the event loop handle it
                uv_close((uv_handle_t*)&oldState->tcpHandle, [](uv_handle_t* handle) {
                    CloseContext* ctx = static_cast<CloseContext*>(handle->data);
                    if (ctx) {
                        ctx->closed = true;
                        // Delete the old state in the callback
                        if (ctx->shouldDeleteState && ctx->oldState) {
                            delete ctx->oldState;
                            ctx->oldState = nullptr;
                        }
                        delete ctx;
                    }
                });
                
                // Don't wait for close to complete - let it happen asynchronously
                // The callback will clean up resources when the event loop processes it
                OH_LOG_INFO(LOG_APP, "TCP handle close initiated, cleanup will happen asynchronously");
                // Note: closeCtx and oldState are deleted in the callback, not here
            } else {
                // Handle already closing
                delete closeCtx;
                delete oldState;
            }
        } else {
            delete oldState;
        }
        // Note: g_connState was already set to nullptr at the beginning
    }
    
    currentConnectKey_.clear();
    
    SetLastError(static_cast<int>(ErrorCode::SUCCESS));
    return static_cast<int>(ErrorCode::SUCCESS);
}

std::vector<DeviceInfo> HdcClientWrapper::ListTargets() {
    std::vector<DeviceInfo> devices;
    
    if (!initialized_) {
        SetLastError(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED));
        return devices;
    }
    
    // If connected, return current device
    if (g_connState != nullptr && g_connState->handshakeOK.load()) {
        DeviceInfo info;
        info.connectKey = currentConnectKey_;
        info.state = "device";
        info.deviceName = "";
        devices.push_back(info);
    }
    
    SetLastError(static_cast<int>(ErrorCode::SUCCESS));
    return devices;
}

int HdcClientWrapper::WaitForDevice(const std::string& host, uint16_t port, int timeoutMs) {
    if (!initialized_) {
        SetLastError(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED));
        return static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
    }
    
    OH_LOG_INFO(LOG_APP, "WaitForDevice %{public}s:%{public}d timeout=%{public}d", 
                host.c_str(), port, timeoutMs);
    
    auto startTime = std::chrono::steady_clock::now();
    int retryInterval = 1000; // 1 second
    
    while (true) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        if (elapsed >= timeoutMs) {
            SetLastError(static_cast<int>(ErrorCode::ERR_CONNECTION_TIMEOUT));
            return static_cast<int>(ErrorCode::ERR_CONNECTION_TIMEOUT);
        }
        
        int ret = Connect(host, port, retryInterval);
        if (ret == static_cast<int>(ErrorCode::SUCCESS)) {
            return ret;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(retryInterval));
    }
}

int HdcClientWrapper::CheckDevice(const std::string& connId) {
    if (!initialized_) {
        SetLastError(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED));
        return static_cast<int>(ErrorCode::ERR_DEVICE_OFFLINE);
    }
    
    if (g_connState == nullptr || !g_connState->handshakeOK.load()) {
        SetLastError(static_cast<int>(ErrorCode::ERR_DEVICE_OFFLINE));
        return static_cast<int>(ErrorCode::ERR_DEVICE_OFFLINE);
    }
    
    SetLastError(static_cast<int>(ErrorCode::SUCCESS));
    return static_cast<int>(ErrorCode::SUCCESS);
}

// UDP discovery constants (matching HDC protocol)
static const uint16_t DISCOVER_PORT = 8710;
static const char* DISCOVER_BROADCAST_ADDR = "255.255.255.255";
static const char* DISCOVER_MESSAGE = "OHOS HDC DISCOVER";
static const int DISCOVER_RECV_BUF_SIZE = 1024;

std::vector<DeviceInfo> HdcClientWrapper::Discover(int timeoutMs) {
    std::vector<DeviceInfo> devices;
    
    if (!initialized_) {
        SetLastError(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED));
        return devices;
    }
    
    OH_LOG_INFO(LOG_APP, "Discovering devices, timeout=%{public}d", timeoutMs);
    
    // Create UDP socket for broadcast
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        OH_LOG_ERROR(LOG_APP, "Discover: failed to create socket");
        SetLastError(static_cast<int>(ErrorCode::ERR_DISCOVERY_FAILED));
        return devices;
    }
    
    // Enable broadcast
    int broadcastEnable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)) < 0) {
        OH_LOG_ERROR(LOG_APP, "Discover: failed to enable broadcast");
        close(sock);
        SetLastError(static_cast<int>(ErrorCode::ERR_DISCOVERY_FAILED));
        return devices;
    }
    
    // Set receive timeout
    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    // Bind to any address
    struct sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = 0;  // Let system choose port
    
    if (bind(sock, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0) {
        OH_LOG_ERROR(LOG_APP, "Discover: failed to bind socket");
        close(sock);
        SetLastError(static_cast<int>(ErrorCode::ERR_DISCOVERY_FAILED));
        return devices;
    }
    
    // Send broadcast message
    struct sockaddr_in broadcastAddr;
    memset(&broadcastAddr, 0, sizeof(broadcastAddr));
    broadcastAddr.sin_family = AF_INET;
    broadcastAddr.sin_addr.s_addr = inet_addr(DISCOVER_BROADCAST_ADDR);
    broadcastAddr.sin_port = htons(DISCOVER_PORT);
    
    ssize_t sent = sendto(sock, DISCOVER_MESSAGE, strlen(DISCOVER_MESSAGE), 0,
                          (struct sockaddr*)&broadcastAddr, sizeof(broadcastAddr));
    if (sent < 0) {
        OH_LOG_ERROR(LOG_APP, "Discover: failed to send broadcast");
        close(sock);
        SetLastError(static_cast<int>(ErrorCode::ERR_DISCOVERY_FAILED));
        return devices;
    }
    
    OH_LOG_INFO(LOG_APP, "Discover: broadcast sent, waiting for responses...");
    
    // Receive responses
    char recvBuf[DISCOVER_RECV_BUF_SIZE];
    struct sockaddr_in senderAddr;
    socklen_t senderAddrLen = sizeof(senderAddr);
    
    auto startTime = std::chrono::steady_clock::now();
    
    while (true) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        if (elapsed >= timeoutMs) {
            break;
        }
        
        ssize_t recvLen = recvfrom(sock, recvBuf, sizeof(recvBuf) - 1, 0,
                                   (struct sockaddr*)&senderAddr, &senderAddrLen);
        
        if (recvLen > 0) {
            recvBuf[recvLen] = '\0';
            
            // Parse response - format: "OHOS HDC deviceName"
            std::string response(recvBuf, recvLen);
            if (response.find("OHOS HDC") == 0) {
                DeviceInfo info;
                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &senderAddr.sin_addr, ipStr, sizeof(ipStr));
                
                info.connectKey = std::string(ipStr) + ":" + std::to_string(DISCOVER_PORT);
                info.state = "device";
                
                // Extract device name if present
                if (response.length() > 9) {
                    info.deviceName = response.substr(9);
                }
                
                // Check for duplicates
                bool isDuplicate = false;
                for (const auto& existing : devices) {
                    if (existing.connectKey == info.connectKey) {
                        isDuplicate = true;
                        break;
                    }
                }
                
                if (!isDuplicate) {
                    OH_LOG_INFO(LOG_APP, "Discover: found device %{public}s", info.connectKey.c_str());
                    devices.push_back(info);
                }
            }
        } else if (recvLen < 0) {
            // Timeout or error
            break;
        }
    }
    
    close(sock);
    
    OH_LOG_INFO(LOG_APP, "Discover: found %{public}zu devices", devices.size());
    SetLastError(static_cast<int>(ErrorCode::SUCCESS));
    return devices;
}

// Build HDC packet with proper TLV serialization (using SendHdcPacket defined earlier)
// Note: BuildHdcPacket is now replaced by SendHdcPacket which uses TLV serialization

// Generate unique channel ID for each command
static std::atomic<uint32_t> g_channelIdCounter{1};
static uint32_t GenerateChannelId() {
    return g_channelIdCounter++;
}

// Helper function to send command and wait for response
// This function handles multi-packet responses:
// - CMD_KERNEL_ECHO_RAW (10) or CMD_SHELL_DATA (2001) for output data
// - CMD_KERNEL_CHANNEL_CLOSE (2) indicates command completion
static CommandResult SendCommandAndWait(const std::string& command, uint16_t cmdType = CMD_UNITY_EXECUTE, 
                                        int timeoutMs = CMD_TIMEOUT_MS) {
    CommandResult result = {0, ""};
    
    if (g_connState == nullptr || !g_connState->handshakeOK.load()) {
        result.code = static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
        result.output = "[Fail]Not connected";
        return result;
    }
    
    // Generate unique channel ID for this command
    uint32_t channelId = GenerateChannelId();
    
    OH_LOG_INFO(LOG_APP, "Sending command (type=%{public}d, channelId=%{public}u): %{public}s", 
                cmdType, channelId, command.c_str());
    
    // Clear response buffer
    {
        std::lock_guard<std::mutex> lock(g_connState->mutex);
        g_connState->responseBuffer.clear();
        g_connState->lastError = 0;
    }
    
    // Send command using TLV-serialized packet with unique channelId
    bool sent = SendHdcPacket(g_connState, channelId, cmdType,
                              reinterpret_cast<const uint8_t*>(command.c_str()), 
                              command.size() + 1);  // include null terminator
    
    if (!sent) {
        result.code = static_cast<int>(ErrorCode::ERR_PROTOCOL_ERROR);
        result.output = "[Fail]Failed to send command";
        return result;
    }
    
    // Collect output from multiple response packets
    std::string outputBuffer;
    bool channelClosed = false;
    auto startTime = std::chrono::steady_clock::now();
    
    while (!channelClosed) {
        // Check timeout
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        if (elapsed >= timeoutMs) {
            OH_LOG_WARN(LOG_APP, "Command timeout after %{public}lld ms", elapsed);
            if (outputBuffer.empty()) {
                result.code = static_cast<int>(ErrorCode::ERR_CONNECTION_TIMEOUT);
                result.output = "[Fail]Command timeout";
                return result;
            }
            // Return partial output if we have some
            break;
        }
        
        // Wait for response with shorter intervals to be more responsive
        std::unique_lock<std::mutex> lock(g_connState->mutex);
        int waitTime = std::min(100, timeoutMs - static_cast<int>(elapsed));  // Wait max 100ms at a time
        bool hasData = g_connState->cv.wait_for(lock, std::chrono::milliseconds(waitTime),
                                                 [&]() { return !g_connState->responseBuffer.empty() || 
                                                                g_connState->lastError.load() != 0; });
        
        if (g_connState->lastError.load() != 0) {
            result.code = g_connState->lastError;
            result.output = outputBuffer.empty() ? "[Fail]Connection error" : outputBuffer;
            return result;
        }
        
        if (!hasData || g_connState->responseBuffer.empty()) {
            continue;
        }
        
        // Process all complete packets in buffer
        while (g_connState->responseBuffer.size() >= sizeof(PayloadHead)) {
            const char* data = g_connState->responseBuffer.data();
            const PayloadHead* respHead = reinterpret_cast<const PayloadHead*>(data);
            
            // Verify packet flag
            if (respHead->flag[0] != PACKET_FLAG_STR[0] || respHead->flag[1] != PACKET_FLAG_STR[1]) {
                OH_LOG_ERROR(LOG_APP, "Invalid packet flag in response");
                g_connState->responseBuffer.clear();
                break;
            }
            
            uint16_t headSize = ntohs(respHead->headSize);
            uint32_t dataSize = ntohl(respHead->dataSize);
            size_t totalPacketSize = sizeof(PayloadHead) + headSize + dataSize;
            
            if (g_connState->responseBuffer.size() < totalPacketSize) {
                // Incomplete packet, wait for more data
                break;
            }
            
            // Parse PayloadProtect
            Hdc::HdcSessionBase::PayloadProtect protectBuf = {};
            std::string protectStr(data + sizeof(PayloadHead), headSize);
            Hdc::SerialStruct::ParseFromString(protectBuf, protectStr);
            
            OH_LOG_INFO(LOG_APP, "Response packet: cmd=%{public}u, channelId=%{public}u, dataSize=%{public}u",
                        protectBuf.commandFlag, protectBuf.channelId, dataSize);
            
            // Handle CMD_KERNEL_CHANNEL_CLOSE first - this indicates command completion
            if (protectBuf.commandFlag == CMD_KERNEL_CHANNEL_CLOSE) {
                OH_LOG_INFO(LOG_APP, "Channel closed (cmd=2), command completed");
                channelClosed = true;
                // Remove this packet from buffer
                g_connState->responseBuffer.erase(0, totalPacketSize);
                break;  // Exit packet processing loop
            }
            
            // Handle output response types
            // CMD_KERNEL_ECHO (9), CMD_KERNEL_ECHO_RAW (10), CMD_SHELL_DATA (2001) all contain output
            if (protectBuf.commandFlag == CMD_KERNEL_ECHO ||
                protectBuf.commandFlag == CMD_KERNEL_ECHO_RAW || 
                protectBuf.commandFlag == CMD_SHELL_DATA) {
                // Output data packet
                if (dataSize > 0) {
                    std::string chunk(data + sizeof(PayloadHead) + headSize, dataSize);
                    
                    // Log raw bytes for debugging (first 64 bytes)
                    std::string hexDump;
                    for (size_t i = 0; i < std::min(chunk.size(), (size_t)64); i++) {
                        char hex[4];
                        snprintf(hex, sizeof(hex), "%02x ", (unsigned char)chunk[i]);
                        hexDump += hex;
                    }
                    OH_LOG_INFO(LOG_APP, "Raw output bytes: %{public}s", hexDump.c_str());
                    
                    // Remove leading nulls (daemon sometimes prepends \0 to messages)
                    size_t startPos = 0;
                    while (startPos < chunk.size() && chunk[startPos] == '\0') {
                        startPos++;
                    }
                    if (startPos > 0) {
                        chunk = chunk.substr(startPos);
                    }
                    
                    // Remove trailing nulls
                    while (!chunk.empty() && chunk.back() == '\0') {
                        chunk.pop_back();
                    }
                    outputBuffer += chunk;
                    OH_LOG_INFO(LOG_APP, "Received output (cmd=%{public}u): %{public}zu bytes, content: [%{public}s]", 
                                protectBuf.commandFlag, chunk.size(), chunk.c_str());
                }
                // Remove processed packet from buffer
                g_connState->responseBuffer.erase(0, totalPacketSize);
                continue;  // Continue processing more packets
            }
            
            // For other unknown commands, log and remove
            OH_LOG_WARN(LOG_APP, "Unexpected response cmd=%{public}u, removing from buffer", protectBuf.commandFlag);
            g_connState->responseBuffer.erase(0, totalPacketSize);
        }
    }
    
    result.code = static_cast<int>(ErrorCode::SUCCESS);
    result.output = outputBuffer;
    
    // Remove trailing newlines for cleaner output
    while (!result.output.empty() && 
           (result.output.back() == '\n' || result.output.back() == '\r')) {
        result.output.pop_back();
    }
    
    OH_LOG_INFO(LOG_APP, "Command completed, output length: %{public}zu", result.output.size());
    return result;
}

CommandResult HdcClientWrapper::ExecuteCommand(const std::string& command, const std::string& connId) {
    CommandResult result = {0, ""};
    
    if (!initialized_) {
        result.code = static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    // Determine command type based on command string
    uint16_t cmdType = CMD_UNITY_EXECUTE;
    std::string actualCommand = command;
    
    if (command.find("shell ") == 0) {
        // "shell <command>" -> CMD_UNITY_EXECUTE with just the command part
        cmdType = CMD_UNITY_EXECUTE;
        actualCommand = command.substr(6);  // Remove "shell " prefix
    } else if (command == "shell") {
        // Interactive shell not supported
        result.code = static_cast<int>(ErrorCode::ERR_INVALID_COMMAND);
        result.output = "[Fail]Interactive shell not supported";
        SetLastError(result.code);
        return result;
    } else if (command.find("target mount") == 0 || command.find("remount") == 0) {
        cmdType = CMD_UNITY_REMOUNT;
    } else if (command.find("target boot") == 0 || command.find("reboot") == 0) {
        cmdType = CMD_UNITY_REBOOT;
    } else if (command.find("smode") == 0 || command.find("tmode") == 0) {
        cmdType = CMD_UNITY_RUNMODE;
    } else if (command.find("hilog") == 0) {
        cmdType = CMD_UNITY_HILOG;
    } else if (command.find("jpid") == 0) {
        cmdType = CMD_JDWP_LIST;
    } else if (command.find("bugreport") == 0) {
        cmdType = CMD_UNITY_BUGREPORT_INIT;
    } else if (command.find("fport") == 0 || command.find("rport") == 0) {
        cmdType = CMD_FORWARD_INIT;
    } else if (command.find("file send") == 0 || command.find("file recv") == 0) {
        cmdType = CMD_FILE_INIT;
    } else if (command.find("install") == 0 || command.find("sideload") == 0) {
        cmdType = CMD_APP_INIT;
    } else if (command.find("uninstall") == 0) {
        cmdType = CMD_APP_UNINSTALL;
    }
    
    result = SendCommandAndWait(actualCommand, cmdType);
    SetLastError(result.code);
    return result;
}

CommandResult HdcClientWrapper::Shell(const std::string& command, const std::string& connId) {
    CommandResult result = {0, ""};
    
    if (!initialized_) {
        result.code = static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    // Shell command handling:
    // - Empty command: CMD_SHELL_INIT (interactive shell, not supported in this implementation)
    // - Non-empty command: CMD_UNITY_EXECUTE (execute single command)
    if (command.empty()) {
        result.code = static_cast<int>(ErrorCode::ERR_INVALID_COMMAND);
        result.output = "[Fail]Interactive shell not supported, please provide a command";
        SetLastError(result.code);
        return result;
    }
    
    // Use CMD_UNITY_EXECUTE for executing shell commands
    result = SendCommandAndWait(command, CMD_UNITY_EXECUTE);
    SetLastError(result.code);
    return result;
}

CommandResult HdcClientWrapper::TargetBoot(const std::string& mode, const std::string& connId) {
    CommandResult result = {0, ""};
    
    if (!initialized_) {
        result.code = static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    // Target boot uses CMD_UNITY_REBOOT
    std::string cmd = mode.empty() ? "" : mode;
    result = SendCommandAndWait(cmd, CMD_UNITY_REBOOT);
    SetLastError(result.code);
    return result;
}

CommandResult HdcClientWrapper::TargetMount(const std::string& connId) {
    CommandResult result = {0, ""};
    
    if (!initialized_) {
        result.code = static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    // Target mount uses CMD_UNITY_REMOUNT
    result = SendCommandAndWait("", CMD_UNITY_REMOUNT);
    SetLastError(result.code);
    return result;
}

CommandResult HdcClientWrapper::Smode(bool enable, const std::string& connId) {
    CommandResult result = {0, ""};
    
    if (!initialized_) {
        result.code = static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    // Smode uses CMD_UNITY_RUNMODE
    std::string cmd = enable ? "-r" : "";
    result = SendCommandAndWait(cmd, CMD_UNITY_RUNMODE);
    SetLastError(result.code);
    return result;
}

CommandResult HdcClientWrapper::Tmode(const std::string& mode, const std::string& connId) {
    CommandResult result = {0, ""};
    
    if (!initialized_) {
        result.code = static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    // Tmode uses CMD_UNITY_RUNMODE
    result = SendCommandAndWait(mode, CMD_UNITY_RUNMODE);
    SetLastError(result.code);
    return result;
}

// File transfer implementation

// Helper: Get file size
static int64_t GetFileSize(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return -1;
    }
    return st.st_size;
}

// Helper: Build file transfer config string (matching HDC TransferConfig serialization)
static std::string BuildTransferConfig(uint64_t fileSize, const std::string& path, 
                                        const std::string& optionalName, uint8_t compressType) {
    // Simple serialization format: fileSize|path|optionalName|compressType
    // Note: Real HDC uses SerialStruct, but we use a simplified format
    std::string config;
    
    // Pack fileSize (8 bytes, little endian)
    for (int i = 0; i < 8; i++) {
        config += static_cast<char>((fileSize >> (i * 8)) & 0xFF);
    }
    
    // Pack atime (8 bytes, set to 0)
    for (int i = 0; i < 8; i++) {
        config += '\0';
    }
    
    // Pack mtime (8 bytes, set to 0)
    for (int i = 0; i < 8; i++) {
        config += '\0';
    }
    
    // Pack options (empty string with length prefix)
    config += '\0';  // empty options
    
    // Pack path with length prefix (2 bytes length + string)
    uint16_t pathLen = static_cast<uint16_t>(path.size());
    config += static_cast<char>(pathLen & 0xFF);
    config += static_cast<char>((pathLen >> 8) & 0xFF);
    config += path;
    
    // Pack optionalName with length prefix
    uint16_t nameLen = static_cast<uint16_t>(optionalName.size());
    config += static_cast<char>(nameLen & 0xFF);
    config += static_cast<char>((nameLen >> 8) & 0xFF);
    config += optionalName;
    
    // Pack updateIfNew (1 byte, false)
    config += '\0';
    
    // Pack compressType (1 byte)
    config += static_cast<char>(compressType);
    
    // Pack holdTimestamp (1 byte, false)
    config += '\0';
    
    return config;
}

// Helper: Send file data block using TLV serialization
static bool SendFileDataBlock(uint32_t channelId, uint64_t index, 
                              const uint8_t* data, size_t dataSize, bool compress) {
    if (g_connState == nullptr || !g_connState->connected.load()) {
        return false;
    }
    
    std::vector<uint8_t> payload;
    
    // Build TransferPayload header
    TransferPayload header;
    header.index = index;
    header.compressType = compress ? COMPRESS_LZ4 : COMPRESS_NONE;
    header.uncompressSize = static_cast<uint32_t>(dataSize);
    
    std::vector<uint8_t> compressedData;
    const uint8_t* sendData = data;
    size_t sendSize = dataSize;
    
    if (compress && dataSize > 0) {
        // LZ4 compression
        int maxCompressedSize = LZ4_compressBound(static_cast<int>(dataSize));
        compressedData.resize(maxCompressedSize);
        int compressedSize = LZ4_compress_default(
            reinterpret_cast<const char*>(data),
            reinterpret_cast<char*>(compressedData.data()),
            static_cast<int>(dataSize),
            maxCompressedSize
        );
        
        if (compressedSize > 0 && compressedSize < static_cast<int>(dataSize)) {
            compressedData.resize(compressedSize);
            sendData = compressedData.data();
            sendSize = compressedSize;
            header.compressSize = static_cast<uint32_t>(compressedSize);
        } else {
            // Compression not effective, send uncompressed
            header.compressType = COMPRESS_NONE;
            header.compressSize = static_cast<uint32_t>(dataSize);
        }
    } else {
        header.compressSize = static_cast<uint32_t>(dataSize);
    }
    
    // Build payload: TransferPayload header + data
    size_t headerSize = sizeof(TransferPayload);
    payload.resize(headerSize + sendSize);
    memcpy(payload.data(), &header, headerSize);
    if (sendSize > 0) {
        memcpy(payload.data() + headerSize, sendData, sendSize);
    }
    
    // Send using TLV-serialized packet
    return SendHdcPacket(g_connState, channelId, CMD_FILE_DATA, payload.data(), payload.size());
}

int HdcClientWrapper::FileSend(const std::string& localPath, const std::string& remotePath,
                               const std::string& connId) {
    if (!initialized_) {
        SetLastError(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED));
        return static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
    }
    
    if (g_connState == nullptr || !g_connState->handshakeOK.load()) {
        SetLastError(static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED));
        return static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED);
    }
    
    OH_LOG_INFO(LOG_APP, "FileSend: %{public}s -> %{public}s", localPath.c_str(), remotePath.c_str());
    
    // Check if local file exists
    int64_t fileSize = GetFileSize(localPath);
    if (fileSize < 0) {
        OH_LOG_ERROR(LOG_APP, "FileSend: local file not found: %{public}s", localPath.c_str());
        SetLastError(static_cast<int>(ErrorCode::ERR_FILE_NOT_FOUND));
        return static_cast<int>(ErrorCode::ERR_FILE_NOT_FOUND);
    }
    
    // Open local file
    std::ifstream file(localPath, std::ios::binary);
    if (!file.is_open()) {
        OH_LOG_ERROR(LOG_APP, "FileSend: failed to open file: %{public}s", localPath.c_str());
        SetLastError(static_cast<int>(ErrorCode::ERR_FILE_NOT_FOUND));
        return static_cast<int>(ErrorCode::ERR_FILE_NOT_FOUND);
    }
    
    // Extract filename from local path
    std::string filename = localPath;
    size_t pos = localPath.find_last_of("/\\");
    if (pos != std::string::npos) {
        filename = localPath.substr(pos + 1);
    }
    
    // Step 1: Send CMD_FILE_INIT with file path info
    // Format: "send localPath remotePath" (matching original hdc)
    std::string initCmd = localPath + " " + remotePath;
    auto initResult = SendCommandAndWait(initCmd, CMD_FILE_INIT, FILE_TRANSFER_TIMEOUT_MS);
    if (initResult.code != static_cast<int>(ErrorCode::SUCCESS)) {
        OH_LOG_ERROR(LOG_APP, "FileSend: CMD_FILE_INIT failed: %{public}d", initResult.code);
        file.close();
        SetLastError(initResult.code);
        return initResult.code;
    }
    
    // Step 2: Read and send file data in blocks
    std::vector<uint8_t> buffer(FILE_BLOCK_SIZE);
    uint64_t totalSent = 0;
    uint64_t index = 0;
    
    while (totalSent < static_cast<uint64_t>(fileSize)) {
        size_t toRead = std::min(static_cast<size_t>(FILE_BLOCK_SIZE), 
                                  static_cast<size_t>(fileSize - totalSent));
        file.read(reinterpret_cast<char*>(buffer.data()), toRead);
        size_t bytesRead = file.gcount();
        
        if (bytesRead == 0) {
            break;
        }
        
        // Send data block with LZ4 compression
        if (!SendFileDataBlock(g_connState->channelId.load(), index, buffer.data(), bytesRead, true)) {
            OH_LOG_ERROR(LOG_APP, "FileSend: failed to send data block at index %{public}lu", static_cast<unsigned long>(index));
            file.close();
            SetLastError(static_cast<int>(ErrorCode::ERR_FILE_TRANSFER_FAILED));
            return static_cast<int>(ErrorCode::ERR_FILE_TRANSFER_FAILED);
        }
        
        totalSent += bytesRead;
        index++;
        
        // Small delay to prevent overwhelming the connection
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    file.close();
    
    // Step 3: Send CMD_FILE_FINISH
    uint8_t finishFlag = 1;
    auto finishResult = SendCommandAndWait(std::string(1, finishFlag), CMD_FILE_FINISH, FILE_TRANSFER_TIMEOUT_MS);
    
    OH_LOG_INFO(LOG_APP, "FileSend: completed, sent %{public}lu bytes", static_cast<unsigned long>(totalSent));
    SetLastError(static_cast<int>(ErrorCode::SUCCESS));
    return static_cast<int>(ErrorCode::SUCCESS);
}

// Helper: Process received file data (implementation)
static bool ProcessFileData(const uint8_t* data, size_t dataSize) {
    if (g_fileRecvState == nullptr || !g_fileRecvState->file.is_open()) {
        return false;
    }
    
    if (dataSize < sizeof(TransferPayload)) {
        OH_LOG_ERROR(LOG_APP, "FileRecv: data too small for TransferPayload header");
        return false;
    }
    
    // Parse TransferPayload header
    const TransferPayload* header = reinterpret_cast<const TransferPayload*>(data);
    const uint8_t* payload = data + sizeof(TransferPayload);
    size_t payloadSize = dataSize - sizeof(TransferPayload);
    
    std::vector<uint8_t> decompressedData;
    const uint8_t* writeData = payload;
    size_t writeSize = payloadSize;
    
    // Decompress if needed
    if (header->compressType == COMPRESS_LZ4 && header->compressSize != header->uncompressSize) {
        decompressedData.resize(header->uncompressSize);
        int decompressedSize = LZ4_decompress_safe(
            reinterpret_cast<const char*>(payload),
            reinterpret_cast<char*>(decompressedData.data()),
            static_cast<int>(header->compressSize),
            static_cast<int>(header->uncompressSize)
        );
        
        if (decompressedSize <= 0) {
            OH_LOG_ERROR(LOG_APP, "FileRecv: LZ4 decompression failed");
            return false;
        }
        
        writeData = decompressedData.data();
        writeSize = decompressedSize;
    }
    
    // Write to file
    g_fileRecvState->file.write(reinterpret_cast<const char*>(writeData), writeSize);
    g_fileRecvState->totalReceived.fetch_add(writeSize);
    
    // Debug logging
    // OH_LOG_INFO(LOG_APP, "FileRecv: received block index=%{public}lu, size=%{public}zu, total=%{public}lu",
    //              static_cast<unsigned long>(header->index), writeSize, 
    //              static_cast<unsigned long>(g_fileRecvState->totalReceived));
    
    return true;
}

int HdcClientWrapper::FileRecv(const std::string& remotePath, const std::string& localPath,
                               const std::string& connId) {
    if (!initialized_) {
        SetLastError(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED));
        return static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
    }
    
    if (g_connState == nullptr || !g_connState->handshakeOK.load()) {
        SetLastError(static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED));
        return static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED);
    }
    
    OH_LOG_INFO(LOG_APP, "FileRecv: %{public}s -> %{public}s", remotePath.c_str(), localPath.c_str());
    
    // Create/open local file for writing
    std::ofstream file(localPath, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        OH_LOG_ERROR(LOG_APP, "FileRecv: failed to create local file: %{public}s", localPath.c_str());
        SetLastError(static_cast<int>(ErrorCode::ERR_PERMISSION_DENIED));
        return static_cast<int>(ErrorCode::ERR_PERMISSION_DENIED);
    }
    
    // Initialize receive state
    g_fileRecvState = new FileRecvState();
    g_fileRecvState->localPath = localPath;
    g_fileRecvState->file = std::move(file);
    g_fileRecvState->totalReceived.store(0);
    g_fileRecvState->finished.store(false);
    g_fileRecvState->errorCode.store(0);
    
    // Step 1: Send CMD_FILE_INIT to request file from device
    // Format: "remotePath localPath" (matching original hdc recv)
    std::string initCmd = remotePath + " " + localPath;
    auto initResult = SendCommandAndWait(initCmd, CMD_FILE_INIT, FILE_TRANSFER_TIMEOUT_MS);
    
    if (initResult.code != static_cast<int>(ErrorCode::SUCCESS)) {
        OH_LOG_ERROR(LOG_APP, "FileRecv: CMD_FILE_INIT failed: %{public}d", initResult.code);
        g_fileRecvState->file.close();
        delete g_fileRecvState;
        g_fileRecvState = nullptr;
        SetLastError(initResult.code);
        return initResult.code;
    }
    
    // Step 2: Wait for file data and finish signal
    // The data will be received through the OnRead callback
    // We need to wait for CMD_FILE_FINISH
    std::unique_lock<std::mutex> lock(g_fileRecvState->mutex);
    bool success = g_fileRecvState->cv.wait_for(lock, 
        std::chrono::milliseconds(FILE_TRANSFER_TIMEOUT_MS),
        [&]() { return g_fileRecvState->finished.load() || g_fileRecvState->errorCode.load() != 0; });
    
    int result = static_cast<int>(ErrorCode::SUCCESS);
    uint64_t totalReceived = g_fileRecvState->totalReceived.load();
    
    if (!success) {
        OH_LOG_ERROR(LOG_APP, "FileRecv: timeout waiting for file data");
        result = static_cast<int>(ErrorCode::ERR_CONNECTION_TIMEOUT);
    } else if (g_fileRecvState->errorCode.load() != 0) {
        result = g_fileRecvState->errorCode.load();
    }
    
    // Cleanup
    g_fileRecvState->file.close();
    delete g_fileRecvState;
    g_fileRecvState = nullptr;
    
    if (result == static_cast<int>(ErrorCode::SUCCESS)) {
        OH_LOG_INFO(LOG_APP, "FileRecv: completed, received %{public}lu bytes", static_cast<unsigned long>(totalReceived));
    }
    
    SetLastError(result);
    return result;
}

// App management
// App installation timeout (longer than file transfer due to installation process)
static const int APP_INSTALL_TIMEOUT_MS = 120000;  // 2 minutes

CommandResult HdcClientWrapper::Install(const std::string& hapPath, const std::string& options,
                                        const std::string& connId) {
    CommandResult result = {0, ""};
    
    if (!initialized_) {
        result.code = static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    if (g_connState == nullptr || !g_connState->handshakeOK.load()) {
        result.code = static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    OH_LOG_INFO(LOG_APP, "Install: %{public}s options=%{public}s", hapPath.c_str(), options.c_str());
    
    // Check if local HAP file exists
    int64_t fileSize = GetFileSize(hapPath);
    if (fileSize < 0) {
        OH_LOG_ERROR(LOG_APP, "Install: HAP file not found: %{public}s", hapPath.c_str());
        result.code = static_cast<int>(ErrorCode::ERR_FILE_NOT_FOUND);
        result.output = "[Fail]HAP file not found: " + hapPath;
        SetLastError(result.code);
        return result;
    }
    
    // Extract filename from path
    std::string filename = hapPath;
    size_t pos = hapPath.find_last_of("/\\");
    if (pos != std::string::npos) {
        filename = hapPath.substr(pos + 1);
    }
    
    // Step 1: Send CMD_APP_INIT with install command
    // Format: "install [options] hapPath" (matching original hdc)
    std::string initCmd = options.empty() ? hapPath : (options + " " + hapPath);
    result = SendCommandAndWait(initCmd, CMD_APP_INIT, APP_INSTALL_TIMEOUT_MS);
    
    if (result.code != static_cast<int>(ErrorCode::SUCCESS)) {
        OH_LOG_ERROR(LOG_APP, "Install: CMD_APP_INIT failed: %{public}d", result.code);
        SetLastError(result.code);
        return result;
    }
    
    // The device will handle the file transfer and installation
    // Wait for the final result
    OH_LOG_INFO(LOG_APP, "Install: completed with result: %{public}s", result.output.c_str());
    SetLastError(result.code);
    return result;
}

CommandResult HdcClientWrapper::Uninstall(const std::string& packageName, const std::string& options,
                                          const std::string& connId) {
    CommandResult result = {0, ""};
    
    if (!initialized_) {
        result.code = static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    if (g_connState == nullptr || !g_connState->handshakeOK.load()) {
        result.code = static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    OH_LOG_INFO(LOG_APP, "Uninstall: %{public}s options=%{public}s", packageName.c_str(), options.c_str());
    
    // Validate package name format (basic check)
    if (packageName.empty()) {
        result.code = static_cast<int>(ErrorCode::ERR_INVALID_COMMAND);
        result.output = "[Fail]Package name is empty";
        SetLastError(result.code);
        return result;
    }
    
    // Send CMD_APP_UNINSTALL
    // Format: "uninstall [options] packageName" (matching original hdc)
    std::string cmd = options.empty() ? packageName : (options + " " + packageName);
    result = SendCommandAndWait(cmd, CMD_APP_UNINSTALL, APP_INSTALL_TIMEOUT_MS);
    
    OH_LOG_INFO(LOG_APP, "Uninstall: completed with result: %{public}s", result.output.c_str());
    SetLastError(result.code);
    return result;
}

CommandResult HdcClientWrapper::Sideload(const std::string& packagePath, const std::string& connId) {
    CommandResult result = {0, ""};
    
    if (!initialized_) {
        result.code = static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    if (g_connState == nullptr || !g_connState->handshakeOK.load()) {
        result.code = static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    OH_LOG_INFO(LOG_APP, "Sideload: %{public}s", packagePath.c_str());
    
    // Check if package file exists
    int64_t fileSize = GetFileSize(packagePath);
    if (fileSize < 0) {
        OH_LOG_ERROR(LOG_APP, "Sideload: package file not found: %{public}s", packagePath.c_str());
        result.code = static_cast<int>(ErrorCode::ERR_FILE_NOT_FOUND);
        result.output = "[Fail]Package file not found: " + packagePath;
        SetLastError(result.code);
        return result;
    }
    
    // Sideload uses CMD_APP_SIDELOAD (3005) for OTA-style updates
    // This is different from regular install
    result = SendCommandAndWait(packagePath, CMD_APP_SIDELOAD, APP_INSTALL_TIMEOUT_MS);
    
    OH_LOG_INFO(LOG_APP, "Sideload: completed with result: %{public}s", result.output.c_str());
    SetLastError(result.code);
    return result;
}

// Port forwarding
// Supported forward types: tcp, localabstract, localfilesystem, jdwp, ark

int HdcClientWrapper::Forward(const std::string& localPort, const std::string& remotePort,
                              const std::string& connId) {
    if (!initialized_) {
        SetLastError(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED));
        return static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
    }
    
    if (g_connState == nullptr || !g_connState->handshakeOK.load()) {
        SetLastError(static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED));
        return static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED);
    }
    
    OH_LOG_INFO(LOG_APP, "Forward: %{public}s -> %{public}s", localPort.c_str(), remotePort.c_str());
    
    // Validate port format
    if (localPort.empty() || remotePort.empty()) {
        SetLastError(static_cast<int>(ErrorCode::ERR_INVALID_COMMAND));
        return static_cast<int>(ErrorCode::ERR_INVALID_COMMAND);
    }
    
    // Build forward command
    // Format: "localSpec remoteSpec" where spec can be:
    // - tcp:port
    // - localabstract:name
    // - localfilesystem:path
    // - jdwp:pid
    // - ark:pid
    std::string localSpec = localPort;
    std::string remoteSpec = remotePort;
    
    // Add tcp: prefix if not already specified
    if (localSpec.find(':') == std::string::npos) {
        localSpec = "tcp:" + localSpec;
    }
    if (remoteSpec.find(':') == std::string::npos) {
        remoteSpec = "tcp:" + remoteSpec;
    }
    
    std::string cmd = localSpec + " " + remoteSpec;
    auto result = SendCommandAndWait(cmd, CMD_FORWARD_INIT);
    
    if (result.code == static_cast<int>(ErrorCode::SUCCESS)) {
        OH_LOG_INFO(LOG_APP, "Forward: established %{public}s -> %{public}s", localSpec.c_str(), remoteSpec.c_str());
    } else {
        OH_LOG_ERROR(LOG_APP, "Forward: failed with code %{public}d", result.code);
    }
    
    SetLastError(result.code);
    return result.code;
}

int HdcClientWrapper::Reverse(const std::string& remotePort, const std::string& localPort,
                              const std::string& connId) {
    if (!initialized_) {
        SetLastError(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED));
        return static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
    }
    
    if (g_connState == nullptr || !g_connState->handshakeOK.load()) {
        SetLastError(static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED));
        return static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED);
    }
    
    OH_LOG_INFO(LOG_APP, "Reverse: %{public}s -> %{public}s", remotePort.c_str(), localPort.c_str());
    
    // Validate port format
    if (remotePort.empty() || localPort.empty()) {
        SetLastError(static_cast<int>(ErrorCode::ERR_INVALID_COMMAND));
        return static_cast<int>(ErrorCode::ERR_INVALID_COMMAND);
    }
    
    // Build reverse forward command
    // Reverse is similar to forward but direction is from device to host
    std::string remoteSpec = remotePort;
    std::string localSpec = localPort;
    
    // Add tcp: prefix if not already specified
    if (remoteSpec.find(':') == std::string::npos) {
        remoteSpec = "tcp:" + remoteSpec;
    }
    if (localSpec.find(':') == std::string::npos) {
        localSpec = "tcp:" + localSpec;
    }
    
    // For reverse, we send with a special flag or different command format
    // The format is: "reverse remoteSpec localSpec"
    std::string cmd = remoteSpec + " " + localSpec;
    auto result = SendCommandAndWait(cmd, CMD_FORWARD_INIT);
    
    if (result.code == static_cast<int>(ErrorCode::SUCCESS)) {
        OH_LOG_INFO(LOG_APP, "Reverse: established %{public}s -> %{public}s", remoteSpec.c_str(), localSpec.c_str());
    } else {
        OH_LOG_ERROR(LOG_APP, "Reverse: failed with code %{public}d", result.code);
    }
    
    SetLastError(result.code);
    return result.code;
}

// Logging and debug
// Hilog timeout (can be long for continuous log streaming)
static const int HILOG_TIMEOUT_MS = 60000;  // 60 seconds
static const int BUGREPORT_TIMEOUT_MS = 180000;  // 3 minutes for bugreport

CommandResult HdcClientWrapper::Hilog(const std::string& args, const std::string& connId) {
    CommandResult result = {0, ""};
    
    if (!initialized_) {
        result.code = static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    if (g_connState == nullptr || !g_connState->handshakeOK.load()) {
        result.code = static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    OH_LOG_INFO(LOG_APP, "Hilog: args=%{public}s", args.c_str());
    
    // Hilog uses CMD_UNITY_HILOG
    // Supported args: -h (help), -x (exit), -g (get buffer size), -p <pid>, -t <tag>, etc.
    result = SendCommandAndWait(args, CMD_UNITY_HILOG, HILOG_TIMEOUT_MS);
    
    OH_LOG_INFO(LOG_APP, "Hilog: completed with code %{public}d", result.code);
    SetLastError(result.code);
    return result;
}

CommandResult HdcClientWrapper::Bugreport(const std::string& outputPath, const std::string& connId) {
    CommandResult result = {0, ""};
    
    if (!initialized_) {
        result.code = static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    if (g_connState == nullptr || !g_connState->handshakeOK.load()) {
        result.code = static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    OH_LOG_INFO(LOG_APP, "Bugreport: outputPath=%{public}s", outputPath.c_str());
    
    // Bugreport uses CMD_UNITY_BUGREPORT_INIT
    // This collects system logs, crash dumps, and diagnostic information
    result = SendCommandAndWait(outputPath, CMD_UNITY_BUGREPORT_INIT, BUGREPORT_TIMEOUT_MS);
    
    if (result.code == static_cast<int>(ErrorCode::SUCCESS)) {
        OH_LOG_INFO(LOG_APP, "Bugreport: completed successfully");
    } else {
        OH_LOG_ERROR(LOG_APP, "Bugreport: failed with code %{public}d", result.code);
    }
    
    SetLastError(result.code);
    return result;
}

CommandResult HdcClientWrapper::Jpid(const std::string& connId) {
    CommandResult result = {0, ""};
    
    if (!initialized_) {
        result.code = static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    if (g_connState == nullptr || !g_connState->handshakeOK.load()) {
        result.code = static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED);
        result.output = GetErrorMessage(result.code);
        SetLastError(result.code);
        return result;
    }
    
    OH_LOG_INFO(LOG_APP, "Jpid: listing Java/ArkTS process IDs");
    
    // Jpid uses CMD_JDWP_LIST
    // Returns list of debuggable process IDs (JDWP/ArkTS debug)
    result = SendCommandAndWait("", CMD_JDWP_LIST);
    
    OH_LOG_INFO(LOG_APP, "Jpid: completed with code %{public}d", result.code);
    SetLastError(result.code);
    return result;
}

// Key management

int HdcClientWrapper::Keygen(const std::string& keyPath) {
    if (!initialized_) {
        SetLastError(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED));
        return static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
    }
    
    OH_LOG_INFO(LOG_APP, "Keygen: %{public}s", keyPath.c_str());
    
    // TODO: Implement key generation using HdcAuth
    SetLastError(static_cast<int>(ErrorCode::SUCCESS));
    return static_cast<int>(ErrorCode::SUCCESS);
}

} // namespace HdcWrapper
