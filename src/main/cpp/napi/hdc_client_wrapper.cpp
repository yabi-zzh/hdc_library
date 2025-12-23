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
#include <algorithm>
#include <vector>

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
    CMD_KERNEL_WAKEUP_SLAVETASK = 12,  // Daemon wakeup slave task
    CMD_UNITY_EXECUTE = 1001,
    CMD_UNITY_REMOUNT = 1002,
    CMD_UNITY_REBOOT = 1003,
    CMD_UNITY_RUNMODE = 1004,
    CMD_UNITY_HILOG = 1005,
    CMD_JDWP_LIST = 1008,
    CMD_UNITY_BUGREPORT_INIT = 1011,
    CMD_SHELL_INIT = 2000,
    CMD_SHELL_DATA = 2001,
    // Forward commands
    CMD_FORWARD_INIT = 2500,
    CMD_FORWARD_CHECK = 2501,
    CMD_FORWARD_CHECK_RESULT = 2502,
    CMD_FORWARD_ACTIVE_SLAVE = 2503,
    CMD_FORWARD_ACTIVE_MASTER = 2504,
    CMD_FORWARD_DATA = 2505,
    CMD_FORWARD_FREE_CONTEXT = 2506,
    CMD_FORWARD_LIST = 2507,
    CMD_FORWARD_REMOVE = 2508,
    CMD_FORWARD_SUCCESS = 2509,
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

// Forward context structure for managing port forwarding
struct ForwardContext {
    uint32_t id;                    // Context ID
    uint32_t channelId;             // HDC channel ID
    bool masterSlave;               // true = master (listener), false = slave (connector)
    bool ready;                     // Forward is ready for data transfer
    bool finished;                  // Context is finished/closed
    bool checkPoint;                // Is this a check point connection
    std::string localSpec;          // Local port spec (e.g., "tcp:8080")
    std::string remoteSpec;         // Remote port spec (e.g., "tcp:8012")
    int localPort;                  // Parsed local port number
    int remotePort;                 // Parsed remote port number
    uv_tcp_t tcpHandle;             // TCP handle for local connection
    uv_tcp_t listenHandle;          // TCP handle for listening (master only)
    std::string dataBuffer;         // Buffer for incoming data
    std::mutex mutex;
};

// Forward task structure for managing a forward session
struct ForwardTask {
    uint32_t channelId;             // HDC channel ID for this forward
    std::string localSpec;          // Local port spec
    std::string remoteSpec;         // Remote port spec
    int localPort;                  // Local port number
    bool isReverse;                 // Is this a reverse forward
    bool established;               // Forward is established
    bool failed;                    // Forward setup failed
    std::string errorMessage;       // Error message if failed
    std::map<uint32_t, ForwardContext*> contexts;  // Active contexts
    std::mutex mutex;
    std::condition_variable cv;
    uv_tcp_t listenHandle;          // TCP listener handle
    bool listenerActive;            // Listener is active
};

// Global forward task map
static std::map<uint32_t, ForwardTask*> g_forwardTasks;
static std::mutex g_forwardTasksMutex;

// Forward info for listing
struct ForwardInfo {
    std::string localSpec;
    std::string remoteSpec;
    bool isReverse;
    uint32_t channelId;
};

// Local forward list
static std::vector<ForwardInfo> g_forwardList;
static std::mutex g_forwardListMutex;

// Forward protocol constants
static const int FORWARD_PARAM_BUF_SIZE = 8;  // First 8 bytes for parameter bits
static const uint32_t DWORD_SERIALIZE_SIZE = 4;  // Size of uint32_t for context ID

// Static mutex for event loop thread safety
static std::mutex g_loopMutex;
// Flag to indicate if we should keep the event loop running (for the lifetime of the app)
static std::atomic<bool> g_keepLoopAlive{true};

HdcClientWrapper::HdcClientWrapper() {
}

HdcClientWrapper::~HdcClientWrapper() {
    if (initialized_) {
        Cleanup();
    }
}

HdcClientWrapper& HdcClientWrapper::GetInstance() {
    static HdcClientWrapper instance;
    return instance;
}

int HdcClientWrapper::Init(int logLevel, const std::string& sandboxPath) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (initialized_) {
        return static_cast<int>(ErrorCode::SUCCESS);
    }
    
    // 设置应用沙箱路径（用于存储 RSA 密钥）
    if (!sandboxPath.empty()) {
        HdcAuth::SetAppSandboxPath(sandboxPath);
    }
    
    // Pre-generate RSA key pair if not exists
    std::string pubkeyInfo;
    HdcAuth::GetPublicKeyinfo(pubkeyInfo);
    
    // Reset the keep-alive flag
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
    
    OH_LOG_INFO(LOG_APP, "HdcClientWrapper initialized");
    return static_cast<int>(ErrorCode::SUCCESS);
}

// Forward declaration for cleanup helper
static void CleanupForwardTasks();

void HdcClientWrapper::Cleanup() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return;
    }
    
    // First stop the event loop to prevent any further processing
    StopEventLoop();
    
    // Now safe to cleanup connection state
    ConnectionState* oldState = g_connState;
    g_connState = nullptr;
    
    if (oldState != nullptr) {
        delete oldState;
    }
    
    // Cleanup forward tasks and list
    CleanupForwardTasks();
    
    // Close and cleanup libuv loop
    if (loop_ != nullptr) {
        // Walk all handles and close them
        uv_walk(loop_, [](uv_handle_t* handle, void* arg) {
            if (!uv_is_closing(handle)) {
                uv_close(handle, nullptr);
            }
        }, nullptr);
        
        // Run loop once more to process close callbacks
        uv_run(loop_, UV_RUN_NOWAIT);
        
        uv_loop_close(loop_);
        delete loop_;
        loop_ = nullptr;
    }
    
    currentConnectKey_.clear();
    initialized_ = false;
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
            return;
        }
        bool expected = false;
        if (!loopRunning_.compare_exchange_strong(expected, true)) {
            return;
        }
    }
    
    while (g_keepLoopAlive && loopRunning_) {
        {
            std::lock_guard<std::mutex> lock(g_loopMutex);
            
            if (loop_ == nullptr) {
                break;
            }
            
            uv_run(loop_, UV_RUN_NOWAIT);
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    
    loopRunning_ = false;
}

void HdcClientWrapper::StopEventLoop() {
    // Signal the loop to stop
    g_keepLoopAlive = false;
    
    {
        std::lock_guard<std::mutex> lock(g_loopMutex);
        if (loop_ != nullptr) {
            uv_stop(loop_);
        }
    }
    
    // Wait for loop thread to exit (max 2 seconds)
    int waitCount = 0;
    while (loopRunning_ && waitCount < 200) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        waitCount++;
    }
    
    if (loopRunning_) {
        OH_LOG_WARN(LOG_APP, "StopEventLoop: timeout waiting for loop to stop");
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

// Forward protocol functions
static bool SendForwardPacket(uint32_t contextId, uint16_t command, const uint8_t* data, size_t dataSize);
static void HandleForwardCheck(uint32_t channelId, const uint8_t* payload, size_t payloadSize);
static void HandleForwardCheckResult(uint32_t channelId, const uint8_t* payload, size_t payloadSize);
static void HandleForwardActiveMaster(uint32_t channelId, const uint8_t* payload, size_t payloadSize);
static void HandleForwardActiveSlave(uint32_t channelId, const uint8_t* payload, size_t payloadSize);
static void HandleForwardData(uint32_t channelId, const uint8_t* payload, size_t payloadSize);
static void HandleForwardFreeContext(uint32_t channelId, const uint8_t* payload, size_t payloadSize);
static void HandleForwardSuccess(uint32_t channelId, const uint8_t* payload, size_t payloadSize);
static ForwardTask* GetForwardTask(uint32_t channelId);
static ForwardContext* GetForwardContext(ForwardTask* task, uint32_t contextId);
static uint32_t GenerateContextId();
static bool ParsePortSpec(const std::string& spec, std::string& type, int& port);
static void ForwardListenCallback(uv_stream_t* server, int status);
static void ForwardConnectCallback(uv_connect_t* req, int status);
static void ForwardReadCallback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
static void ForwardAllocCallback(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
static void ProcessForwardMessage(uint16_t command, uint32_t channelId, 
                                  const uint8_t* payload, size_t payloadSize);

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
            
            OH_LOG_INFO(LOG_APP, "Packet cmd=%{public}u, channelId=%{public}u", 
                        protectBuf.commandFlag, protectBuf.channelId);
            
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
                // Parse SessionHandShake using TLV deserialization
                Hdc::HdcSessionBase::SessionHandShake handshake = {};
                std::string handshakeStr(reinterpret_cast<const char*>(payloadData), payloadSize);
                Hdc::SerialStruct::ParseFromString(handshake, handshakeStr);
                
                OH_LOG_INFO(LOG_APP, "Handshake: authType=%{public}u, sessionId=%{public}u",
                            handshake.authType, handshake.sessionId);
                
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
                                state->handshakeOK.store(true);
                                OH_LOG_INFO(LOG_APP, "Handshake OK, sessionId=%{public}u", state->sessionId.load());
                            }
                            break;
                        }
                            
                        case Hdc::HdcSessionBase::AUTH_NONE:
                            state->handshakeOK.store(true);
                            OH_LOG_INFO(LOG_APP, "Handshake OK (no auth), sessionId=%{public}u", state->sessionId.load());
                            break;
                            
                        case Hdc::HdcSessionBase::AUTH_PUBLICKEY: {
                            // Daemon requests public key
                            std::string pubkeyInfo;
                            if (HdcAuth::GetPublicKeyinfo(pubkeyInfo)) {
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
                                OH_LOG_ERROR(LOG_APP, "Failed to get public key");
                                state->lastError.store(static_cast<int>(ErrorCode::ERR_AUTH_FAILED));
                            }
                            break;
                        }
                            
                        case Hdc::HdcSessionBase::AUTH_SIGNATURE: {
                            // Daemon requests signature - sign the token
                            std::string signedData = handshake.buf;
                            if (HdcAuth::RsaSignAndBase64(signedData, Hdc::AuthVerifyType::RSA_3072_SHA512)) {
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
                // During handshake phase (channelId=0), if we haven't completed handshake yet,
                // this might be the UNAUTHORIZED notification. Daemon will send AUTH_SIGNATURE
                // after user authorizes on device. Don't notify waiting thread yet - keep waiting.
                if (protectBuf.channelId == 0 && !state->handshakeOK.load()) {
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
                
                // Check if this might be a handshake message embedded in echo
                // Try to parse as SessionHandShake
                if (payloadSize > 0 && !state->handshakeOK.load()) {
                    Hdc::HdcSessionBase::SessionHandShake echoHandshake = {};
                    std::string echoStr(reinterpret_cast<const char*>(payloadData), payloadSize);
                    bool parsed = Hdc::SerialStruct::ParseFromString(echoHandshake, echoStr);
                    
                    if (parsed && echoHandshake.banner.find(HANDSHAKE_MESSAGE) == 0) {
                        // Process as handshake
                        if (echoHandshake.authType == Hdc::HdcSessionBase::AUTH_SIGNATURE) {
                            // Sign the token
                            std::string signedData = echoHandshake.buf;
                            if (HdcAuth::RsaSignAndBase64(signedData, Hdc::AuthVerifyType::RSA_3072_SHA512)) {
                                
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
                
                // During handshake phase, ignore echo packets and keep waiting for AUTH_SIGNATURE
                if (!state->handshakeOK.load()) {
                    state->responseBuffer.erase(0, sizeof(PayloadHead) + headSize + dataSize);
                    continue;  // Keep waiting for more packets
                }
                
                // Check if this is a forward port result message
                // The daemon sends "Forwardport result:OK" via CMD_KERNEL_ECHO before CMD_FORWARD_SUCCESS
                // But sometimes CMD_FORWARD_SUCCESS may not arrive, so we treat this as success signal
                if (content.find("Forwardport result:OK") != std::string::npos) {
                    // Find and mark the forward task as established
                    std::lock_guard<std::mutex> fwdLock(g_forwardTasksMutex);
                    for (auto& pair : g_forwardTasks) {
                        ForwardTask* task = pair.second;
                        if (task && !task->established && !task->failed) {
                            std::lock_guard<std::mutex> taskLock(task->mutex);
                            task->established = true;
                            task->cv.notify_all();
                            break;
                        }
                    }
                    
                    // Remove from buffer and continue
                    state->responseBuffer.erase(0, sizeof(PayloadHead) + headSize + dataSize);
                    state->cv.notify_all();
                    continue;
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
                // Leave in buffer for SendCommandAndWait to process
                state->cv.notify_all();
                break;
            }
            
            // Handle Forward protocol messages
            if (protectBuf.commandFlag == CMD_KERNEL_WAKEUP_SLAVETASK ||
                protectBuf.commandFlag == CMD_FORWARD_CHECK ||
                protectBuf.commandFlag == CMD_FORWARD_CHECK_RESULT ||
                protectBuf.commandFlag == CMD_FORWARD_ACTIVE_SLAVE ||
                protectBuf.commandFlag == CMD_FORWARD_ACTIVE_MASTER ||
                protectBuf.commandFlag == CMD_FORWARD_DATA ||
                protectBuf.commandFlag == CMD_FORWARD_FREE_CONTEXT ||
                protectBuf.commandFlag == CMD_FORWARD_SUCCESS) {
                // Process forward message
                ProcessForwardMessage(protectBuf.commandFlag, protectBuf.channelId, payloadData, payloadSize);
                
                // Remove processed packet from buffer
                state->responseBuffer.erase(0, totalPacketSize);
                
                // For CMD_FORWARD_SUCCESS, also notify waiting thread
                if (protectBuf.commandFlag == CMD_FORWARD_SUCCESS) {
                    state->cv.notify_all();
                }
                continue;
            }
            
            // For other unknown commands, remove from buffer
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

// ============================================================================
// Forward Protocol Implementation
// ============================================================================

// Generate a unique context ID
static uint32_t GenerateContextId() {
    static std::atomic<uint32_t> contextCounter{1};
    return contextCounter++;
}

// Parse port specification (e.g., "tcp:8080" -> type="tcp", port=8080)
static bool ParsePortSpec(const std::string& spec, std::string& type, int& port) {
    size_t colonPos = spec.find(':');
    if (colonPos == std::string::npos || colonPos == 0 || colonPos == spec.length() - 1) {
        return false;
    }
    type = spec.substr(0, colonPos);
    std::string portStr = spec.substr(colonPos + 1);
    try {
        port = std::stoi(portStr);
        if (port <= 0 || port > 65535) {
            return false;
        }
    } catch (...) {
        return false;
    }
    return true;
}

// Get forward task by channel ID
static ForwardTask* GetForwardTask(uint32_t channelId) {
    std::lock_guard<std::mutex> lock(g_forwardTasksMutex);
    auto it = g_forwardTasks.find(channelId);
    if (it != g_forwardTasks.end()) {
        return it->second;
    }
    return nullptr;
}

// Get forward context by context ID
static ForwardContext* GetForwardContext(ForwardTask* task, uint32_t contextId) {
    if (!task) return nullptr;
    std::lock_guard<std::mutex> lock(task->mutex);
    auto it = task->contexts.find(contextId);
    if (it != task->contexts.end()) {
        return it->second;
    }
    return nullptr;
}

// Send forward packet with context ID prefix
static bool SendForwardPacket(uint32_t channelId, uint32_t contextId, uint16_t command, 
                              const uint8_t* data, size_t dataSize) {
    if (!g_connState || !g_connState->connected.load()) {
        return false;
    }
    
    // Build packet with context ID prefix (4 bytes, network byte order)
    size_t totalSize = DWORD_SERIALIZE_SIZE + dataSize;
    std::vector<uint8_t> payload(totalSize);
    
    // Write context ID in network byte order
    uint32_t netContextId = htonl(contextId);
    memcpy(payload.data(), &netContextId, DWORD_SERIALIZE_SIZE);
    
    // Copy data if any
    if (data && dataSize > 0) {
        memcpy(payload.data() + DWORD_SERIALIZE_SIZE, data, dataSize);
    }
    
    return SendHdcPacket(g_connState, channelId, command, payload.data(), totalSize);
}

// Allocate buffer for forward read
static void ForwardAllocCallback(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    size_t size = suggested_size > 65536 ? 65536 : suggested_size;
    buf->base = new char[size];
    buf->len = size;
}

// Handle data read from local TCP connection, forward to daemon
static void ForwardReadCallback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    ForwardContext* ctx = static_cast<ForwardContext*>(stream->data);
    if (!ctx) {
        if (buf->base) delete[] buf->base;
        return;
    }
    
    if (nread < 0) {
        // Notify daemon to free context
        ForwardTask* task = GetForwardTask(ctx->channelId);
        if (task) {
            SendForwardPacket(ctx->channelId, ctx->id, CMD_FORWARD_FREE_CONTEXT, nullptr, 0);
        }
        // Close local handle
        if (!uv_is_closing((uv_handle_t*)stream)) {
            uv_close((uv_handle_t*)stream, [](uv_handle_t* handle) {
                ForwardContext* c = static_cast<ForwardContext*>(handle->data);
                if (c) {
                    c->finished = true;
                }
            });
        }
        if (buf->base) delete[] buf->base;
        return;
    }
    
    if (nread == 0) {
        if (buf->base) delete[] buf->base;
        return;
    }
    
    // Forward data to daemon
    ForwardTask* task = GetForwardTask(ctx->channelId);
    if (task && ctx->ready) {
        SendForwardPacket(ctx->channelId, ctx->id, CMD_FORWARD_DATA, 
                         reinterpret_cast<uint8_t*>(buf->base), nread);
    }
    
    if (buf->base) delete[] buf->base;
}

// Handle new connection on local listener
static void ForwardListenCallback(uv_stream_t* server, int status) {
    ForwardTask* task = static_cast<ForwardTask*>(server->data);
    if (!task || status < 0) {
        return;
    }
    
    // Create new context for this connection
    ForwardContext* ctx = new ForwardContext();
    ctx->id = GenerateContextId();
    ctx->channelId = task->channelId;
    ctx->masterSlave = true;
    ctx->ready = false;
    ctx->finished = false;
    ctx->checkPoint = false;
    ctx->localSpec = task->localSpec;
    ctx->remoteSpec = task->remoteSpec;
    ctx->localPort = task->localPort;
    
    // Initialize TCP handle for this connection
    uv_tcp_init(server->loop, &ctx->tcpHandle);
    ctx->tcpHandle.data = ctx;
    
    // Accept the connection
    if (uv_accept(server, (uv_stream_t*)&ctx->tcpHandle) != 0) {
        uv_close((uv_handle_t*)&ctx->tcpHandle, nullptr);
        delete ctx;
        return;
    }
    
    // Add context to task
    {
        std::lock_guard<std::mutex> lock(task->mutex);
        task->contexts[ctx->id] = ctx;
    }
    
    // Build CMD_FORWARD_ACTIVE_SLAVE payload
    // Format: [4 bytes context ID][8 bytes param][remote spec string]
    std::vector<uint8_t> payload;
    payload.resize(FORWARD_PARAM_BUF_SIZE + task->remoteSpec.length() + 1);
    memset(payload.data(), 0, FORWARD_PARAM_BUF_SIZE);
    memcpy(payload.data() + FORWARD_PARAM_BUF_SIZE, task->remoteSpec.c_str(), task->remoteSpec.length() + 1);
    
    // Send CMD_FORWARD_ACTIVE_SLAVE to daemon
    SendForwardPacket(task->channelId, ctx->id, CMD_FORWARD_ACTIVE_SLAVE, 
                     payload.data(), payload.size());
}

// Handle CMD_FORWARD_CHECK from daemon
static void HandleForwardCheck(uint32_t channelId, const uint8_t* payload, size_t payloadSize) {
    if (payloadSize <= DWORD_SERIALIZE_SIZE + FORWARD_PARAM_BUF_SIZE) {
        return;
    }
    
    // Parse context ID
    uint32_t contextId = ntohl(*reinterpret_cast<const uint32_t*>(payload));
    
    ForwardTask* task = GetForwardTask(channelId);
    if (!task) {
        return;
    }
    
    // Send CHECK_RESULT with success
    uint8_t result = 1;  // Success
    SendForwardPacket(channelId, contextId, CMD_FORWARD_CHECK_RESULT, &result, 1);
}

// Handle CMD_FORWARD_CHECK_RESULT from daemon
static void HandleForwardCheckResult(uint32_t channelId, const uint8_t* payload, size_t payloadSize) {
    if (payloadSize <= DWORD_SERIALIZE_SIZE) {
        return;
    }
    
    uint32_t contextId = ntohl(*reinterpret_cast<const uint32_t*>(payload));
    uint8_t result = payload[DWORD_SERIALIZE_SIZE];
    
    ForwardTask* task = GetForwardTask(channelId);
    if (!task) {
        return;
    }
    
    if (!result) {
        // Check failed
        std::lock_guard<std::mutex> lock(task->mutex);
        task->failed = true;
        task->errorMessage = "Remote port check failed";
        task->cv.notify_all();
    }
}

// Handle CMD_FORWARD_ACTIVE_MASTER from daemon
static void HandleForwardActiveMaster(uint32_t channelId, const uint8_t* payload, size_t payloadSize) {
    uint32_t contextId = 0;
    if (payloadSize >= DWORD_SERIALIZE_SIZE) {
        contextId = ntohl(*reinterpret_cast<const uint32_t*>(payload));
    }
    
    ForwardTask* task = GetForwardTask(channelId);
    if (!task) {
        return;
    }
    
    ForwardContext* ctx = GetForwardContext(task, contextId);
    if (ctx) {
        ctx->ready = true;
        // Start reading from local connection
        uv_read_start((uv_stream_t*)&ctx->tcpHandle, ForwardAllocCallback, ForwardReadCallback);
    }
}

// Handle CMD_FORWARD_ACTIVE_SLAVE from daemon (for reverse forward)
static void HandleForwardActiveSlave(uint32_t channelId, const uint8_t* payload, size_t payloadSize) {
    // This is for reverse forward, not implemented yet
}

// Handle CMD_FORWARD_DATA from daemon
static void HandleForwardData(uint32_t channelId, const uint8_t* payload, size_t payloadSize) {
    if (payloadSize <= DWORD_SERIALIZE_SIZE) {
        return;
    }
    
    uint32_t contextId = ntohl(*reinterpret_cast<const uint32_t*>(payload));
    const uint8_t* data = payload + DWORD_SERIALIZE_SIZE;
    size_t dataSize = payloadSize - DWORD_SERIALIZE_SIZE;
    
    ForwardTask* task = GetForwardTask(channelId);
    if (!task) {
        return;
    }
    
    ForwardContext* ctx = GetForwardContext(task, contextId);
    if (!ctx || ctx->finished || !ctx->ready) {
        return;
    }
    
    // Write data to local TCP connection
    uv_buf_t buf;
    buf.base = new char[dataSize];
    buf.len = dataSize;
    memcpy(buf.base, data, dataSize);
    
    uv_write_t* writeReq = new uv_write_t();
    writeReq->data = buf.base;
    
    int ret = uv_write(writeReq, (uv_stream_t*)&ctx->tcpHandle, &buf, 1, 
             [](uv_write_t* req, int status) {
                 if (status < 0) {
                     OH_LOG_ERROR(LOG_APP, "Forward write to local failed: %{public}s", uv_strerror(status));
                 }
                 delete[] static_cast<char*>(req->data);
                 delete req;
             });
    
    if (ret != 0) {
        delete[] buf.base;
        delete writeReq;
    }
}

// Handle CMD_FORWARD_FREE_CONTEXT from daemon
static void HandleForwardFreeContext(uint32_t channelId, const uint8_t* payload, size_t payloadSize) {
    uint32_t contextId = 0;
    if (payloadSize >= DWORD_SERIALIZE_SIZE) {
        contextId = ntohl(*reinterpret_cast<const uint32_t*>(payload));
    }
    
    ForwardTask* task = GetForwardTask(channelId);
    if (!task) {
        return;
    }
    
    ForwardContext* ctx = nullptr;
    {
        std::lock_guard<std::mutex> lock(task->mutex);
        auto it = task->contexts.find(contextId);
        if (it != task->contexts.end()) {
            ctx = it->second;
            task->contexts.erase(it);
        }
    }
    
    if (ctx && !ctx->finished) {
        ctx->finished = true;
        if (!uv_is_closing((uv_handle_t*)&ctx->tcpHandle)) {
            uv_close((uv_handle_t*)&ctx->tcpHandle, [](uv_handle_t* handle) {
                ForwardContext* c = static_cast<ForwardContext*>(handle->data);
                delete c;
            });
        } else {
            delete ctx;
        }
    }
}

// Handle CMD_FORWARD_SUCCESS from daemon
static void HandleForwardSuccess(uint32_t channelId, const uint8_t* payload, size_t payloadSize) {
    ForwardTask* task = GetForwardTask(channelId);
    if (!task) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(task->mutex);
    task->established = true;
    task->cv.notify_all();
    
    OH_LOG_INFO(LOG_APP, "Forward established: %{public}s -> %{public}s", 
                task->localSpec.c_str(), task->remoteSpec.c_str());
}

// Process forward protocol message
static void ProcessForwardMessage(uint16_t command, uint32_t channelId, 
                                  const uint8_t* payload, size_t payloadSize) {
    switch (command) {
        case CMD_FORWARD_CHECK:
            HandleForwardCheck(channelId, payload, payloadSize);
            break;
        case CMD_FORWARD_CHECK_RESULT:
            HandleForwardCheckResult(channelId, payload, payloadSize);
            break;
        case CMD_FORWARD_ACTIVE_MASTER:
            HandleForwardActiveMaster(channelId, payload, payloadSize);
            break;
        case CMD_FORWARD_ACTIVE_SLAVE:
            HandleForwardActiveSlave(channelId, payload, payloadSize);
            break;
        case CMD_FORWARD_DATA:
            HandleForwardData(channelId, payload, payloadSize);
            break;
        case CMD_FORWARD_FREE_CONTEXT:
            HandleForwardFreeContext(channelId, payload, payloadSize);
            break;
        case CMD_FORWARD_SUCCESS:
            HandleForwardSuccess(channelId, payload, payloadSize);
            break;
        case CMD_KERNEL_WAKEUP_SLAVETASK:
            // Wakeup slave task, no action needed
            break;
        default:
            break;
    }
}

// ============================================================================
// End Forward Protocol Implementation
// ============================================================================

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
    
    // Build SessionHandShake (client sends first, like HDC server does)
    Hdc::HdcSessionBase::SessionHandShake handshake = {};
    handshake.banner = HANDSHAKE_MESSAGE;
    handshake.authType = Hdc::HdcSessionBase::AUTH_NONE;
    handshake.sessionId = state->sessionId.load();
    handshake.connectKey = state->connectKey;
    handshake.version = Hdc::Base::GetVersion();
    
    // Tell daemon we support RSA_3072_SHA512 authentication
    Hdc::Base::TlvAppend(handshake.buf, TAG_AUTH_TYPE, std::to_string(Hdc::AuthVerifyType::RSA_3072_SHA512));
    
    // Serialize handshake using TLV
    std::string handshakeStr = Hdc::SerialStruct::SerializeToString(handshake);
    
    // Send as CMD_KERNEL_HANDSHAKE packet
    SendHdcPacket(state, 0, CMD_KERNEL_HANDSHAKE, 
                  reinterpret_cast<const uint8_t*>(handshakeStr.c_str()), handshakeStr.size());
    
    state->handshakeSent.store(true);
}

// Send handshake response to daemon (when daemon sends handshake back)
static void SendHandshakeResponse(ConnectionState* state, uint32_t sessionId) {
    // Build SessionHandShake response
    Hdc::HdcSessionBase::SessionHandShake handshake = {};
    handshake.banner = HANDSHAKE_MESSAGE;
    handshake.authType = Hdc::HdcSessionBase::AUTH_NONE;
    handshake.sessionId = sessionId;
    handshake.connectKey = state->connectKey;
    handshake.version = Hdc::Base::GetVersion();
    
    // Serialize handshake using TLV
    std::string handshakeStr = Hdc::SerialStruct::SerializeToString(handshake);
    
    // Send as CMD_KERNEL_HANDSHAKE packet
    SendHdcPacket(state, 0, CMD_KERNEL_HANDSHAKE, 
                  reinterpret_cast<const uint8_t*>(handshakeStr.c_str()), handshakeStr.size());
}

static void OnConnect(uv_connect_t* req, int status) {
    ConnectionState* state = (ConnectionState*)req->data;
    if (state == nullptr) {
        return;
    }
    
    // Check if this callback is for the current connection or an old one being cleaned up
    ConnectionState* currentState = g_connState;
    if (currentState != state) {
        // Still need to close the handle if connection failed
        if (status < 0 && !uv_is_closing((uv_handle_t*)&state->tcpHandle)) {
            uv_close((uv_handle_t*)&state->tcpHandle, nullptr);
        }
        return;
    }
    
    if (status < 0) {
        // Map libuv error to more specific error codes
        int errorCode = static_cast<int>(ErrorCode::ERR_CONNECTION_FAILED);
        
        switch (status) {
            case UV_ETIMEDOUT:
                errorCode = static_cast<int>(ErrorCode::ERR_CONNECTION_TIMEOUT);
                break;
            case UV_ECONNREFUSED:
                errorCode = static_cast<int>(ErrorCode::ERR_CONNECTION_REFUSED);
                break;
            case UV_ENETUNREACH:
            case UV_EHOSTUNREACH:
                errorCode = static_cast<int>(ErrorCode::ERR_CONNECTION_FAILED);
                break;
            case UV_ECONNRESET:
            case UV_ECANCELED:
                errorCode = static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED);
                break;
        }
        
        OH_LOG_ERROR(LOG_APP, "Connect failed: %{public}s", uv_strerror(status));
        
        state->lastError.store(errorCode);
        state->connected.store(false);
        
        // Close the TCP handle since connection failed
        if (!uv_is_closing((uv_handle_t*)&state->tcpHandle)) {
            uv_close((uv_handle_t*)&state->tcpHandle, nullptr);
        }
        
        state->cv.notify_all();
        return;
    }
    
    state->connected.store(true);
    state->tcpHandle.data = state;
    
    // Start reading for daemon's response
    uv_read_start((uv_stream_t*)&state->tcpHandle, OnAllocBuffer, OnRead);
    
    // Client sends handshake first
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
        // Cleanup forward tasks and reset channel ID counter first
        CleanupForwardTasks();
        
        ConnectionState* oldState = g_connState;
        g_connState = nullptr;  // Clear global pointer first to prevent callbacks from using it
        
        // Always try to close the TCP handle if loop exists and is running
        if (loop_ != nullptr && loopRunning_.load()) {
            // Create close context on heap - will be deleted in close callback
            CloseContext* closeCtx = new CloseContext();
            closeCtx->oldState = oldState;
            closeCtx->shouldDeleteState = true;
            
            // CRITICAL: uv_close must be called from the event loop thread
            // Use uv_async to schedule the close operation
            struct CleanupContext {
                ConnectionState* oldState;
                CloseContext* closeCtx;
                uv_loop_t* loop;
                std::atomic<bool> done{false};
            };
            
            CleanupContext* cleanupCtx = new CleanupContext();
            cleanupCtx->oldState = oldState;
            cleanupCtx->closeCtx = closeCtx;
            cleanupCtx->loop = loop_;
            
            uv_async_t* asyncCleanup = new uv_async_t();
            asyncCleanup->data = cleanupCtx;
            
            bool asyncInitSuccess = false;
            {
                std::lock_guard<std::mutex> lock(g_loopMutex);
                
                if (loop_ != nullptr) {
                    int ret = uv_async_init(loop_, asyncCleanup, [](uv_async_t* handle) {
                        CleanupContext* ctx = static_cast<CleanupContext*>(handle->data);
                        if (ctx && ctx->oldState) {
                            bool alreadyClosing = uv_is_closing((uv_handle_t*)&ctx->oldState->tcpHandle);
                            
                            if (!alreadyClosing) {
                                // Stop reading first if connected
                                if (ctx->oldState->connected.load()) {
                                    uv_read_stop((uv_stream_t*)&ctx->oldState->tcpHandle);
                                }
                                
                                // Store close context in handle data
                                ctx->oldState->tcpHandle.data = ctx->closeCtx;
                                
                                // Close the handle - the callback will clean up asynchronously
                                uv_close((uv_handle_t*)&ctx->oldState->tcpHandle, [](uv_handle_t* tcpHandle) {
                                    CloseContext* closeCtx = static_cast<CloseContext*>(tcpHandle->data);
                                    if (closeCtx) {
                                        closeCtx->closed = true;
                                        if (closeCtx->shouldDeleteState && closeCtx->oldState) {
                                            delete closeCtx->oldState;
                                            closeCtx->oldState = nullptr;
                                        }
                                        delete closeCtx;
                                    }
                                });
                            } else {
                                // Handle already closing, just delete the context
                                delete ctx->closeCtx;
                                delete ctx->oldState;
                            }
                        }
                        ctx->done = true;
                        
                        // Close the async handle
                        uv_close((uv_handle_t*)handle, [](uv_handle_t* h) {
                            uv_async_t* async = (uv_async_t*)h;
                            CleanupContext* cctx = static_cast<CleanupContext*>(async->data);
                            delete cctx;
                            delete async;
                        });
                    });
                    
                    if (ret == 0) {
                        asyncInitSuccess = true;
                        uv_async_send(asyncCleanup);
                    }
                }
            }
            
            if (asyncInitSuccess) {
                // Wait for cleanup to complete (max 1 second)
                int closeWaitCount = 0;
                const int maxCloseWait = 100;
                while (!cleanupCtx->done.load() && closeWaitCount < maxCloseWait) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    closeWaitCount++;
                }
            } else {
                // Async init failed, clean up directly
                delete closeCtx;
                delete oldState;
                delete cleanupCtx;
                delete asyncCleanup;
            }
        } else {
            delete oldState;
        }
        
        // Additional pause to ensure event loop processes everything
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Ensure event loop exists and is running
    {
        std::lock_guard<std::mutex> lock(g_loopMutex);
        
        if (loop_ == nullptr) {
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
    
    OH_LOG_INFO(LOG_APP, "Connect: %{public}s:%{public}d, timeout=%{public}d", 
                host.c_str(), port, timeoutMs);
    
    // Try to connect with automatic retry
    const int maxRetries = 3;
    const int retryDelayMs = 500;
    int lastError = 0;
    
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        int result = ConnectInternal(host, port, timeoutMs);
        if (result == static_cast<int>(ErrorCode::SUCCESS)) {
            OH_LOG_INFO(LOG_APP, "Connect: success on attempt %{public}d", attempt);
            SetLastError(static_cast<int>(ErrorCode::SUCCESS));
            return static_cast<int>(ErrorCode::SUCCESS);
        }
        
        lastError = result;
        OH_LOG_WARN(LOG_APP, "Connect: attempt %{public}d failed, error=%{public}d", attempt, result);
        
        // Don't retry on certain errors
        if (result == static_cast<int>(ErrorCode::ERR_AUTH_FAILED) ||
            result == static_cast<int>(ErrorCode::ERR_AUTH_REJECTED)) {
            break;
        }
        
        // Wait before retry (except for last attempt)
        if (attempt < maxRetries) {
            std::this_thread::sleep_for(std::chrono::milliseconds(retryDelayMs));
        }
    }
    
    OH_LOG_ERROR(LOG_APP, "Connect: failed, error=%{public}d", lastError);
    SetLastError(lastError);
    return lastError;
}

int HdcClientWrapper::Disconnect(const std::string& connId) {
    if (!initialized_) {
        SetLastError(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED));
        return static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED);
    }
    
    OH_LOG_INFO(LOG_APP, "Disconnect: %{public}s", connId.c_str());
    
    // Cleanup forward tasks and reset channel ID counter first
    CleanupForwardTasks();
    
    // Only close the TCP connection, keep the event loop running
    if (g_connState != nullptr) {
        ConnectionState* oldState = g_connState;
        g_connState = nullptr;  // Clear global pointer first to prevent callbacks from using it
        
        if (oldState->connected.load() && loop_ != nullptr && loopRunning_.load()) {
            // Create close context on heap - will be deleted in callback
            CloseContext* closeCtx = new CloseContext();
            closeCtx->oldState = oldState;
            closeCtx->shouldDeleteState = true;
            
            // CRITICAL: uv_close must be called from the event loop thread
            // Use uv_async to schedule the close operation in the event loop thread
            struct DisconnectContext {
                ConnectionState* oldState;
                CloseContext* closeCtx;
                uv_loop_t* loop;
                std::atomic<bool> done{false};
            };
            
            DisconnectContext* disconnectCtx = new DisconnectContext();
            disconnectCtx->oldState = oldState;
            disconnectCtx->closeCtx = closeCtx;
            disconnectCtx->loop = loop_;
            
            uv_async_t* asyncDisconnect = new uv_async_t();
            asyncDisconnect->data = disconnectCtx;
            
            {
                std::lock_guard<std::mutex> lock(g_loopMutex);
                
                if (loop_ == nullptr) {
                    // Loop was destroyed, clean up directly
                    delete closeCtx;
                    delete oldState;
                    delete disconnectCtx;
                    delete asyncDisconnect;
                    currentConnectKey_.clear();
                    SetLastError(static_cast<int>(ErrorCode::SUCCESS));
                    return static_cast<int>(ErrorCode::SUCCESS);
                }
                
                int ret = uv_async_init(loop_, asyncDisconnect, [](uv_async_t* handle) {
                    DisconnectContext* ctx = static_cast<DisconnectContext*>(handle->data);
                    if (ctx && ctx->oldState) {
                        // Now we're in the event loop thread, safe to call uv_close
                        if (!uv_is_closing((uv_handle_t*)&ctx->oldState->tcpHandle)) {
                            uv_read_stop((uv_stream_t*)&ctx->oldState->tcpHandle);
                            
                            // Store close context in handle data
                            ctx->oldState->tcpHandle.data = ctx->closeCtx;
                            
                            // Close handle - the callback will clean up asynchronously
                            uv_close((uv_handle_t*)&ctx->oldState->tcpHandle, [](uv_handle_t* tcpHandle) {
                                CloseContext* closeCtx = static_cast<CloseContext*>(tcpHandle->data);
                                if (closeCtx) {
                                    closeCtx->closed = true;
                                    // Delete the old state in the callback
                                    if (closeCtx->shouldDeleteState && closeCtx->oldState) {
                                        delete closeCtx->oldState;
                                        closeCtx->oldState = nullptr;
                                    }
                                    delete closeCtx;
                                }
                            });
                        } else {
                            // Handle already closing
                            delete ctx->closeCtx;
                            delete ctx->oldState;
                        }
                    }
                    ctx->done = true;
                    
                    // Close the async handle
                    uv_close((uv_handle_t*)handle, [](uv_handle_t* h) {
                        uv_async_t* async = (uv_async_t*)h;
                        DisconnectContext* dctx = static_cast<DisconnectContext*>(async->data);
                        delete dctx;
                        delete async;
                    });
                });
                
                if (ret != 0) {
                    OH_LOG_ERROR(LOG_APP, "uv_async_init failed in Disconnect: %{public}s", uv_strerror(ret));
                    delete closeCtx;
                    delete oldState;
                    delete disconnectCtx;
                    delete asyncDisconnect;
                    currentConnectKey_.clear();
                    SetLastError(static_cast<int>(ErrorCode::ERR_INTERNAL));
                    return static_cast<int>(ErrorCode::ERR_INTERNAL);
                }
                
                // Trigger the async callback
                uv_async_send(asyncDisconnect);
            }
            
            // Wait for disconnect to complete (max 2 seconds)
            int waitCount = 0;
            while (!disconnectCtx->done.load() && waitCount < 200) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                waitCount++;
            }
            
            if (!disconnectCtx->done.load()) {
                OH_LOG_WARN(LOG_APP, "Disconnect: timeout waiting for async close");
            }
        } else {
            // Not connected or loop not running, just delete the state
            delete oldState;
        }
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
        close(sock);
        SetLastError(static_cast<int>(ErrorCode::ERR_DISCOVERY_FAILED));
        return devices;
    }
    
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
                    devices.push_back(info);
                }
            }
        } else if (recvLen < 0) {
            // Timeout or error
            break;
        }
    }
    
    close(sock);
    
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

// Reset channel ID counter (called when reconnecting to a new device)
static void ResetChannelIdCounter() {
    g_channelIdCounter = 1;
}

// Structure to track pending close operations for forward tasks
struct ForwardCloseContext {
    ForwardTask* task;
    std::atomic<int> pendingCloses{0};
    std::atomic<bool> allClosed{false};
};

// Cleanup forward tasks and list (called during disconnect/cleanup)
// CRITICAL: Must properly close uv_tcp_t handles before deleting ForwardTask
// to prevent use-after-free in libuv event loop
// NOTE: uv_close must be called from the event loop thread
static void CleanupForwardTasks() {
    // Get the loop pointer safely
    uv_loop_t* loop = HdcClientWrapper::GetInstance().GetLoop();
    bool loopRunning = HdcClientWrapper::GetInstance().IsLoopRunning();
    
    // Collect tasks to cleanup
    std::vector<ForwardTask*> tasksToCleanup;
    {
        std::lock_guard<std::mutex> lock(g_forwardTasksMutex);
        for (auto& pair : g_forwardTasks) {
            if (pair.second) {
                tasksToCleanup.push_back(pair.second);
            }
        }
        g_forwardTasks.clear();
    }
    
    if (tasksToCleanup.empty()) {
        // Cleanup forward list
        {
            std::lock_guard<std::mutex> lock(g_forwardListMutex);
            g_forwardList.clear();
        }
        ResetChannelIdCounter();
        return;
    }
    
    // If loop is not running, just delete everything directly
    if (loop == nullptr || !loopRunning) {
        for (auto* task : tasksToCleanup) {
            for (auto& ctxPair : task->contexts) {
                delete ctxPair.second;
            }
            task->contexts.clear();
            delete task;
        }
        
        // Cleanup forward list
        {
            std::lock_guard<std::mutex> lock(g_forwardListMutex);
            g_forwardList.clear();
        }
        ResetChannelIdCounter();
        return;
    }
    
    // Use uv_async to close handles in the event loop thread
    struct ForwardCleanupContext {
        std::vector<ForwardTask*> tasks;
        std::atomic<bool> done{false};
    };
    
    ForwardCleanupContext* cleanupCtx = new ForwardCleanupContext();
    cleanupCtx->tasks = std::move(tasksToCleanup);
    
    uv_async_t* asyncCleanup = new uv_async_t();
    asyncCleanup->data = cleanupCtx;
    
    bool asyncInitSuccess = false;
    {
        std::lock_guard<std::mutex> loopLock(g_loopMutex);
        
        if (loop != nullptr) {
            int ret = uv_async_init(loop, asyncCleanup, [](uv_async_t* handle) {
                ForwardCleanupContext* ctx = static_cast<ForwardCleanupContext*>(handle->data);
                
                // Now we're in the event loop thread, safe to call uv_close
                for (auto* task : ctx->tasks) {
                    // Close context TCP handles
                    for (auto& ctxPair : task->contexts) {
                        ForwardContext* fwdCtx = ctxPair.second;
                        if (fwdCtx) {
                            fwdCtx->finished = true;
                            
                            // Close tcpHandle if initialized and not closing
                            if (!uv_is_closing((uv_handle_t*)&fwdCtx->tcpHandle)) {
                                fwdCtx->tcpHandle.data = fwdCtx;
                                uv_close((uv_handle_t*)&fwdCtx->tcpHandle, [](uv_handle_t* h) {
                                    ForwardContext* fc = static_cast<ForwardContext*>(h->data);
                                    delete fc;
                                });
                            } else {
                                delete fwdCtx;
                            }
                            
                            // Note: listenHandle for master contexts is handled by task->listenHandle
                        }
                    }
                    task->contexts.clear();
                    
                    // Close task listener handle if active
                    if (task->listenerActive && !uv_is_closing((uv_handle_t*)&task->listenHandle)) {
                        task->listenHandle.data = task;
                        uv_close((uv_handle_t*)&task->listenHandle, [](uv_handle_t* h) {
                            ForwardTask* t = static_cast<ForwardTask*>(h->data);
                            delete t;
                        });
                    } else {
                        delete task;
                    }
                }
                ctx->tasks.clear();
                ctx->done = true;
                
                // Close the async handle
                uv_close((uv_handle_t*)handle, [](uv_handle_t* h) {
                    uv_async_t* async = (uv_async_t*)h;
                    ForwardCleanupContext* fctx = static_cast<ForwardCleanupContext*>(async->data);
                    delete fctx;
                    delete async;
                });
            });
            
            if (ret == 0) {
                asyncInitSuccess = true;
                uv_async_send(asyncCleanup);
            }
        }
    }
    
    if (asyncInitSuccess) {
        // Wait for cleanup to complete (max 2 seconds)
        int waitCount = 0;
        const int maxWait = 200;
        while (!cleanupCtx->done.load() && waitCount < maxWait) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            waitCount++;
        }
        
        if (waitCount >= maxWait) {
            OH_LOG_WARN(LOG_APP, "CleanupForwardTasks: timeout waiting for async cleanup");
        }
    } else {
        // Async init failed, clean up directly (risky but better than leaking)
        OH_LOG_WARN(LOG_APP, "CleanupForwardTasks: async init failed, cleaning up directly");
        for (auto* task : cleanupCtx->tasks) {
            for (auto& ctxPair : task->contexts) {
                delete ctxPair.second;
            }
            task->contexts.clear();
            delete task;
        }
        delete cleanupCtx;
        delete asyncCleanup;
    }
    
    // Cleanup forward list
    {
        std::lock_guard<std::mutex> lock(g_forwardListMutex);
        g_forwardList.clear();
    }
    
    // Reset channel ID counter for new connection
    ResetChannelIdCounter();
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
    
    OH_LOG_INFO(LOG_APP, "SendCommand: cmd=%{public}s, type=%{public}u, channelId=%{public}u", 
                command.c_str(), cmdType, channelId);
    
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
        OH_LOG_ERROR(LOG_APP, "SendCommand: failed to send packet");
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
        int waitTime = std::min(100, timeoutMs - static_cast<int>(elapsed));
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
            
            // Handle CMD_KERNEL_CHANNEL_CLOSE first - this indicates command completion
            if (protectBuf.commandFlag == CMD_KERNEL_CHANNEL_CLOSE) {
                channelClosed = true;
                g_connState->responseBuffer.erase(0, totalPacketSize);
                break;
            }
            
            // Handle output response types
            if (protectBuf.commandFlag == CMD_KERNEL_ECHO ||
                protectBuf.commandFlag == CMD_KERNEL_ECHO_RAW || 
                protectBuf.commandFlag == CMD_SHELL_DATA) {
                // Output data packet
                if (dataSize > 0) {
                    std::string chunk(data + sizeof(PayloadHead) + headSize, dataSize);
                    
                    // Remove leading nulls
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
                }
                g_connState->responseBuffer.erase(0, totalPacketSize);
                continue;
            }
            
            // For other unknown commands, remove from buffer
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
    
    OH_LOG_INFO(LOG_APP, "SendCommand: completed, code=%{public}d, output_len=%{public}zu", 
                result.code, result.output.size());
    if (!result.output.empty()) {
        // 截取前200字符显示，避免日志过长
        std::string displayOutput = result.output.length() > 200 
            ? result.output.substr(0, 200) + "..." 
            : result.output;
        OH_LOG_INFO(LOG_APP, "SendCommand: output=[%{public}s]", displayOutput.c_str());
    }
    return result;
}

CommandResult HdcClientWrapper::ExecuteCommand(const std::string& command, const std::string& connId) {
    CommandResult result = {0, ""};
    
    OH_LOG_INFO(LOG_APP, "ExecuteCommand: %{public}s", command.c_str());
    
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
    } else if (command.find("fport") == 0) {
        // Handle fport commands using our Forward implementation
        if (command == "fport ls" || command == "fport list") {
            // List all forwards
            return ForwardList(connId);
        } else if (command.find("fport rm ") == 0) {
            // Remove forward: "fport rm <local> <remote>"
            std::string args = command.substr(9);  // Remove "fport rm "
            size_t spacePos = args.find(' ');
            if (spacePos != std::string::npos) {
                std::string localPort = args.substr(0, spacePos);
                std::string remotePort = args.substr(spacePos + 1);
                int ret = ForwardRemove(localPort, remotePort, connId);
                result.code = ret;
                result.output = (ret == 0) ? "[Success]Forward removed" : GetErrorMessage(ret);
                return result;
            } else {
                result.code = static_cast<int>(ErrorCode::ERR_INVALID_COMMAND);
                result.output = "[Fail]Usage: fport rm <local> <remote>";
                return result;
            }
        } else if (command.find("fport ") == 0) {
            // Create forward: "fport <local> <remote>"
            std::string args = command.substr(6);  // Remove "fport "
            size_t spacePos = args.find(' ');
            if (spacePos != std::string::npos) {
                std::string localPort = args.substr(0, spacePos);
                std::string remotePort = args.substr(spacePos + 1);
                int ret = Forward(localPort, remotePort, connId);
                result.code = ret;
                result.output = (ret == 0) ? "[Success]Forward established" : GetErrorMessage(ret);
                return result;
            } else {
                result.code = static_cast<int>(ErrorCode::ERR_INVALID_COMMAND);
                result.output = "[Fail]Usage: fport <local> <remote>";
                return result;
            }
        } else {
            result.code = static_cast<int>(ErrorCode::ERR_INVALID_COMMAND);
            result.output = "[Fail]Unknown fport command. Usage: fport <local> <remote>, fport ls, fport rm <local> <remote>";
            return result;
        }
    } else if (command.find("rport") == 0) {
        // Reverse forward not yet implemented
        result.code = static_cast<int>(ErrorCode::ERR_FORWARD_FAILED);
        result.output = "[Fail]Reverse forward (rport) not yet implemented";
        return result;
    } else if (command.find("file send") == 0 || command.find("file recv") == 0) {
        cmdType = CMD_FILE_INIT;
    } else if (command.find("install") == 0 || command.find("sideload") == 0) {
        cmdType = CMD_APP_INIT;
    } else if (command.find("uninstall") == 0) {
        cmdType = CMD_APP_UNINSTALL;
    }
    
    result = SendCommandAndWait(actualCommand, cmdType);
    OH_LOG_INFO(LOG_APP, "ExecuteCommand: result code=%{public}d", result.code);
    SetLastError(result.code);
    return result;
}

CommandResult HdcClientWrapper::Execute(const std::string& command) {
    // 通用 hdc 命令执行接口，直接调用 ExecuteCommand
    return ExecuteCommand(command, "");
}

CommandResult HdcClientWrapper::Shell(const std::string& command, const std::string& connId) {
    CommandResult result = {0, ""};
    
    OH_LOG_INFO(LOG_APP, "Shell: %{public}s", command.c_str());
    
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
    OH_LOG_INFO(LOG_APP, "Shell: result code=%{public}d", result.code);
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
    CHECK_INITIALIZED_RETURN(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED));
    CHECK_CONNECTION_RETURN(static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED));
    
    OH_LOG_INFO(LOG_APP, "FileSend: %{public}s -> %{public}s", localPath.c_str(), remotePath.c_str());
    
    // Check if local file exists
    int64_t fileSize = GetFileSize(localPath);
    if (fileSize < 0) {
        OH_LOG_ERROR(LOG_APP, "FileSend: file not found");
        SetLastError(static_cast<int>(ErrorCode::ERR_FILE_NOT_FOUND));
        return static_cast<int>(ErrorCode::ERR_FILE_NOT_FOUND);
    }
    
    // Open local file
    std::ifstream file(localPath, std::ios::binary);
    if (!file.is_open()) {
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
    CHECK_INITIALIZED_RETURN(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED));
    CHECK_CONNECTION_RETURN(static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED));
    
    OH_LOG_INFO(LOG_APP, "FileRecv: %{public}s -> %{public}s", remotePath.c_str(), localPath.c_str());
    
    // Create/open local file for writing
    std::ofstream file(localPath, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
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
        OH_LOG_ERROR(LOG_APP, "FileRecv: timeout");
        result = static_cast<int>(ErrorCode::ERR_CONNECTION_TIMEOUT);
    } else if (g_fileRecvState->errorCode.load() != 0) {
        result = g_fileRecvState->errorCode.load();
    }
    
    // Cleanup
    g_fileRecvState->file.close();
    delete g_fileRecvState;
    g_fileRecvState = nullptr;
    
    OH_LOG_INFO(LOG_APP, "FileRecv: completed, code=%{public}d, received=%{public}lu bytes", 
                result, static_cast<unsigned long>(totalReceived));
    SetLastError(result);
    return result;
}

// App management
// App installation timeout (longer than file transfer due to installation process)
static const int APP_INSTALL_TIMEOUT_MS = 120000;  // 2 minutes

CommandResult HdcClientWrapper::Install(const std::string& hapPath, const std::string& options,
                                        const std::string& connId) {
    CommandResult result = {0, ""};
    CHECK_INITIALIZED_RESULT();
    CHECK_CONNECTION_RESULT();
    
    OH_LOG_INFO(LOG_APP, "Install: %{public}s, options=%{public}s", hapPath.c_str(), options.c_str());
    
    // Check if local HAP file exists
    int64_t fileSize = GetFileSize(hapPath);
    if (fileSize < 0) {
        OH_LOG_ERROR(LOG_APP, "Install: HAP file not found");
        result.code = static_cast<int>(ErrorCode::ERR_FILE_NOT_FOUND);
        result.output = "[Fail]HAP file not found: " + hapPath;
        SetLastError(result.code);
        return result;
    }
    
    // Step 1: Send CMD_APP_INIT with install command
    std::string initCmd = options.empty() ? hapPath : (options + " " + hapPath);
    result = SendCommandAndWait(initCmd, CMD_APP_INIT, APP_INSTALL_TIMEOUT_MS);
    
    OH_LOG_INFO(LOG_APP, "Install: completed, code=%{public}d", result.code);
    SetLastError(result.code);
    return result;
}

CommandResult HdcClientWrapper::Uninstall(const std::string& packageName, const std::string& options,
                                          const std::string& connId) {
    CommandResult result = {0, ""};
    CHECK_INITIALIZED_RESULT();
    CHECK_CONNECTION_RESULT();
    
    OH_LOG_INFO(LOG_APP, "Uninstall: %{public}s, options=%{public}s", packageName.c_str(), options.c_str());
    
    // Validate package name format
    if (packageName.empty()) {
        result.code = static_cast<int>(ErrorCode::ERR_INVALID_COMMAND);
        result.output = "[Fail]Package name is empty";
        SetLastError(result.code);
        return result;
    }
    
    // Send CMD_APP_UNINSTALL
    std::string cmd = options.empty() ? packageName : (options + " " + packageName);
    result = SendCommandAndWait(cmd, CMD_APP_UNINSTALL, APP_INSTALL_TIMEOUT_MS);
    
    OH_LOG_INFO(LOG_APP, "Uninstall: completed, code=%{public}d", result.code);
    SetLastError(result.code);
    return result;
}

CommandResult HdcClientWrapper::Sideload(const std::string& packagePath, const std::string& connId) {
    CommandResult result = {0, ""};
    CHECK_INITIALIZED_RESULT();
    CHECK_CONNECTION_RESULT();
    
    OH_LOG_INFO(LOG_APP, "Sideload: %{public}s", packagePath.c_str());
    
    // Check if package file exists
    int64_t fileSize = GetFileSize(packagePath);
    if (fileSize < 0) {
        OH_LOG_ERROR(LOG_APP, "Sideload: file not found");
        result.code = static_cast<int>(ErrorCode::ERR_FILE_NOT_FOUND);
        result.output = "[Fail]Package file not found: " + packagePath;
        SetLastError(result.code);
        return result;
    }
    
    // Sideload uses CMD_APP_SIDELOAD (3005) for OTA-style updates
    result = SendCommandAndWait(packagePath, CMD_APP_SIDELOAD, APP_INSTALL_TIMEOUT_MS);
    
    OH_LOG_INFO(LOG_APP, "Sideload: completed, code=%{public}d", result.code);
    SetLastError(result.code);
    return result;
}

// Port forwarding
// Supported forward types: tcp (other types like jdwp, ark require additional implementation)

int HdcClientWrapper::Forward(const std::string& localPort, const std::string& remotePort,
                              const std::string& connId) {
    CHECK_INITIALIZED_RETURN(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED));
    CHECK_CONNECTION_RETURN(static_cast<int>(ErrorCode::ERR_CONNECTION_CLOSED));
    
    OH_LOG_INFO(LOG_APP, "Forward: %{public}s -> %{public}s", localPort.c_str(), remotePort.c_str());
    
    // Validate port format
    if (localPort.empty() || remotePort.empty()) {
        SetLastError(static_cast<int>(ErrorCode::ERR_INVALID_COMMAND));
        return static_cast<int>(ErrorCode::ERR_INVALID_COMMAND);
    }
    
    // Build forward command
    std::string localSpec = localPort;
    std::string remoteSpec = remotePort;
    
    // Add tcp: prefix if not already specified
    if (localSpec.find(':') == std::string::npos) {
        localSpec = "tcp:" + localSpec;
    }
    if (remoteSpec.find(':') == std::string::npos) {
        remoteSpec = "tcp:" + remoteSpec;
    }
    
    // Parse local port
    std::string localType;
    int localPortNum = 0;
    if (!ParsePortSpec(localSpec, localType, localPortNum)) {
        OH_LOG_ERROR(LOG_APP, "Forward: invalid local port spec: %{public}s", localSpec.c_str());
        SetLastError(static_cast<int>(ErrorCode::ERR_INVALID_COMMAND));
        return static_cast<int>(ErrorCode::ERR_INVALID_COMMAND);
    }
    
    // Only TCP is supported for now
    if (localType != "tcp") {
        OH_LOG_ERROR(LOG_APP, "Forward: only tcp type is supported, got: %{public}s", localType.c_str());
        SetLastError(static_cast<int>(ErrorCode::ERR_INVALID_COMMAND));
        return static_cast<int>(ErrorCode::ERR_INVALID_COMMAND);
    }
    
    // Get channel ID for this forward
    uint32_t channelId = g_connState->channelId.fetch_add(1);
    
    // Create forward task
    ForwardTask* task = new ForwardTask();
    task->channelId = channelId;
    task->localSpec = localSpec;
    task->remoteSpec = remoteSpec;
    task->localPort = localPortNum;
    task->isReverse = false;
    task->established = false;
    task->failed = false;
    task->listenerActive = false;
    
    // Add to global task map
    {
        std::lock_guard<std::mutex> lock(g_forwardTasksMutex);
        g_forwardTasks[channelId] = task;
    }
    
    // Initialize TCP listener
    uv_tcp_init(loop_, &task->listenHandle);
    task->listenHandle.data = task;
    
    // Bind to local port
    struct sockaddr_in addr;
    uv_ip4_addr("127.0.0.1", localPortNum, &addr);
    
    int bindResult = uv_tcp_bind(&task->listenHandle, (const struct sockaddr*)&addr, 0);
    if (bindResult != 0) {
        OH_LOG_ERROR(LOG_APP, "Forward: failed to bind to port %{public}d: %{public}s", 
                    localPortNum, uv_strerror(bindResult));
        
        // Cleanup
        {
            std::lock_guard<std::mutex> lock(g_forwardTasksMutex);
            g_forwardTasks.erase(channelId);
        }
        delete task;
        
        SetLastError(static_cast<int>(ErrorCode::ERR_PORT_IN_USE));
        return static_cast<int>(ErrorCode::ERR_PORT_IN_USE);
    }
    
    // Start listening
    int listenResult = uv_listen((uv_stream_t*)&task->listenHandle, 128, ForwardListenCallback);
    if (listenResult != 0) {
        OH_LOG_ERROR(LOG_APP, "Forward: failed to listen on port %{public}d: %{public}s", 
                    localPortNum, uv_strerror(listenResult));
        
        uv_close((uv_handle_t*)&task->listenHandle, nullptr);
        {
            std::lock_guard<std::mutex> lock(g_forwardTasksMutex);
            g_forwardTasks.erase(channelId);
        }
        delete task;
        
        SetLastError(static_cast<int>(ErrorCode::ERR_FORWARD_FAILED));
        return static_cast<int>(ErrorCode::ERR_FORWARD_FAILED);
    }
    
    task->listenerActive = true;
    
    // Send CMD_FORWARD_INIT to daemon
    std::string cmd = localSpec + " " + remoteSpec;
    bool sendResult = SendHdcPacket(g_connState, channelId, CMD_FORWARD_INIT, 
                  reinterpret_cast<const uint8_t*>(cmd.c_str()), cmd.length());
    if (!sendResult) {
        OH_LOG_ERROR(LOG_APP, "Forward: failed to send CMD_FORWARD_INIT");
    }
    
    // Wait for forward to be established (with timeout)
    {
        std::unique_lock<std::mutex> lock(task->mutex);
        bool success = task->cv.wait_for(lock, std::chrono::milliseconds(CMD_TIMEOUT_MS), [task]() {
            return task->established || task->failed;
        });
        
        if (!success) {
            OH_LOG_ERROR(LOG_APP, "Forward: timeout waiting for establishment (no CMD_FORWARD_SUCCESS received)");
            task->failed = true;
            task->errorMessage = "Timeout waiting for CMD_FORWARD_SUCCESS";
        }
    }
    
    if (task->failed) {
        OH_LOG_ERROR(LOG_APP, "Forward: failed - %{public}s", task->errorMessage.c_str());
        
        // Cleanup listener
        if (task->listenerActive) {
            uv_close((uv_handle_t*)&task->listenHandle, nullptr);
        }
        
        {
            std::lock_guard<std::mutex> lock(g_forwardTasksMutex);
            g_forwardTasks.erase(channelId);
        }
        delete task;
        
        SetLastError(static_cast<int>(ErrorCode::ERR_FORWARD_FAILED));
        return static_cast<int>(ErrorCode::ERR_FORWARD_FAILED);
    }
    
    // Add to forward list
    {
        std::lock_guard<std::mutex> lock(g_forwardListMutex);
        ForwardInfo info;
        info.localSpec = localSpec;
        info.remoteSpec = remoteSpec;
        info.isReverse = false;
        info.channelId = channelId;
        g_forwardList.push_back(info);
    }
    
    OH_LOG_INFO(LOG_APP, "Forward: established %{public}s -> %{public}s", localSpec.c_str(), remoteSpec.c_str());
    SetLastError(static_cast<int>(ErrorCode::SUCCESS));
    return static_cast<int>(ErrorCode::SUCCESS);
}

int HdcClientWrapper::Reverse(const std::string& remotePort, const std::string& localPort,
                              const std::string& connId) {
    // Reverse forward is not yet implemented
    // It requires the daemon to initiate connections to the host
    OH_LOG_WARN(LOG_APP, "Reverse: not yet implemented");
    SetLastError(static_cast<int>(ErrorCode::ERR_FORWARD_FAILED));
    return static_cast<int>(ErrorCode::ERR_FORWARD_FAILED);
}

CommandResult HdcClientWrapper::ForwardList(const std::string& connId) {
    CommandResult result = {0, ""};
    CHECK_INITIALIZED_RESULT();
    
    std::lock_guard<std::mutex> lock(g_forwardListMutex);
    
    if (g_forwardList.empty()) {
        result.output = "[Empty]";
    } else {
        std::string output;
        for (const auto& fwd : g_forwardList) {
            output += fwd.localSpec + " " + fwd.remoteSpec;
            output += fwd.isReverse ? " [Reverse]\n" : " [Forward]\n";
        }
        // Remove trailing newline
        if (!output.empty() && output.back() == '\n') {
            output.pop_back();
        }
        result.output = output;
    }
    
    result.code = static_cast<int>(ErrorCode::SUCCESS);
    SetLastError(result.code);
    return result;
}

int HdcClientWrapper::ForwardRemove(const std::string& localPort, const std::string& remotePort,
                                    const std::string& connId) {
    CHECK_INITIALIZED_RETURN(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED));
    
    OH_LOG_INFO(LOG_APP, "ForwardRemove: %{public}s %{public}s", localPort.c_str(), remotePort.c_str());
    
    std::string localSpec = localPort;
    std::string remoteSpec = remotePort;
    
    // Add tcp: prefix if not already specified
    if (localSpec.find(':') == std::string::npos) {
        localSpec = "tcp:" + localSpec;
    }
    if (remoteSpec.find(':') == std::string::npos) {
        remoteSpec = "tcp:" + remoteSpec;
    }
    
    // Find and remove from forward list
    uint32_t channelId = 0;
    {
        std::lock_guard<std::mutex> lock(g_forwardListMutex);
        auto it = std::find_if(g_forwardList.begin(), g_forwardList.end(),
            [&](const ForwardInfo& fwd) {
                return fwd.localSpec == localSpec && fwd.remoteSpec == remoteSpec;
            });
        
        if (it == g_forwardList.end()) {
            OH_LOG_WARN(LOG_APP, "ForwardRemove: forward not found");
            SetLastError(static_cast<int>(ErrorCode::ERR_FORWARD_FAILED));
            return static_cast<int>(ErrorCode::ERR_FORWARD_FAILED);
        }
        
        channelId = it->channelId;
        g_forwardList.erase(it);
    }
    
    // Find and cleanup forward task
    ForwardTask* task = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_forwardTasksMutex);
        auto it = g_forwardTasks.find(channelId);
        if (it != g_forwardTasks.end()) {
            task = it->second;
            g_forwardTasks.erase(it);
        }
    }
    
    if (task) {
        // Close listener
        if (task->listenerActive && !uv_is_closing((uv_handle_t*)&task->listenHandle)) {
            uv_close((uv_handle_t*)&task->listenHandle, nullptr);
        }
        
        // Close all contexts
        std::vector<ForwardContext*> contextsToClose;
        {
            std::lock_guard<std::mutex> lock(task->mutex);
            for (auto& pair : task->contexts) {
                contextsToClose.push_back(pair.second);
            }
            task->contexts.clear();
        }
        
        for (auto ctx : contextsToClose) {
            if (!ctx->finished && !uv_is_closing((uv_handle_t*)&ctx->tcpHandle)) {
                ctx->finished = true;
                uv_close((uv_handle_t*)&ctx->tcpHandle, [](uv_handle_t* handle) {
                    ForwardContext* c = static_cast<ForwardContext*>(handle->data);
                    delete c;
                });
            }
        }
        
        // Send channel close to daemon
        if (g_connState && g_connState->connected.load()) {
            uint8_t flag = 0;
            SendHdcPacket(g_connState, channelId, CMD_KERNEL_CHANNEL_CLOSE, &flag, 1);
        }
        
        delete task;
    }
    
    OH_LOG_INFO(LOG_APP, "ForwardRemove: success");
    SetLastError(static_cast<int>(ErrorCode::SUCCESS));
    return static_cast<int>(ErrorCode::SUCCESS);
}

// Logging and debug
// Hilog timeout (can be long for continuous log streaming)
static const int HILOG_TIMEOUT_MS = 60000;  // 60 seconds
static const int BUGREPORT_TIMEOUT_MS = 180000;  // 3 minutes for bugreport

CommandResult HdcClientWrapper::Hilog(const std::string& args, const std::string& connId) {
    CommandResult result = {0, ""};
    CHECK_INITIALIZED_RESULT();
    CHECK_CONNECTION_RESULT();
    
    OH_LOG_INFO(LOG_APP, "Hilog: args=%{public}s", args.c_str());
    
    result = SendCommandAndWait(args, CMD_UNITY_HILOG, HILOG_TIMEOUT_MS);
    OH_LOG_INFO(LOG_APP, "Hilog: completed, code=%{public}d", result.code);
    SetLastError(result.code);
    return result;
}

CommandResult HdcClientWrapper::Bugreport(const std::string& outputPath, const std::string& connId) {
    CommandResult result = {0, ""};
    CHECK_INITIALIZED_RESULT();
    CHECK_CONNECTION_RESULT();
    
    OH_LOG_INFO(LOG_APP, "Bugreport: outputPath=%{public}s", outputPath.c_str());
    
    result = SendCommandAndWait(outputPath, CMD_UNITY_BUGREPORT_INIT, BUGREPORT_TIMEOUT_MS);
    OH_LOG_INFO(LOG_APP, "Bugreport: completed, code=%{public}d", result.code);
    SetLastError(result.code);
    return result;
}

CommandResult HdcClientWrapper::Jpid(const std::string& connId) {
    CommandResult result = {0, ""};
    CHECK_INITIALIZED_RESULT();
    CHECK_CONNECTION_RESULT();
    
    OH_LOG_INFO(LOG_APP, "Jpid: listing debuggable processes");
    
    result = SendCommandAndWait("", CMD_JDWP_LIST);
    OH_LOG_INFO(LOG_APP, "Jpid: completed, code=%{public}d", result.code);
    SetLastError(result.code);
    return result;
}

// Key management

int HdcClientWrapper::Keygen(const std::string& keyPath) {
    CHECK_INITIALIZED_RETURN(static_cast<int>(ErrorCode::ERR_NOT_INITIALIZED));
    
    // TODO: Implement key generation using HdcAuth
    SetLastError(static_cast<int>(ErrorCode::SUCCESS));
    return static_cast<int>(ErrorCode::SUCCESS);
}

} // namespace HdcWrapper
