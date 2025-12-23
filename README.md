# HDC Library

HarmonyOS 设备连接器 (HDC) 库 - 提供与 HarmonyOS 设备通信的核心功能。

## 简介

HDC Library 是一个独立的 HarmonyOS 静态共享包 (HAR)，提供与 HarmonyOS 设备通信的能力，包括：

- 设备连接管理
- Shell 命令执行
- 文件传输
- 应用安装/卸载
- 端口转发
- 日志获取

该库不包含任何 UI 组件，可直接集成到其他 HarmonyOS 应用中使用。

## 版本信息

- 库版本：3.2.0c
- 兼容 HarmonyOS API 版本：API 9+

## 安装

### 方式一：本地引用

1. 将 `hdc_library` 目录复制到你的项目中
2. 在项目根目录的 `build-profile.json5` 中添加模块引用：

```json5
{
  "modules": [
    // ... 其他模块
    {
      "name": "hdc_library",
      "srcPath": "./hdc_library",
      "targets": [
        {
          "name": "default",
          "applyToProducts": ["default"]
        }
      ]
    }
  ]
}
```

3. 在使用模块的 `oh-package.json5` 中添加依赖：

```json5
{
  "dependencies": {
    "@anthropic/hdc-library": "file:../hdc_library"
  }
}
```

## 快速开始

### 基本使用流程

```typescript
import { HdcClient, HdcErrorCode, getErrorMessage } from '@anthropic/hdc-library';

// 1. 初始化（必须在使用前调用）
const initResult = HdcClient.init(3, getContext().filesDir);
if (initResult !== HdcErrorCode.SUCCESS) {
  console.error('初始化失败:', getErrorMessage(initResult));
  return;
}

// 2. 连接设备
const connectResult = await HdcClient.connect('192.168.1.100', 8710);
if (connectResult !== HdcErrorCode.SUCCESS) {
  console.error('连接失败:', getErrorMessage(connectResult));
  return;
}

// 3. 执行操作
const result = HdcClient.shell('ls -la');
console.log(result.output);

// 4. 断开连接
HdcClient.disconnect();

// 5. 清理资源（应用退出时调用）
HdcClient.cleanup();
```

## 使用示例

### 初始化

```typescript
import { HdcClient, HdcErrorCode } from '@anthropic/hdc-library';

// 初始化 HDC 客户端
// 参数1: logLevel - 日志级别 (0-4)，默认为 3
// 参数2: sandboxPath - 应用沙箱路径，用于存储 RSA 密钥
const result = HdcClient.init(3, getContext().filesDir);
if (result === HdcErrorCode.SUCCESS) {
  console.log('HDC 初始化成功');
}
```

### 连接设备

```typescript
// 连接到设备 (异步方法)
// 参数: host - IP地址, port - 端口号(默认8710), timeoutMs - 超时时间(默认30000ms)
try {
  const connectResult = await HdcClient.connect('192.168.1.100', 8710, 30000);
  if (connectResult === HdcErrorCode.SUCCESS) {
    console.log('连接成功');
  } else if (connectResult === HdcErrorCode.ERR_AUTH_REJECTED) {
    console.log('用户在设备上拒绝了授权');
  } else if (connectResult === HdcErrorCode.ERR_AUTH_TIMEOUT) {
    console.log('等待用户授权超时');
  }
} catch (e) {
  console.error('连接异常:', e);
}
```

### 执行 Shell 命令

```typescript
const shellResult = HdcClient.shell('ls -la /data');
if (shellResult.success) {
  console.log('输出:', shellResult.output);
} else {
  console.error('错误码:', shellResult.errorCode);
  console.error('错误信息:', shellResult.errorMessage);
}
```

### 通用命令执行

```typescript
// execute() 方法支持执行任意 hdc 命令
const result = HdcClient.execute('shell ls -la /data');
// 等同于: HdcClient.shell('ls -la /data')

// 其他示例
HdcClient.execute('target mount');
HdcClient.execute('hilog');
```

### 文件传输

```typescript
// 发送文件到设备
const sendResult = HdcClient.fileSend('/local/path/file.txt', '/data/local/tmp/file.txt');
if (sendResult === HdcErrorCode.SUCCESS) {
  console.log('文件发送成功');
}

// 从设备接收文件
const recvResult = HdcClient.fileRecv('/data/local/tmp/file.txt', '/local/path/file.txt');
if (recvResult === HdcErrorCode.SUCCESS) {
  console.log('文件接收成功');
}
```

### 应用管理

```typescript
// 安装应用
const installResult = HdcClient.install('/path/to/app.hap');
if (installResult.success) {
  console.log('安装成功:', installResult.output);
} else {
  console.error('安装失败:', installResult.errorMessage);
}

// 带选项安装
const installResult2 = HdcClient.install('/path/to/app.hap', '-r'); // 覆盖安装

// 卸载应用
const uninstallResult = HdcClient.uninstall('com.example.app');
if (uninstallResult.success) {
  console.log('卸载成功');
}
```

### 端口转发

```typescript
// 创建端口转发: 本地8080 -> 远程8012
const result = HdcClient.forward('tcp:8080', 'tcp:8012');
if (result === HdcErrorCode.SUCCESS) {
  console.log('端口转发已建立');
  // 现在可以通过 127.0.0.1:8080 访问远程设备的 8012 端口
}

// 也可以省略 tcp: 前缀
HdcClient.forward('8080', '8012');

// 列出所有端口转发
const listResult = HdcClient.forwardList();
console.log(listResult.output);

// 移除端口转发
HdcClient.forwardRemove('tcp:8080', 'tcp:8012');
```

### 获取设备列表

```typescript
const targets = HdcClient.listTargets();
console.log(`发现 ${targets.count} 个设备`);
for (const device of targets.devices) {
  console.log(`- ${device.connectKey}: ${device.state}`);
}
```

### 设备发现

```typescript
// 发现网络上的设备（5秒超时）
const devices = HdcClient.discover(5000);
for (const device of devices) {
  console.log(`发现设备: ${device.connectKey}`);
}
```

### 清理资源

```typescript
// 断开连接
HdcClient.disconnect();

// 清理资源（释放所有资源，应用退出时调用）
HdcClient.cleanup();
```

## API 参考

### HdcClient

#### 初始化和清理

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `init(logLevel?, sandboxPath?)` | 初始化 HDC 客户端 | `number` (错误码，0=成功) |
| `cleanup()` | 清理资源 | `void` |
| `isInitialized()` | 检查是否已初始化 | `boolean` |

#### 连接管理

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `connect(host, port, timeoutMs?)` | 连接设备（异步） | `Promise<number>` |
| `disconnect(connId?)` | 断开连接 | `number` |
| `listTargets()` | 获取设备列表 | `ListTargetsResult` |
| `waitForDevice(host, port, timeoutMs?)` | 等待设备连接 | `number` |
| `checkDevice(connId?)` | 检查设备状态 | `CheckDeviceResult` |
| `discover(timeoutMs?)` | 发现网络设备 | `DeviceInfo[]` |

#### Shell 命令

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `shell(command, connId?)` | 执行 Shell 命令 | `ShellResult` |
| `execute(command)` | 通用命令执行 | `ShellResult` |

#### 设备控制

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `targetBoot(mode?, connId?)` | 重启设备 | `ShellResult` |
| `targetMount(connId?)` | 挂载设备分区 | `ShellResult` |
| `smode(enable, connId?)` | 设置 root 权限 | `ShellResult` |
| `tmode(mode, connId?)` | 切换连接模式 | `ShellResult` |

#### 文件传输

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `fileSend(localPath, remotePath, connId?)` | 发送文件 | `number` (错误码) |
| `fileRecv(remotePath, localPath, connId?)` | 接收文件 | `number` (错误码) |

#### 应用管理

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `install(hapPath, options?, connId?)` | 安装应用 | `ShellResult` |
| `uninstall(packageName, options?, connId?)` | 卸载应用 | `ShellResult` |
| `sideload(packagePath, connId?)` | 侧载应用 | `ShellResult` |

#### 端口转发

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `forward(localPort, remotePort, connId?)` | TCP端口转发 | `number` (错误码) |
| `forwardList(connId?)` | 列出所有端口转发 | `ShellResult` |
| `forwardRemove(localPort, remotePort, connId?)` | 移除端口转发 | `number` (错误码) |
| `reverse(remotePort, localPort, connId?)` | 反向端口转发 | `number` (错误码) |

#### 日志和调试

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `hilog(args?, connId?)` | 获取设备日志 | `ShellResult` |
| `bugreport(outputPath, connId?)` | 生成错误报告 | `ShellResult` |
| `jpid(connId?)` | 获取 JDWP 进程列表 | `ShellResult` |

#### 密钥管理

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `keygen(outputPath)` | 生成密钥 | `number` (错误码) |

#### 信息和错误处理

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `version()` | 获取版本信息 | `string` |
| `help()` | 获取帮助信息 | `string` |
| `getLastError()` | 获取最后错误码 | `number` |
| `getErrorMessage(errorCode)` | 获取错误消息 | `string` |

### 辅助函数

| 函数 | 说明 | 返回值 |
|------|------|--------|
| `getErrorMessage(errorCode)` | 获取错误消息（中文） | `string` |
| `isNetworkError(errorCode)` | 判断是否为网络错误 | `boolean` |
| `getAllErrorCodes()` | 获取所有错误码 | `number[]` |

### 数据类型

#### DeviceInfo
```typescript
class DeviceInfo {
  connectKey: string;  // 连接标识 (IP:Port)
  state: string;       // 设备状态 ("device" | "offline")
  deviceName: string;  // 设备名称
}
```

#### ShellResult
```typescript
class ShellResult {
  success: boolean;     // 是否成功
  output: string;       // 输出内容
  errorCode: number;    // 错误码 (0=成功)
  errorMessage: string; // 错误消息
}
```

#### ListTargetsResult
```typescript
class ListTargetsResult {
  count: number;         // 设备数量
  devices: DeviceInfo[]; // 设备列表
}
```

#### CheckDeviceResult
```typescript
class CheckDeviceResult {
  responsive: number;  // 响应状态 (1=响应, 0=无响应)
  status: string;      // 状态描述 ("device" | "offline")
}
```

#### JpidResult
```typescript
class JpidResult {
  count: number;  // 进程数量
  data: string;   // 进程数据
}
```

### 错误码

| 错误码 | 常量名 | 说明 |
|--------|--------|------|
| 0 | SUCCESS | 操作成功 |
| -1001 | ERR_CONNECTION_FAILED | 连接失败 |
| -1002 | ERR_CONNECTION_TIMEOUT | 连接超时 |
| -1003 | ERR_CONNECTION_REFUSED | 连接被拒绝 |
| -1004 | ERR_CONNECTION_CLOSED | 连接已关闭 |
| -1005 | ERR_HANDSHAKE_FAILED | 握手失败 |
| -2001 | ERR_PROTOCOL_ERROR | 协议错误 |
| -2002 | ERR_INVALID_COMMAND | 无效命令 |
| -2003 | ERR_INVALID_RESPONSE | 无效响应 |
| -3001 | ERR_FILE_NOT_FOUND | 文件不存在 |
| -3002 | ERR_PERMISSION_DENIED | 权限被拒绝 |
| -3003 | ERR_FILE_TRANSFER_FAILED | 文件传输失败 |
| -4001 | ERR_DEVICE_NOT_FOUND | 设备未找到 |
| -4002 | ERR_DEVICE_OFFLINE | 设备离线 |
| -4003 | ERR_DEVICE_BUSY | 设备忙 |
| -5001 | ERR_INSTALL_FAILED | 安装失败 |
| -5002 | ERR_UNINSTALL_FAILED | 卸载失败 |
| -5003 | ERR_APP_NOT_FOUND | 应用未找到 |
| -6001 | ERR_PORT_IN_USE | 端口被占用 |
| -6002 | ERR_FORWARD_FAILED | 转发失败 |
| -7001 | ERR_AUTH_FAILED | 认证失败 |
| -7002 | ERR_AUTH_TIMEOUT | 认证超时 |
| -7003 | ERR_AUTH_REJECTED | 用户拒绝授权 |
| -7004 | ERR_KEY_NOT_FOUND | 密钥未找到 |
| -7005 | ERR_KEY_INVALID | 密钥无效 |
| -7006 | ERR_KEY_GENERATION_FAILED | 密钥生成失败 |
| -9001 | ERR_DISCOVERY_FAILED | 发现失败 |
| -9002 | ERR_DISCOVERY_TIMEOUT | 发现超时 |
| -9998 | ERR_NOT_INITIALIZED | 未初始化 |
| -9999 | ERR_INTERNAL | 内部错误 |

## 重要注意事项

### 1. 初始化要求

- **必须在使用任何其他方法前调用 `init()`**
- `sandboxPath` 参数用于存储 RSA 密钥，建议使用 `getContext().filesDir`
- 重复调用 `init()` 会直接返回成功，不会重复初始化

```typescript
// 推荐的初始化方式
const result = HdcClient.init(3, getContext().filesDir);
```

### 2. 设备授权

首次连接设备时，目标设备会弹出授权对话框，用户需要选择：
- **始终允许**：记住此设备，下次自动授权
- **单次允许**：仅本次允许连接
- **拒绝**：拒绝连接请求

如果用户拒绝，`connect()` 会返回 `ERR_AUTH_REJECTED (-7003)`。

```typescript
const result = await HdcClient.connect(host, port);
if (result === HdcErrorCode.ERR_AUTH_REJECTED) {
  // 提示用户需要在设备上授权
  console.log('请在目标设备上允许调试连接');
}
```

### 3. 连接管理

- 当前版本仅支持**单设备连接**，连接新设备会断开之前的连接
- `connect()` 是异步方法，需要使用 `await` 或 `.then()`
- 建议在连接前检查初始化状态

```typescript
if (!HdcClient.isInitialized()) {
  HdcClient.init(3, getContext().filesDir);
}
const result = await HdcClient.connect(host, port);
```

### 4. 资源清理

- 应用退出前应调用 `cleanup()` 释放资源
- `disconnect()` 仅断开连接，不释放底层资源
- 端口转发会在 `cleanup()` 时自动清理

```typescript
// 在 UIAbility 的 onDestroy 中调用
onDestroy() {
  HdcClient.disconnect();
  HdcClient.cleanup();
}
```

### 5. 线程安全

- 所有方法都是线程安全的
- `connect()` 是异步方法，内部使用独立线程处理
- 建议在主线程调用 API，避免在多个线程同时操作

### 6. 超时设置

| 操作 | 默认超时 | 说明 |
|------|----------|------|
| connect | 30秒 | 包含认证等待时间 |
| shell | 30秒 | 命令执行超时 |
| fileSend/fileRecv | 60秒 | 文件传输超时 |
| install | 120秒 | 应用安装超时 |
| hilog | 60秒 | 日志获取超时 |
| bugreport | 180秒 | 错误报告生成超时 |

### 7. 功能限制

以下功能在当前版本中**未完全实现**或**不支持**：

| 功能 | 状态 | 说明 |
|------|------|------|
| `reverse()` | ❌ 未实现 | 反向端口转发暂不支持 |
| `keygen()` | ⚠️ 部分实现 | 密钥生成功能未完全实现 |
| USB 连接 | ❌ 不支持 | 仅支持 TCP/IP 网络连接 |
| 多设备连接 | ❌ 不支持 | 当前仅支持单设备连接 |

### 8. 错误处理最佳实践

```typescript
import { HdcClient, HdcErrorCode, getErrorMessage, isNetworkError } from '@anthropic/hdc-library';

async function connectDevice(host: string, port: number) {
  const result = await HdcClient.connect(host, port);
  
  if (result === HdcErrorCode.SUCCESS) {
    return true;
  }
  
  // 网络错误处理
  if (isNetworkError(result)) {
    console.error('网络错误，请检查网络连接');
  }
  
  // 认证错误处理
  switch (result) {
    case HdcErrorCode.ERR_AUTH_REJECTED:
      console.error('用户拒绝了授权请求');
      break;
    case HdcErrorCode.ERR_AUTH_TIMEOUT:
      console.error('等待授权超时，请在设备上确认');
      break;
    default:
      console.error('连接失败:', getErrorMessage(result));
  }
  
  return false;
}
```

### 9. 日志级别

`init()` 的 `logLevel` 参数控制日志输出级别：

| 级别 | 值 | 说明 |
|------|-----|------|
| FATAL | 0 | 仅输出致命错误 |
| ERROR | 1 | 输出错误信息 |
| WARN | 2 | 输出警告信息 |
| INFO | 3 | 输出一般信息（默认） |
| DEBUG | 4 | 输出调试信息 |

## 权限要求

使用此库需要在 `module.json5` 中声明以下权限：

```json5
{
  "requestPermissions": [
    {
      "name": "ohos.permission.INTERNET"
    }
  ]
}
```

## 常见问题

### Q: 连接失败，提示 "连接被拒绝"

**A:** 请检查：
1. 目标设备是否开启了 HDC 服务
2. IP 地址和端口是否正确（默认端口 8710）
3. 设备和应用是否在同一网络
4. 防火墙是否阻止了连接

### Q: 连接成功但命令执行失败

**A:** 请检查：
1. 设备是否已授权此应用
2. 连接是否仍然有效（使用 `checkDevice()` 检查）
3. 命令是否正确

### Q: 文件传输失败

**A:** 请检查：
1. 本地文件路径是否正确且有读取权限
2. 远程路径是否有写入权限
3. 设备存储空间是否充足

### Q: 应用安装失败

**A:** 请检查：
1. HAP 包是否完整且签名正确
2. 设备是否有足够的存储空间
3. 是否需要使用 `-r` 选项覆盖安装

### Q: 端口转发不工作

**A:** 请检查：
1. 本地端口是否被占用
2. 远程端口上是否有服务在监听
3. 使用 `forwardList()` 确认转发是否建立成功

## 项目结构

```
hdc_library/
├── src/main/
│   ├── cpp/                    # C++ 原生代码
│   │   ├── CMakeLists.txt      # CMake 构建配置
│   │   ├── hdc_core/           # HDC 核心代码
│   │   ├── napi/               # NAPI 接口封装
│   │   │   ├── hdc_napi.cpp
│   │   │   ├── hdc_napi.h
│   │   │   ├── hdc_client_wrapper.cpp
│   │   │   └── hdc_client_wrapper.h
│   │   └── third_party/        # 第三方库 (OpenSSL, LZ4)
│   ├── ets/                    # ArkTS 代码
│   │   ├── HdcClient.ets       # 主客户端类
│   │   ├── HdcError.ets        # 错误码定义
│   │   ├── Index.ets           # 模块导出
│   │   └── @types/             # 类型声明
│   │       └── libhdc_napi.d.ts
│   └── resources/              # 资源文件
├── oh-package.json5            # 包配置
├── build-profile.json5         # 构建配置
└── README.md                   # 本文档
```

## 更新日志

### v1.0.0
- 初始版本
- 支持设备连接、Shell 命令、文件传输、应用管理
- 支持端口转发（仅正向）
- 支持设备发现和日志获取

## 许可证

Apache-2.0
