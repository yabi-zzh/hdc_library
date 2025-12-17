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

## 使用示例

### 初始化

```typescript
import { HdcClient, HdcErrorCode } from '@anthropic/hdc-library';

// 初始化 HDC 客户端
// sandboxPath 用于存储 RSA 密钥，建议使用应用沙箱路径
const result = HdcClient.init(3, '/data/storage/el2/base/haps/entry/files');
if (result === HdcErrorCode.SUCCESS) {
  console.log('HDC 初始化成功');
}
```

### 连接设备

```typescript
// 连接到设备 (异步)
const connectResult = await HdcClient.connect('192.168.1.100', 8710, 30000);
if (connectResult === HdcErrorCode.SUCCESS) {
  console.log('连接成功');
}
```

### 执行 Shell 命令

```typescript
const shellResult = HdcClient.shell('ls -la /data');
if (shellResult.success) {
  console.log('输出:', shellResult.output);
} else {
  console.error('错误:', shellResult.errorMessage);
}
```

### 文件传输

```typescript
// 发送文件到设备
const sendResult = HdcClient.fileSend('/local/path/file.txt', '/data/local/tmp/file.txt');

// 从设备接收文件
const recvResult = HdcClient.fileRecv('/data/local/tmp/file.txt', '/local/path/file.txt');
```

### 应用管理

```typescript
// 安装应用
const installResult = HdcClient.install('/path/to/app.hap');
if (installResult.success) {
  console.log('安装成功');
}

// 卸载应用
const uninstallResult = HdcClient.uninstall('com.example.app');
```

### 获取设备列表

```typescript
const targets = HdcClient.listTargets();
console.log(`发现 ${targets.count} 个设备`);
for (const device of targets.devices) {
  console.log(`- ${device.connectKey}: ${device.state}`);
}
```

### 清理资源

```typescript
// 断开连接
HdcClient.disconnect();

// 清理资源
HdcClient.cleanup();
```

## API 参考

### HdcClient

#### 初始化和清理

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `init(logLevel?, sandboxPath?)` | 初始化 HDC 客户端 | `number` (错误码) |
| `cleanup()` | 清理资源 | `void` |
| `isInitialized()` | 检查是否已初始化 | `boolean` |

#### 连接管理

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `connect(host, port, timeoutMs?)` | 连接设备 | `Promise<number>` |
| `disconnect(connId?)` | 断开连接 | `number` |
| `listTargets()` | 获取设备列表 | `ListTargetsResult` |
| `waitForDevice(host, port, timeoutMs?)` | 等待设备连接 | `number` |
| `checkDevice(connId?)` | 检查设备状态 | `CheckDeviceResult` |
| `discover(timeoutMs?)` | 发现网络设备 | `DeviceInfo[]` |

#### Shell 命令

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `shell(command, connId?)` | 执行 Shell 命令 | `ShellResult` |

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
| `fileSend(localPath, remotePath, connId?)` | 发送文件 | `number` |
| `fileRecv(remotePath, localPath, connId?)` | 接收文件 | `number` |

#### 应用管理

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `install(hapPath, options?, connId?)` | 安装应用 | `ShellResult` |
| `uninstall(packageName, options?, connId?)` | 卸载应用 | `ShellResult` |
| `sideload(packagePath, connId?)` | 侧载应用 | `ShellResult` |

#### 端口转发

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `forward(localPort, remotePort, connId?)` | 端口转发 | `number` |
| `reverse(remotePort, localPort, connId?)` | 反向端口转发 | `number` |

#### 日志和调试

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `hilog(args?, connId?)` | 获取设备日志 | `ShellResult` |
| `bugreport(outputPath, connId?)` | 生成错误报告 | `ShellResult` |
| `jpid(connId?)` | 获取 JDWP 进程列表 | `ShellResult` |

#### 密钥管理

| 方法 | 说明 | 返回值 |
|------|------|--------|
| `keygen(outputPath)` | 生成密钥 | `number` |

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
| `getErrorMessage(errorCode)` | 获取错误消息 | `string` |
| `isNetworkError(errorCode)` | 判断是否为网络错误 | `boolean` |
| `getAllErrorCodes()` | 获取所有错误码 | `number[]` |

### 数据类型

#### DeviceInfo
```typescript
class DeviceInfo {
  connectKey: string;  // 连接标识 (IP:Port)
  state: string;       // 设备状态
  deviceName: string;  // 设备名称
}
```

#### ShellResult
```typescript
class ShellResult {
  success: boolean;     // 是否成功
  output: string;       // 输出内容
  errorCode: number;    // 错误码
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
  status: string;      // 状态描述
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
| -2003 | ERR_INVALID_PARAMETER | 无效参数 |
| -3001 | ERR_FILE_NOT_FOUND | 文件不存在 |
| -3002 | ERR_PERMISSION_DENIED | 权限被拒绝 |
| -3003 | ERR_TRANSFER_FAILED | 传输失败 |
| -4001 | ERR_DEVICE_NOT_FOUND | 设备未找到 |
| -4002 | ERR_DEVICE_OFFLINE | 设备离线 |
| -4003 | ERR_MULTIPLE_DEVICES | 多设备冲突 |
| -5001 | ERR_INSTALL_FAILED | 安装失败 |
| -5002 | ERR_UNINSTALL_FAILED | 卸载失败 |
| -5003 | ERR_INVALID_PACKAGE | 无效包 |
| -6001 | ERR_PORT_IN_USE | 端口被占用 |
| -6002 | ERR_FORWARD_FAILED | 转发失败 |
| -7001 | ERR_AUTH_FAILED | 认证失败 |
| -7002 | ERR_AUTH_TIMEOUT | 认证超时 |
| -7003 | ERR_AUTH_REJECTED | 认证被拒绝 |
| -7004 | ERR_KEY_NOT_FOUND | 密钥未找到 |
| -7005 | ERR_KEY_INVALID | 密钥无效 |
| -7006 | ERR_KEY_GENERATION_FAILED | 密钥生成失败 |
| -9001 | ERR_DISCOVERY_FAILED | 发现失败 |
| -9002 | ERR_DISCOVERY_TIMEOUT | 发现超时 |
| -9998 | ERR_NOT_INITIALIZED | 未初始化 |
| -9999 | ERR_INTERNAL | 内部错误 |

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

## 许可证

Apache-2.0
