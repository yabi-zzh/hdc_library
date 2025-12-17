/**
 * HDC 客户端封装
 * 封装 NAPI 调用，提供类型安全的 ArkTS 接口
 */

import hdcNapi from 'libhdc_napi.so';
import { HdcErrorCode, getErrorMessage as getHdcErrorMessage } from './HdcError';
import { hilog } from '@kit.PerformanceAnalysisKit';

const TAG = 'HdcClient';
const DOMAIN = 0x0000;

/** 设备信息类 */
export class DeviceInfo {
  connectKey: string = '';
  state: string = '';
  deviceName: string = '';

  constructor(connectKey: string, state: string, deviceName: string) {
    this.connectKey = connectKey;
    this.state = state;
    this.deviceName = deviceName;
  }
}

/** Shell 执行结果类 */
export class ShellResult {
  success: boolean = false;
  output: string = '';
  errorCode: number = 0;
  errorMessage: string = '';

  constructor(success: boolean, output: string, errorCode: number = 0, errorMessage: string = '') {
    this.success = success;
    this.output = output;
    this.errorCode = errorCode;
    this.errorMessage = errorMessage;
  }
}

/** 设备列表结果类 */
export class ListTargetsResult {
  count: number = 0;
  devices: DeviceInfo[] = [];

  constructor(count: number, devices: DeviceInfo[]) {
    this.count = count;
    this.devices = devices;
  }
}

/** 设备检查结果类 */
export class CheckDeviceResult {
  responsive: number = 0;
  status: string = '';

  constructor(responsive: number, status: string) {
    this.responsive = responsive;
    this.status = status;
  }
}

/** JPID 结果类 */
export class JpidResult {
  count: number = 0;
  data: string = '';

  constructor(count: number, data: string) {
    this.count = count;
    this.data = data;
  }
}

// NAPI 返回类型
class NapiListTargetsResult {
  count: number = 0;
  data: string = '';
}

class NapiShellResult {
  code: number = 0;
  output: string = '';
}

class NapiCheckDeviceResult {
  responsive: number = 0;
  status: string = '';
}

class NapiJpidResult {
  count: number = 0;
  data: string = '';
}

class NapiDiscoverItem {
  connectKey: string = '';
}

/**
 * HDC 客户端类
 */
export class HdcClient {
  private static initialized: boolean = false;

  // ==================== 初始化和清理 ====================

  /**
   * 初始化 HDC 客户端
   * @param logLevel 日志级别 (0-4)
   * @param sandboxPath 沙箱路径
   * @returns 错误码
   */
  static init(logLevel: number = 3, sandboxPath: string = ''): number {
    if (HdcClient.initialized) {
      return HdcErrorCode.SUCCESS;
    }
    const result = hdcNapi.hdcInit(logLevel, sandboxPath) as number;
    if (result === HdcErrorCode.SUCCESS) {
      HdcClient.initialized = true;
    }
    return result;
  }

  /**
   * 清理 HDC 客户端资源
   */
  static cleanup(): void {
    if (HdcClient.initialized) {
      hdcNapi.hdcCleanup();
      HdcClient.initialized = false;
    }
  }

  /**
   * 检查是否已初始化
   */
  static isInitialized(): boolean {
    return HdcClient.initialized;
  }

  // ==================== 连接管理 ====================

  /**
   * 连接到设备
   * @param host 主机地址
   * @param port 端口号
   * @param timeoutMs 超时时间（毫秒）
   * @returns Promise<错误码>
   */
  static async connect(host: string, port: number, timeoutMs: number = 30000): Promise<number> {
    if (!HdcClient.initialized) {
      hilog.warn(DOMAIN, TAG, 'HdcClient not initialized, call init() first with sandboxPath');
      return HdcErrorCode.ERR_NOT_INITIALIZED;
    }
    return await (hdcNapi.hdcConnect(host, port, timeoutMs) as Promise<number>);
  }

  /**
   * 断开连接
   * @param connId 连接标识（可选）
   * @returns 错误码
   */
  static disconnect(connId?: string): number {
    return hdcNapi.hdcDisconnect(connId) as number;
  }

  /**
   * 解析设备列表字符串
   * @param data 设备列表原始数据
   * @returns DeviceInfo 数组
   */
  static parseDeviceList(data: string): DeviceInfo[] {
    if (!data || data.trim().length === 0) return [];
    const devices: DeviceInfo[] = [];
    const lines = data.split('\n');
    for (const line of lines) {
      const trimmedLine = line.trim();
      if (trimmedLine.length === 0) continue;
      const parts = trimmedLine.split('\t');
      if (parts.length >= 2) {
        devices.push(new DeviceInfo(
          parts[0] || '',
          parts[1] || '',
          parts.length > 2 ? (parts[2] || '') : ''
        ));
      }
    }
    return devices;
  }

  /**
   * 获取已连接设备列表
   * @returns ListTargetsResult
   */
  static listTargets(): ListTargetsResult {
    const result = hdcNapi.hdcListTargets() as NapiListTargetsResult;
    const devices = HdcClient.parseDeviceList(result.data);
    return new ListTargetsResult(result.count, devices);
  }

  /**
   * 等待设备连接
   * @param host 主机地址
   * @param port 端口号
   * @param timeoutMs 超时时间（毫秒）
   * @returns 错误码
   */
  static waitForDevice(host: string, port: number, timeoutMs: number = 30000): number {
    if (!HdcClient.initialized) {
      hilog.warn(DOMAIN, TAG, 'HdcClient not initialized, call init() first with sandboxPath');
      return HdcErrorCode.ERR_NOT_INITIALIZED;
    }
    return hdcNapi.hdcWaitForDevice(host, port, timeoutMs) as number;
  }

  /**
   * 检查设备状态
   * @param connId 连接标识（可选）
   * @returns CheckDeviceResult
   */
  static checkDevice(connId?: string): CheckDeviceResult {
    const result = hdcNapi.hdcCheckDevice(connId) as NapiCheckDeviceResult;
    return new CheckDeviceResult(result.responsive, result.status);
  }

  /**
   * 发现网络上的设备
   * @param timeoutMs 超时时间（毫秒）
   * @returns DeviceInfo 数组
   */
  static discover(timeoutMs: number = 5000): DeviceInfo[] {
    const result = hdcNapi.hdcDiscover(timeoutMs) as NapiDiscoverItem[];
    return result.map((item: NapiDiscoverItem): DeviceInfo => new DeviceInfo(item.connectKey, 'device', ''));
  }

  // ==================== Shell 命令 ====================

  /**
   * 执行 Shell 命令
   * @param command 命令字符串
   * @param connId 连接标识（可选）
   * @returns ShellResult
   */
  static shell(command: string, connId?: string): ShellResult {
    const result = hdcNapi.hdcShell(command, connId) as NapiShellResult;
    if (result.code === HdcErrorCode.SUCCESS) {
      return new ShellResult(true, result.output);
    }
    return new ShellResult(false, result.output, result.code, HdcClient.getErrorMessage(result.code));
  }

  // ==================== 设备控制 ====================

  /**
   * 重启设备
   * @param mode 重启模式（可选）
   * @param connId 连接标识（可选）
   * @returns ShellResult
   */
  static targetBoot(mode?: string, connId?: string): ShellResult {
    const result = hdcNapi.hdcTargetBoot(mode, connId) as NapiShellResult;
    if (result.code === HdcErrorCode.SUCCESS) {
      return new ShellResult(true, result.output);
    }
    return new ShellResult(false, result.output, result.code, HdcClient.getErrorMessage(result.code));
  }

  /**
   * 挂载设备分区
   * @param connId 连接标识（可选）
   * @returns ShellResult
   */
  static targetMount(connId?: string): ShellResult {
    const result = hdcNapi.hdcTargetMount(connId) as NapiShellResult;
    if (result.code === HdcErrorCode.SUCCESS) {
      return new ShellResult(true, result.output);
    }
    return new ShellResult(false, result.output, result.code, HdcClient.getErrorMessage(result.code));
  }

  /**
   * 设置 root 权限
   * @param enable 是否启用
   * @param connId 连接标识（可选）
   * @returns ShellResult
   */
  static smode(enable: boolean, connId?: string): ShellResult {
    const result = hdcNapi.hdcSmode(enable, connId) as NapiShellResult;
    if (result.code === HdcErrorCode.SUCCESS) {
      return new ShellResult(true, result.output);
    }
    return new ShellResult(false, result.output, result.code, HdcClient.getErrorMessage(result.code));
  }

  /**
   * 切换设备连接模式
   * @param mode 模式字符串
   * @param connId 连接标识（可选）
   * @returns ShellResult
   */
  static tmode(mode: string, connId?: string): ShellResult {
    const result = hdcNapi.hdcTmode(mode, connId) as NapiShellResult;
    if (result.code === HdcErrorCode.SUCCESS) {
      return new ShellResult(true, result.output);
    }
    return new ShellResult(false, result.output, result.code, HdcClient.getErrorMessage(result.code));
  }

  // ==================== 文件传输 ====================

  /**
   * 发送文件到设备
   * @param localPath 本地文件路径
   * @param remotePath 远程文件路径
   * @param connId 连接标识（可选）
   * @returns 错误码
   */
  static fileSend(localPath: string, remotePath: string, connId?: string): number {
    return hdcNapi.hdcFileSend(localPath, remotePath, connId) as number;
  }

  /**
   * 从设备接收文件
   * @param remotePath 远程文件路径
   * @param localPath 本地文件路径
   * @param connId 连接标识（可选）
   * @returns 错误码
   */
  static fileRecv(remotePath: string, localPath: string, connId?: string): number {
    return hdcNapi.hdcFileRecv(remotePath, localPath, connId) as number;
  }

  // ==================== 应用管理 ====================

  /**
   * 安装应用
   * @param hapPath HAP 包路径
   * @param options 安装选项（可选）
   * @param connId 连接标识（可选）
   * @returns ShellResult
   */
  static install(hapPath: string, options?: string, connId?: string): ShellResult {
    const result = hdcNapi.hdcInstall(hapPath, options || '', connId) as NapiShellResult;
    if (result.code === HdcErrorCode.SUCCESS) {
      return new ShellResult(true, result.output);
    }
    return new ShellResult(false, result.output, result.code, HdcClient.getErrorMessage(result.code));
  }

  /**
   * 卸载应用
   * @param packageName 包名
   * @param options 卸载选项（可选）
   * @param connId 连接标识（可选）
   * @returns ShellResult
   */
  static uninstall(packageName: string, options?: string, connId?: string): ShellResult {
    const result = hdcNapi.hdcUninstall(packageName, options || '', connId) as NapiShellResult;
    if (result.code === HdcErrorCode.SUCCESS) {
      return new ShellResult(true, result.output);
    }
    return new ShellResult(false, result.output, result.code, HdcClient.getErrorMessage(result.code));
  }

  /**
   * 侧载应用
   * @param packagePath 包路径
   * @param connId 连接标识（可选）
   * @returns ShellResult
   */
  static sideload(packagePath: string, connId?: string): ShellResult {
    const result = hdcNapi.hdcSideload(packagePath, connId) as NapiShellResult;
    if (result.code === HdcErrorCode.SUCCESS) {
      return new ShellResult(true, result.output);
    }
    return new ShellResult(false, result.output, result.code, HdcClient.getErrorMessage(result.code));
  }

  // ==================== 端口转发 ====================

  /**
   * 设置端口转发
   * @param localPort 本地端口
   * @param remotePort 远程端口
   * @param connId 连接标识（可选）
   * @returns 错误码
   */
  static forward(localPort: string, remotePort: string, connId?: string): number {
    return hdcNapi.hdcForward(localPort, remotePort, connId) as number;
  }

  /**
   * 设置反向端口转发
   * @param remotePort 远程端口
   * @param localPort 本地端口
   * @param connId 连接标识（可选）
   * @returns 错误码
   */
  static reverse(remotePort: string, localPort: string, connId?: string): number {
    return hdcNapi.hdcReverse(remotePort, localPort, connId) as number;
  }

  // ==================== 日志和调试 ====================

  /**
   * 获取设备日志
   * @param args 日志参数（可选）
   * @param connId 连接标识（可选）
   * @returns ShellResult
   */
  static hilog(args?: string, connId?: string): ShellResult {
    const result = hdcNapi.hdcHilog(args || '', connId) as NapiShellResult;
    if (result.code === HdcErrorCode.SUCCESS) {
      return new ShellResult(true, result.output);
    }
    return new ShellResult(false, result.output, result.code, HdcClient.getErrorMessage(result.code));
  }

  /**
   * 生成错误报告
   * @param outputPath 输出路径
   * @param connId 连接标识（可选）
   * @returns ShellResult
   */
  static bugreport(outputPath: string, connId?: string): ShellResult {
    const result = hdcNapi.hdcBugreport(outputPath, connId) as NapiShellResult;
    if (result.code === HdcErrorCode.SUCCESS) {
      return new ShellResult(true, result.output);
    }
    return new ShellResult(false, result.output, result.code, HdcClient.getErrorMessage(result.code));
  }

  /**
   * 获取 JDWP 进程列表
   * @param connId 连接标识（可选）
   * @returns ShellResult
   */
  static jpid(connId?: string): ShellResult {
    const result = hdcNapi.hdcJpid(connId) as NapiShellResult;
    if (result.code === HdcErrorCode.SUCCESS) {
      return new ShellResult(true, result.output);
    }
    return new ShellResult(false, result.output, result.code, HdcClient.getErrorMessage(result.code));
  }

  // ==================== 密钥管理 ====================

  /**
   * 生成密钥
   * @param outputPath 输出路径
   * @returns 错误码
   */
  static keygen(outputPath: string): number {
    return hdcNapi.hdcKeygen(outputPath) as number;
  }

  // ==================== 错误处理和信息 ====================

  /**
   * 获取版本信息
   * @returns 版本字符串
   */
  static version(): string {
    return hdcNapi.hdcVersion() as string;
  }

  /**
   * 获取帮助信息
   * @returns 帮助字符串
   */
  static help(): string {
    return hdcNapi.hdcHelp() as string;
  }

  /**
   * 获取最后一次错误码
   * @returns 错误码
   */
  static getLastError(): number {
    return hdcNapi.hdcGetLastError() as number;
  }

  /**
   * 获取错误消息
   * @param errorCode 错误码
   * @returns 错误消息字符串
   */
  static getErrorMessage(errorCode: number): string {
    const message = getHdcErrorMessage(errorCode);
    if (!message.startsWith('未知错误')) {
      return message;
    }
    return hdcNapi.hdcGetErrorMessage(errorCode) as string;
  }
}
