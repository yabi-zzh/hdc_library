/**
 * HDC 错误码定义和错误消息映射
 */

/**
 * HDC 错误码类
 */
export class HdcErrorCode {
  // 成功
  static readonly SUCCESS: number = 0;

  // 连接错误 (-1001 ~ -1005)
  static readonly ERR_CONNECTION_FAILED: number = -1001;
  static readonly ERR_CONNECTION_TIMEOUT: number = -1002;
  static readonly ERR_CONNECTION_REFUSED: number = -1003;
  static readonly ERR_CONNECTION_CLOSED: number = -1004;
  static readonly ERR_HANDSHAKE_FAILED: number = -1005;

  // 协议错误 (-2001 ~ -2003)
  static readonly ERR_PROTOCOL_ERROR: number = -2001;
  static readonly ERR_INVALID_COMMAND: number = -2002;
  static readonly ERR_INVALID_RESPONSE: number = -2003;

  // 文件传输错误 (-3001 ~ -3003)
  static readonly ERR_FILE_NOT_FOUND: number = -3001;
  static readonly ERR_PERMISSION_DENIED: number = -3002;
  static readonly ERR_FILE_TRANSFER_FAILED: number = -3003;

  // 设备错误 (-4001 ~ -4003)
  static readonly ERR_DEVICE_NOT_FOUND: number = -4001;
  static readonly ERR_DEVICE_OFFLINE: number = -4002;
  static readonly ERR_DEVICE_BUSY: number = -4003;

  // 应用管理错误 (-5001 ~ -5003)
  static readonly ERR_INSTALL_FAILED: number = -5001;
  static readonly ERR_UNINSTALL_FAILED: number = -5002;
  static readonly ERR_APP_NOT_FOUND: number = -5003;

  // 端口转发错误 (-6001 ~ -6002)
  static readonly ERR_PORT_IN_USE: number = -6001;
  static readonly ERR_FORWARD_FAILED: number = -6002;

  // 认证错误 (-7001 ~ -7006) - 与 C++ 层保持一致
  static readonly ERR_AUTH_FAILED: number = -7001;
  static readonly ERR_AUTH_TIMEOUT: number = -7002;
  static readonly ERR_AUTH_REJECTED: number = -7003;  // 用户拒绝授权
  static readonly ERR_KEY_NOT_FOUND: number = -7004;
  static readonly ERR_KEY_INVALID: number = -7005;
  static readonly ERR_KEY_GENERATION_FAILED: number = -7006;

  // 发现错误 (-9001 ~ -9002)
  static readonly ERR_DISCOVERY_FAILED: number = -9001;
  static readonly ERR_DISCOVERY_TIMEOUT: number = -9002;

  // 内部错误
  static readonly ERR_NOT_INITIALIZED: number = -9998;
  static readonly ERR_INTERNAL: number = -9999;
}

/**
 * 网络相关错误码列表
 */
export const NETWORK_ERROR_CODES: number[] = [
  HdcErrorCode.ERR_CONNECTION_FAILED,
  HdcErrorCode.ERR_CONNECTION_TIMEOUT,
  HdcErrorCode.ERR_CONNECTION_REFUSED,
  HdcErrorCode.ERR_CONNECTION_CLOSED,
  HdcErrorCode.ERR_HANDSHAKE_FAILED,
];

/**
 * 错误消息映射类
 */
class ErrorMessageMap {
  private messages: Map<number, string> = new Map();

  constructor() {
    this.messages.set(HdcErrorCode.SUCCESS, '操作成功');

    // 连接错误
    this.messages.set(HdcErrorCode.ERR_CONNECTION_FAILED, '连接失败，请检查目标设备是否开启 HDC 服务');
    this.messages.set(HdcErrorCode.ERR_CONNECTION_TIMEOUT, '连接超时，请检查网络连接是否正常');
    this.messages.set(HdcErrorCode.ERR_CONNECTION_REFUSED, '连接被拒绝，请确认端口是否正确');
    this.messages.set(HdcErrorCode.ERR_CONNECTION_CLOSED, '连接已关闭，请检查目标设备状态');
    this.messages.set(HdcErrorCode.ERR_HANDSHAKE_FAILED, '握手失败，请检查目标设备 HDC 版本是否兼容');

    // 协议错误
    this.messages.set(HdcErrorCode.ERR_PROTOCOL_ERROR, '协议错误');
    this.messages.set(HdcErrorCode.ERR_INVALID_COMMAND, '无效的命令');
    this.messages.set(HdcErrorCode.ERR_INVALID_RESPONSE, '无效的响应');

    // 文件传输错误
    this.messages.set(HdcErrorCode.ERR_FILE_NOT_FOUND, '文件不存在');
    this.messages.set(HdcErrorCode.ERR_PERMISSION_DENIED, '权限被拒绝');
    this.messages.set(HdcErrorCode.ERR_FILE_TRANSFER_FAILED, '文件传输失败');

    // 设备错误
    this.messages.set(HdcErrorCode.ERR_DEVICE_NOT_FOUND, '设备未找到');
    this.messages.set(HdcErrorCode.ERR_DEVICE_OFFLINE, '设备离线');
    this.messages.set(HdcErrorCode.ERR_DEVICE_BUSY, '设备忙');

    // 应用管理错误
    this.messages.set(HdcErrorCode.ERR_INSTALL_FAILED, '安装失败');
    this.messages.set(HdcErrorCode.ERR_UNINSTALL_FAILED, '卸载失败');
    this.messages.set(HdcErrorCode.ERR_APP_NOT_FOUND, '应用未找到');

    // 端口转发错误
    this.messages.set(HdcErrorCode.ERR_PORT_IN_USE, '端口已被占用');
    this.messages.set(HdcErrorCode.ERR_FORWARD_FAILED, '端口转发失败');

    // 认证错误
    this.messages.set(HdcErrorCode.ERR_AUTH_FAILED, '认证失败，请检查设备授权状态');
    this.messages.set(HdcErrorCode.ERR_AUTH_TIMEOUT, '认证超时，请在目标设备上确认授权弹窗');
    this.messages.set(HdcErrorCode.ERR_AUTH_REJECTED, '用户拒绝了授权请求，请重新连接并选择"始终允许"或"单次允许"');
    this.messages.set(HdcErrorCode.ERR_KEY_NOT_FOUND, '密钥文件未找到');
    this.messages.set(HdcErrorCode.ERR_KEY_INVALID, '密钥无效或已损坏');
    this.messages.set(HdcErrorCode.ERR_KEY_GENERATION_FAILED, '密钥生成失败');

    // 发现错误
    this.messages.set(HdcErrorCode.ERR_DISCOVERY_FAILED, '设备发现失败');
    this.messages.set(HdcErrorCode.ERR_DISCOVERY_TIMEOUT, '设备发现超时');

    // 内部错误
    this.messages.set(HdcErrorCode.ERR_NOT_INITIALIZED, 'HDC 未初始化，请先调用 init()');
    this.messages.set(HdcErrorCode.ERR_INTERNAL, '内部错误');
  }

  get(errorCode: number): string {
    const msg = this.messages.get(errorCode);
    return msg !== undefined ? msg : `未知错误 (${errorCode})`;
  }

  has(errorCode: number): boolean {
    return this.messages.has(errorCode);
  }
}

const errorMessageMap = new ErrorMessageMap();

/**
 * 获取所有已定义的错误码列表
 */
export function getAllErrorCodes(): number[] {
  return [
    HdcErrorCode.SUCCESS,
    HdcErrorCode.ERR_CONNECTION_FAILED,
    HdcErrorCode.ERR_CONNECTION_TIMEOUT,
    HdcErrorCode.ERR_CONNECTION_REFUSED,
    HdcErrorCode.ERR_CONNECTION_CLOSED,
    HdcErrorCode.ERR_HANDSHAKE_FAILED,
    HdcErrorCode.ERR_PROTOCOL_ERROR,
    HdcErrorCode.ERR_INVALID_COMMAND,
    HdcErrorCode.ERR_INVALID_RESPONSE,
    HdcErrorCode.ERR_FILE_NOT_FOUND,
    HdcErrorCode.ERR_PERMISSION_DENIED,
    HdcErrorCode.ERR_FILE_TRANSFER_FAILED,
    HdcErrorCode.ERR_DEVICE_NOT_FOUND,
    HdcErrorCode.ERR_DEVICE_OFFLINE,
    HdcErrorCode.ERR_DEVICE_BUSY,
    HdcErrorCode.ERR_INSTALL_FAILED,
    HdcErrorCode.ERR_UNINSTALL_FAILED,
    HdcErrorCode.ERR_APP_NOT_FOUND,
    HdcErrorCode.ERR_PORT_IN_USE,
    HdcErrorCode.ERR_FORWARD_FAILED,
    HdcErrorCode.ERR_AUTH_FAILED,
    HdcErrorCode.ERR_AUTH_TIMEOUT,
    HdcErrorCode.ERR_AUTH_REJECTED,
    HdcErrorCode.ERR_KEY_NOT_FOUND,
    HdcErrorCode.ERR_KEY_INVALID,
    HdcErrorCode.ERR_KEY_GENERATION_FAILED,
    HdcErrorCode.ERR_DISCOVERY_FAILED,
    HdcErrorCode.ERR_DISCOVERY_TIMEOUT,
    HdcErrorCode.ERR_NOT_INITIALIZED,
    HdcErrorCode.ERR_INTERNAL,
  ];
}

/**
 * 获取错误消息
 */
export function getErrorMessage(errorCode: number): string {
  return errorMessageMap.get(errorCode);
}

/**
 * 判断是否为网络相关错误
 */
export function isNetworkError(errorCode: number): boolean {
  return NETWORK_ERROR_CODES.includes(errorCode);
}
