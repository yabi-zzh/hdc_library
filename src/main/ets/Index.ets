/**
 * HDC Library 模块导出
 * 提供 HDC 客户端功能的公共 API
 */

// 主客户端
export { HdcClient, DeviceInfo, ShellResult, ListTargetsResult, CheckDeviceResult, JpidResult } from './HdcClient';

// 错误处理
export {
  HdcErrorCode,
  getErrorMessage,
  isNetworkError,
  getAllErrorCodes,
  NETWORK_ERROR_CODES
} from './HdcError';
