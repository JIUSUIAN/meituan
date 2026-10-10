#!/usr/bin/env python3
"""T03 错误模型：传输层/业务层异常分离 + 集中式业务码映射。"""


class ApiError(Exception):
    """API 业务错误：HTTP 层成功，但响应 code 非成功。"""

    def __init__(self, code, message, http_status=None):
        super().__init__("code=%s: %s" % (code, message))
        self.code = code
        self.message = message
        self.http_status = http_status


class ApiTransportError(Exception):
    """传输/HTTP 层失败：连接异常、超时、非 2xx 状态等。"""

    def __init__(self, message, http_status=None):
        super().__init__(message)
        self.http_status = http_status


class ApiParseError(ApiTransportError):
    """HTTP 成功但响应体不是合法 JSON。"""


# 集中式业务码 -> 领域状态映射（唯一真源，各业务函数不再各自解析）
GRANT_CODE_STATUS = {
    803: "already_claimed",
    40007: "rate_limited",
    873: "auth_expired",
    60001: "out_of_stock",
}
# 只读接口上明确代表登录态失效的业务码
AUTH_EXPIRED_CODES = {873}


def classify_grant_error(err):
    """把领取路径的 ApiError 映射为领域状态；未知 code 一律 failed，不误分类。"""
    return GRANT_CODE_STATUS.get(err.code, "failed")
