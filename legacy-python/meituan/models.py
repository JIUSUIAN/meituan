#!/usr/bin/env python3
"""领域模型：券与领取事件。

API 响应在客户端边界转换为 Coupon，业务层内部一律用属性访问，
杜绝 couponId/couponName 之类键名的手写漂移。报告输出 JSON 的
键名保持 API 原始形态（coupon/couponId...），不受此层影响。
"""
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class Coupon:
    """一张超级券。raw 保留服务端原始字段，用于透传未知信息。"""

    coupon_id: str
    coupon_name: str = ""
    coupon_type: str = ""
    left_stock: Optional[int] = None
    direct_link: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict, compare=False)

    @classmethod
    def from_api(cls, d: Dict[str, Any]) -> "Coupon":
        return cls(
            coupon_id=d.get("couponId") or "",
            coupon_name=d.get("couponName") or "",
            coupon_type=d.get("couponType") or "",
            left_stock=d.get("leftStock"),
            direct_link=d.get("directLink"),
            raw=dict(d),
        )

    def to_dict(self) -> Dict[str, Any]:
        d = dict(self.raw)
        d.update({"couponId": self.coupon_id, "couponName": self.coupon_name,
                  "couponType": self.coupon_type})
        if self.left_stock is not None:
            d["leftStock"] = self.left_stock
        if self.direct_link is not None:
            d["directLink"] = self.direct_link
        return d

    def sold_out(self) -> bool:
        """left_stock 未知（None）时按未抢光处理——与历史 `== 0` 判断一致。"""
        return self.left_stock == 0

    def is_phone_reward(self) -> bool:
        return self.coupon_type == "PHONE_REWARD"


@dataclass(frozen=True)
class GrantEvent:
    """一次 grant 尝试的事件记录，用于收尾统计。"""

    send_ts: str
    label: str
    coupon_name: str
    status: str
    elapsed: float
