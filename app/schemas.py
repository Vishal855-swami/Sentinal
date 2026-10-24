import ipaddress
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def validate_authorized_target(target: str) -> str:
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ValueError("Enter an IP address or CIDR network, not a hostname.") from exc

    if not network.is_private:
        raise ValueError("Only private or loopback IP targets are allowed by this MVP.")
    if network.num_addresses > 256:
        raise ValueError("A scan may include at most 256 IP addresses.")

    return str(network)


class ScanCreate(BaseModel):
    target: str = Field(min_length=1, max_length=64)
    authorized: bool

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return validate_authorized_target(value)

    @field_validator("authorized")
    @classmethod
    def require_authorization(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("Confirm that you are authorized to assess this network.")
        return value


class UserRegister(BaseModel):
    username: str = Field(min_length=2, max_length=80)
    password: str = Field(min_length=8, max_length=128)


class UserLogin(BaseModel):
    username: str = Field(min_length=2, max_length=80)
    password: str = Field(min_length=8, max_length=128)


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    created_at: datetime


class AuthToken(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str | None = None
    target: str
    status: str
    message: str | None
    created_at: datetime
    completed_at: datetime | None
    host_count: int
    device_count: int
    finding_count: int


class DeviceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    ip_address: str
    hostname: str | None
    device_type: str
    probable_cctv_dvr: bool
    identification_evidence: list[str]
    services: list[dict[str, Any]]


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    device_ip: str
    severity: str
    title: str
    details: str
    evidence: str
    recommendation: str
    confidence: str


class ScanDetail(ScanSummary):
    devices: list[DeviceRead]
    findings: list[FindingRead]