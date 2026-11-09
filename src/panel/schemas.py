"""Формы запросов API: то, что принимает панель."""
from __future__ import annotations

from typing import Any, Annotated, Literal

from pydantic import BaseModel, Field

NAME = Annotated[str, Field(min_length=2, max_length=32, pattern=r"^[A-Za-z0-9_.\-]+$")]
PORT = Annotated[int, Field(ge=1, le=65535)]
ADDRESS = Annotated[str, Field(min_length=4, max_length=63, pattern=r"^[A-Za-z0-9._:\-\[\]]+$")]
NODE_NAME = Annotated[str, Field(min_length=2, max_length=32)]
STATUS = Literal["active", "disabled"]
PROTOCOLS = Literal["vless", "vmess", "trojan", "ss", "hy2"]
NETWORKS = Literal["tcp", "ws", "grpc", "http", "udp"]
SECURITY = Literal["none", "tls", "reality"]


class Login(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=128)


class UserCreate(BaseModel):
    name: NAME
    client: Annotated[str | None, Field(max_length=32)] = None


class UserPatch(BaseModel):
    status: STATUS | None = None
    client: Annotated[str | None, Field(max_length=32)] = None
    name: NAME | None = None


class NodeCreate(BaseModel):
    name: NAME
    address: ADDRESS
    xray: str | None = Field(default=None, max_length=16)
    apiPort: PORT | None = None
    # API-ключ обязателен: без него панель не сможет сделать на ноде ничего,
    # кроме как проверить, что та отвечает
    apiKey: Annotated[str, Field(min_length=12, max_length=128, pattern=r"^[A-Za-z0-9_.\-]+$")]


class NodePatch(BaseModel):
    # имя ноды можно менять: хосты и цепочки держатся за node_id, а имена хопов
    # читаются из базы заново, поэтому переименование у них ничего не ломает
    name: NAME | None = None
    address: ADDRESS | None = None
    online: bool | None = None
    xray: str | None = Field(default=None, max_length=16)
    apiPort: PORT | None = None
    apiKey: Annotated[str | None, Field(min_length=12, max_length=128, pattern=r"^[A-Za-z0-9_.\-]+$")] = None


class HostCreate(BaseModel):
    name: Annotated[str, Field(min_length=2, max_length=48)]
    node: NODE_NAME
    protocol: PROTOCOLS
    port: PORT
    network: NETWORKS = "tcp"
    security: SECURITY = "none"


class Hop(BaseModel):
    node: NODE_NAME
    protocol: PROTOCOLS
    network: NETWORKS = "tcp"
    security: SECURITY = "none"
    port: PORT


class ChainCreate(BaseModel):
    # название цепочки пользователь видит как имя хоста — кириллица тоже нормальна
    name: Annotated[str, Field(min_length=2, max_length=48, pattern=r"^[^\x00-\x1f<>\"']+$")]
    hops: list[Hop] = Field(min_length=2, max_length=6)


class SettingsPatch(BaseModel):
    panelName: str | None = Field(default=None, min_length=1, max_length=32)
    theme: Literal["auto", "light", "dark"] | None = None
    subUrl: str | None = Field(default=None, max_length=255)
    subTitle: str | None = Field(default=None, min_length=1, max_length=48)
    subInterval: int | None = Field(default=None, ge=1, le=168)
    pollInterval: int | None = Field(default=None, ge=5, le=3600)
    nodeTimeout: int | None = Field(default=None, ge=2, le=120)
    sessionHours: int | None = Field(default=None, ge=1, le=720)
    passkeyEnabled: bool | None = None


class AdminCreate(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.\-]+$")
    password: str = Field(min_length=8, max_length=128)
    role: Literal["admin", "viewer"] = "admin"


class AdminPatch(BaseModel):
    status: STATUS | None = None
    role: Literal["admin", "viewer"] | None = None
    password: Annotated[str | None, Field(min_length=8, max_length=128)] = None


class FidoLogin(BaseModel):
    """Ответ аппарата на вызов входа: PublicKeyCredential, переводённый в base64url."""
    response: dict[str, Any]


class FidoKeyAdd(BaseModel):
    """Ответ аппарата на вызов записи ключа. `nickname` — как человек назвал ключ."""
    response: dict[str, Any]
    nickname: Annotated[str | None, Field(max_length=32)] = None


class FidoBegin(BaseModel):
    """Необязательное имя: тогда панель предложит только ключи этого администратора."""
    username: Annotated[str | None, Field(min_length=3, max_length=32)] = None

