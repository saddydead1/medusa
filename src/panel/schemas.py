"""Формы запросов API: то, что принимает панель."""
from __future__ import annotations

from typing import Any, Annotated, Literal

from pydantic import BaseModel, Field

NAME = Annotated[str, Field(min_length=2, max_length=32, pattern=r"^[A-Za-z0-9_.\-]+$")]
PORT = Annotated[int, Field(ge=1, le=65535)]
# IPv4/IPv6/домен — один и тот же алфавит и у адреса ноды, и у адреса хоста
ADDRESS_PATTERN = r"^[A-Za-z0-9._:\-\[\]]+$"
# те же адреса, но пустое значение разрешено: пустая строка в PATCH означает
# «сбросить к разумному по умолчанию»
ADDR_OR_EMPTY = r"^[A-Za-z0-9._:\-\[\]]*$"
# sni — домен без порта; список sni для reality — домены через запятую
SNI_PATTERN = r"^[A-Za-z0-9.\-\[\]]*$"
SNI_LIST_PATTERN = r"^[A-Za-z0-9.\-\[\], ]*$"
# путь к файлу на ноде: только латиница, цифры и служебные символы пути
FILE_PATH_PATTERN = r"^[/A-Za-z0-9._+\-]*$"
ADDRESS = Annotated[str, Field(min_length=4, max_length=63, pattern=ADDRESS_PATTERN)]
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
    # адрес, к которому подключается подписчик (домен или IP ноды наружу);
    # пусто — значит подключаться к адресу ноды, он же у панели для своей связи
    address: Annotated[str | None, Field(min_length=4, max_length=63, pattern=ADDRESS_PATTERN)] = None
    # поля защиты: каждое живёт только со своей защитой (проверка в роутере);
    # пустая строка — сброс к значению по умолчанию
    dest: Annotated[str | None, Field(max_length=63, pattern=ADDR_OR_EMPTY)] = None
    # отпечаток клиента (utls): куда нода притворяется браузером; работает и у
    # reality, и у tls — пустой Literal не разрешён именно поэтому
    fp: Literal["chrome", "edge", "safari", "firefox", "android", "ios"] | None = None
    rejectUnknownSni: bool | None = None
    # tls: sni и пути к своим сертификатам
    sni: Annotated[str | None, Field(max_length=253, pattern=SNI_PATTERN)] = None
    certFile: Annotated[str | None, Field(max_length=255, pattern=FILE_PATH_PATTERN)] = None
    keyFile: Annotated[str | None, Field(max_length=255, pattern=FILE_PATH_PATTERN)] = None
    # reality: какие sni он принимает (пусто — адрес хоста)
    serverNames: Annotated[str | None, Field(max_length=255, pattern=SNI_LIST_PATTERN)] = None
    # транспортные детали: путь и Host у websocket; имя сервиса и authority у gRPC
    path: Annotated[str | None, Field(max_length=256)] = None
    hostHeader: Annotated[str | None, Field(max_length=63, pattern=ADDR_OR_EMPTY)] = None
    serviceName: Annotated[str | None, Field(max_length=64)] = None
    grpcAuthority: Annotated[str | None, Field(max_length=63, pattern=ADDR_OR_EMPTY)] = None


class HostPatch(BaseModel):
    """Правка хоста: то же, что при создании, но всё необязательное —
    панель меняет только то, что принесли."""
    name: Annotated[str | None, Field(min_length=2, max_length=48)] = None
    node: NODE_NAME | None = None
    address: Annotated[str | None, Field(min_length=4, max_length=63, pattern=ADDRESS_PATTERN)] = None
    protocol: PROTOCOLS | None = None
    port: PORT | None = None
    network: NETWORKS | None = None
    security: SECURITY | None = None
    dest: Annotated[str | None, Field(max_length=63, pattern=ADDR_OR_EMPTY)] = None
    fp: Literal["chrome", "edge", "safari", "firefox", "android", "ios"] | None = None
    rejectUnknownSni: bool | None = None
    sni: Annotated[str | None, Field(max_length=253, pattern=SNI_PATTERN)] = None
    certFile: Annotated[str | None, Field(max_length=255, pattern=FILE_PATH_PATTERN)] = None
    keyFile: Annotated[str | None, Field(max_length=255, pattern=FILE_PATH_PATTERN)] = None
    serverNames: Annotated[str | None, Field(max_length=255, pattern=SNI_LIST_PATTERN)] = None
    path: Annotated[str | None, Field(max_length=256)] = None
    hostHeader: Annotated[str | None, Field(max_length=63, pattern=ADDR_OR_EMPTY)] = None
    serviceName: Annotated[str | None, Field(max_length=64)] = None
    grpcAuthority: Annotated[str | None, Field(max_length=63, pattern=ADDR_OR_EMPTY)] = None


class Hop(BaseModel):
    node: NODE_NAME
    protocol: PROTOCOLS
    network: NETWORKS = "tcp"
    security: SECURITY = "none"
    port: PORT
    # адрес, на который соседняя нода цепочки придёт к этому hopу. Пусто — адрес ноды:
    # у ноды он один и тот же для связи с панелью и для подписчиков, а на машине ноды
    # хост может жить на другом имени (домен наружу, VLAN, несколько адресов).
    # Пустая строка здесь разрешена: пусто значит «адрес ноды» (у обычного хоста пустого
    # адреса нет — там он либо назван, либо отсутствует)
    address: Annotated[str | None, Field(max_length=63, pattern=ADDR_OR_EMPTY)] = None


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


class AdminPatch(BaseModel):
    status: STATUS | None = None
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

