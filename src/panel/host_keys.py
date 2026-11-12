"""Ключи и сертификаты, которые выпускает сама панель.

Две разные вещи:

* `new_reality_keys` — пара x25519 для reality-хоста: приватный ключ едет в конфиг ноде,
  публичный — в ссылку подписки. Формат — base64url без дополнения, как у `xray x25519`.
* `new_hop_certificate` — самоподписанный сертификат **хопа цепочки**. Его выпускает панель,
  а не нода, и вот зачем: сертификат ноды-приёмника обязан знать соседний узел, которому
  по этому хопу идти, — Xray 26 выбросил `allowInsecure` и самоподписанный сертификат
  «на веру» не принимает, ему нужен отпечаток (`pinnedPeerCertSha256`). Если бы сертификат
  выпускала нода, панели пришлось бы сначала применить конфиг на одной ноде, выведать у неё
  отпечаток и только потом собирать конфиг соседней. Выпуская сертификат сама, панель знает
  отпечаток в момент сборки обоих конфигов.

Своей CA у панели нет — как и у домашней панели вообще. Reality от роли «шифрование без
сертификатов» не отменяется: для хостов подписчика он по-прежнему предпочтительнее.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from cryptography.x509.oid import NameOID

CERT_YEARS = 10


def new_reality_keys() -> tuple[str, str]:
    private = x25519.X25519PrivateKey.generate()
    raw = lambda data: base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    return (raw(private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
            raw(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)))


def new_hop_certificate(name: str) -> tuple[str, str, str]:
    """Самоподписанный сертификат хопа: (pem сертификата, pem закрытого ключа, sha256 DER).

    Имя в сертификате — то, что назовёт клиент в SNI: sni хоста цепочки, а если его нет —
    адрес ноды этого хопа. Домен идёт DNS-именем, адрес — IP SAN, как и в сертификатах,
    которые нода выпускает обычным хостам.
    """
    value = (name or "").strip() or "localhost"
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value[:64])])
    try:
        alt_name = x509.IPAddress(ipaddress.ip_address(value))
    except ValueError:
        alt_name = x509.DNSName(value)
    moment = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(moment - datetime.timedelta(days=1))
            .not_valid_after(moment + datetime.timedelta(days=365 * CERT_YEARS))
            .add_extension(x509.SubjectAlternativeName([alt_name]), critical=False)
            .sign(key, hashes.SHA256()))
    pem_cert = cert.public_bytes(Encoding.PEM).decode("ascii")
    pem_key = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode("ascii")
    return pem_cert, pem_key, hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()
