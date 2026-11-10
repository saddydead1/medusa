"""Раннер Xray на ноде: применить конфиг панели и держать процесс.

Нода не понимает смысл конфига — она его исполняет. Порядок применения такой, чтобы
плохой конфиг не мог уронить сервис:

1. новый конфиг пишется рядом (`config.new.json`), а не поверх рабочего;
2. недостающие tls-сертификаты выпускаются заранее (у panel-ных хостов self-signed,
   клиент должен быть готов их принимать — reality от этого защищает и лучше reality);
3. старый процесс останавливается, новый проверяется самим Xray (`xray -test`);
4. проверка прошла — конфиг становится рабочим, Xray поднимается;
5. не прошла — рабочий конфиг остаётся прежним, нода честно сообщает ошибку.

Без инбаундов Xray не поднимается вовсе: пустой конфиг — это «хостов нет», а не «сервис
сломан». Процесс живёт в файле состояния рядом с конфигом; при перезапуске ноды
рабочий конфиг поднимается снова.
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from src.core.contract import NodeApplyReport
from src.node.config import NodeConfig
from src.node.identity import NodeIdentity, now_ms, save_identity
from src.node.xray import resolve_xray_bin, xray_version

CONFIG_FILE = "config.json"
PENDING_FILE = "config.new.json"
TEST_TIMEOUT_SECONDS = 25
STOP_GRACE_SECONDS = 5


def _self_signed(host_value: str, crt_path: Path, key_path: Path) -> None:
    """Self-signed сертификат на адрес хоста: домен — DNS, адрес — IP.

    Для домашней панели это честный потолок: своей CA нет, и клиенту надо явно
    разрешить такой сертификат (skip-verify в приложении). Reality играет ту же роль
    без сертификатов вообще — он и нужен там, где клиент строгий.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host_value[:64])])
    try:
        subject_alt = x509.IPAddress(ipaddress.ip_address(host_value))
    except ValueError:
        subject_alt = x509.DNSName(host_value)
    moment = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(moment - datetime.timedelta(days=1))
            .not_valid_after(moment + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([subject_alt]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(key_path, 0o600)
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


class XrayRunner:
    def __init__(self, config: NodeConfig, identity: NodeIdentity) -> None:
        self.config = config
        self.identity = identity
        self.dir = config.state_path.parent / "xray"
        self.config_path = self.dir / CONFIG_FILE
        self.log_path = self.dir / "xray.log"
        self.proc: subprocess.Popen | None = None

    # ---------- файлы ----------

    def _ensure_dir(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass

    def _write(self, path: Path, payload: dict) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)          # в конфиге приватные ключи: права решающие
        os.replace(tmp, path)
        os.chmod(path, 0o600)

    # ---------- сертификатные пути ----------

    def _absolutize_certs(self, payload: dict) -> dict:
        """Xray разрешает относительные пути файлов не от папки конфига, а от папки
        бинарника — историческая традиция geoip.dat. Панель отдаёт сертификаты
        относительными (`certs/host-N.crt`), поэтому перед записью нода превращает
        их в абсолютные пути своей рабочей папки. Иначе `xray -test` ищет ключ
        рядом с самим Xray и честно его не находит."""
        fixed = dict(payload)
        inbounds = []
        for inbound in fixed.get("inbounds", []):
            tls = (inbound.get("streamSettings") or {}).get("tlsSettings")
            if not tls or not tls.get("certificates"):
                inbounds.append(inbound)
                continue
            inbound = dict(inbound)
            tls = dict(tls)
            certs = []
            for cert in tls["certificates"]:
                cert = dict(cert)
                for field in ("certificateFile", "keyFile"):
                    value = cert.get(field) or ""
                    if value and not Path(value).is_absolute():
                        cert[field] = str(self.dir / value)
                certs.append(cert)
            tls["certificates"] = certs
            inbound["streamSettings"] = dict(inbound["streamSettings"], tlsSettings=tls)
            inbounds.append(inbound)
        fixed["inbounds"] = inbounds
        return fixed

    # ---------- сертификаты ----------

    def _ensure_certs(self, hints: list[dict]) -> str | None:
        """Выпускает недостающие tls-сертификаты. Возвращает текст проблемы или None.

        Панель просит сертификат на адрес хоста: домен — DNS-имя, адрес — IP.
        Self-signed — сознательный выбор домашней панели: своей CA у неё нет, а reality
        вообще живёт без сертификатов.
        """
        certs_dir = self.dir / "certs"
        certs_dir.mkdir(parents=True, exist_ok=True)
        for hint in hints:
            crt, key = self.dir / hint["file"], self.dir / hint["key"]
            if crt.exists() and key.exists():
                continue
            try:
                _self_signed(hint["host"], crt, key)
            except Exception as err:  # noqa: BLE001 — причину пишем человеку в отчёт
                return f"сертификат {hint['file']} выпустить не вышло: {err}"
        return None

    # ---------- процесс ----------

    def _stop(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            self.proc = None
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=STOP_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=STOP_GRACE_SECONDS)
        self.proc = None

    def _start(self) -> str | None:
        try:
            log = open(self.log_path, "ab")
            self.proc = subprocess.Popen(
                [self._bin(), "-config", CONFIG_FILE], cwd=self.dir, stdout=log, stderr=log)
        except OSError as err:
            self.proc = None
            return f"Xray не запустился: {err}"
        return None

    def _bin(self) -> str:
        # bin уже проверен в apply; здесь он обязан быть
        return resolve_xray_bin(self.config) or ""

    def _test(self, path: Path) -> tuple[bool, str]:
        try:
            done = subprocess.run([self._bin(), "-test", "-config", str(path)],
                                  cwd=self.dir, capture_output=True, text=True, timeout=TEST_TIMEOUT_SECONDS)
        except (OSError, subprocess.SubprocessError) as err:
            return False, f"проверка конфига не состоялась: {err}"
        if done.returncode == 0:
            return True, ""
        text = (done.stderr or done.stdout or "").strip().splitlines()
        return False, text[-1] if text else f"Xray отверг конфиг (код {done.returncode})"

    # ---------- жизненный цикл ----------

    def autostart(self) -> None:
        """Перезапуск ноды: рабочий конфиг поднимается сам, ничего не ждём."""
        self._ensure_dir()
        if not self.config_path.exists():
            return
        if not resolve_xray_bin(self.config):
            self.identity.last_error = "на ноде нет бинарника xray — рабочий конфиг поднят не был"
            save_identity(self.identity)
            return
        problem = self._start()
        print(f"[medusa-node] автоподъём Xray: {problem or f'рабочий конфиг rev {self.identity.applied_rev}'}", flush=True)

    def shutdown(self) -> None:
        self._stop()

    def note_process_state(self) -> None:
        """Перед ответом о статусе проверяем, жив ли процесс: мёртвый Xray не должен
        прятаться за «применено»."""
        if self.proc is not None and self.proc.poll() is not None:
            code = self.proc.poll()
            self.proc = None
            self.identity.last_error = f"Xray завершился с кодом {code}: детали в {self.log_path}"
            save_identity(self.identity)

    # ---------- применение ----------

    def apply(self, revision: int, payload: dict, cert_hints: list[dict]) -> NodeApplyReport:
        self.identity.desired_rev = revision
        xray_bin = resolve_xray_bin(self.config)
        if not xray_bin:
            return self._finish(revision, ok=False, error="на ноде нет бинарника xray (MEDUSA_XRAY_BIN или PATH)")

        self._ensure_dir()
        pending = self.dir / PENDING_FILE
        self._write(pending, self._absolutize_certs(payload))

        cert_problem = self._ensure_certs(cert_hints)
        if cert_problem:
            pending.unlink(missing_ok=True)
            return self._finish(revision, ok=False, error=cert_problem)

        self._stop()

        if not payload.get("inbounds"):
            # хостов нет — Xray нечему слушать; это не ошибка, сервис просто не нужен
            pending.replace(self.config_path)
            os.chmod(self.config_path, 0o600)
            return self._finish(revision, ok=True, error=None)

        ok, message = self._test(pending)
        if not ok:
            pending.unlink(missing_ok=True)
            if self.config_path.exists():
                self._start()          # рабочий конфиг не тронут — возвращаем сервис
            return self._finish(revision, ok=False, error=f"Xray отверг новый конфиг: {message}")

        pending.replace(self.config_path)
        os.chmod(self.config_path, 0o600)
        problem = self._start()
        if problem:
            return self._finish(revision, ok=False, error=problem)
        return self._finish(revision, ok=True, error=None)

    def _finish(self, revision: int, ok: bool, error: str | None) -> NodeApplyReport:
        moment = now_ms()
        self.identity.last_apply_at = moment
        self.identity.last_error = error
        if ok:
            self.identity.applied_rev = revision
        save_identity(self.identity)
        return NodeApplyReport(
            fingerprint=self.identity.fingerprint,
            ok=ok,
            desiredRev=revision,
            appliedRev=self.identity.applied_rev,
            lastApplyAt=moment,
            xrayVersion=xray_version(self.config),
            error=error,
        )
