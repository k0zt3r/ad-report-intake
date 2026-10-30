"""Чтение отчётов и детерминированная оценка AD без модели и сети."""

from __future__ import annotations

import hashlib
import re
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_EXTRACTED_CHARS = 500_000
SCHEMA_VERSION = "1.0"

FEATURES = {
    "dc_os": ("Контроллеры домена", "Поддержка ОС контроллеров"),
    "dc_updates": ("Контроллеры домена", "Контроль обновлений"),
    "dc_access": ("Контроллеры домена", "Ограничение доступа к контроллерам"),
    "admin_accounts": ("Привилегии", "Раздельные учётные записи администраторов"),
    "admin_workstations": ("Привилегии", "Защищённые АРМ администраторов"),
    "remote_mfa": ("Удалённый доступ", "MFA при удалённом администрировании"),
    "remote_scope": ("Удалённый доступ", "Ограничение удалённого доступа"),
    "dc_segmentation": ("Сеть", "Изоляция контроллеров домена"),
    "network_rules": ("Сеть", "Контроль межсегментных правил"),
    "ad_backup": ("Восстановление", "Резервные копии AD"),
    "restore_test": ("Восстановление", "Проверка восстановления AD"),
}

GROUPS = {
    "Контроллеры домена": ["dc_os", "dc_updates", "dc_access"],
    "Привилегии": ["admin_accounts", "admin_workstations"],
    "Удалённый доступ": ["remote_mfa", "remote_scope"],
    "Сеть": ["dc_segmentation", "network_rules"],
    "Восстановление": ["ad_backup", "restore_test"],
}

SCENARIOS = {
    "Доступ к контроллеру через рабочую станцию":
        ["dc_os", "dc_updates", "dc_access", "admin_workstations", "dc_segmentation"],
    "Захват AD через удалённого администратора":
        ["remote_mfa", "remote_scope", "admin_accounts", "dc_access"],
    "Восстановление после компрометации AD": ["ad_backup", "restore_test"],
}

# Правила намеренно узкие. Одно упоминание меры ещё не доказывает её внедрение.
# Для каждого признака отрицательные правила идут перед положительными.
RULES: dict[str, list[tuple[float, str, str]]] = {
    "dc_os": [
        (0, r"(?:контроллер\w* домен\w*|domain controller|\bкд\b).{0,90}windows server\s*2012(?:\s*r2)?\b", "Контроллер домена на Windows Server 2012"),
        (0.5, r"(?:контроллер\w* домен\w*|domain controller|\bкд\b).{0,90}windows server\s*(?:2016|2019|2022|2025)\b", "Версия ОС контроллера указана; статус обновлений проверяется отдельно"),
    ],
    "dc_updates": [
        (0, r"(?:обновлени\w*|патч\w*).{0,50}(?:не устанавлива|отсутству|не выполня)", "Обновления не устанавливаются"),
        (1, r"(?:обновлени\w*|патч\w*).{0,65}(?:регулярно устанавлива|контролирую|проверяю)", "Указан контроль установки обновлений"),
    ],
    "dc_access": [
        (0, r"(?:контроллер\w* домен\w*|\bкд\b).{0,70}(?:доступн\w* с люб\w*|доступн\w* со всех|без ограничен)", "Широкий доступ к контроллерам"),
        (1, r"(?:доступ к контроллер\w* домен\w*|доступ к \bкд\b).{0,80}(?:огранич\w*|только с выделенн)", "Доступ к контроллерам ограничен"),
    ],
    "admin_accounts": [
        (0, r"(?:администратор\w*|админ\w*).{0,75}(?:повседневн\w*|обычн\w* задач\w*).{0,25}(?:уч[её]тн\w* запис|аккаунт)", "Привилегированная запись используется повседневно"),
        (1, r"(?:отдельн\w*|раздельн\w*|выделенн\w*).{0,35}(?:уч[её]тн\w* запис\w*|аккаунт\w*).{0,35}администратор", "Выделены административные учётные записи"),
        (1, r"администратор\w*.{0,55}(?:отдельн\w*|раздельн\w*|выделенн\w*).{0,35}уч[её]тн\w* запис", "Выделены административные учётные записи"),
    ],
    "admin_workstations": [
        (0, r"(?:администрирован\w*|администратор\w*).{0,60}(?:с обычн\w* арм|с рабочих станц\w* пользовател)", "Администрирование с обычных АРМ"),
        (1, r"(?:выделенн\w*|защищ[её]нн\w*).{0,35}(?:арм|рабоч\w* станц\w*).{0,35}администратор", "Выделены АРМ администраторов"),
        (1, r"администратор\w*.{0,55}(?:выделенн\w*|защищ[её]нн\w*).{0,35}(?:арм|рабоч\w* станц)", "Выделены АРМ администраторов"),
    ],
    "remote_mfa": [
        (0, r"(?:удал[её]нн\w*|vpn|rdp).{0,70}(?:mfa не|без mfa|многофакторн\w* аутентификац\w* не|без многофакторн)", "Удалённый доступ без MFA"),
        (1, r"(?:удал[её]нн\w*|vpn|rdp).{0,70}mfa (?:включен\w*|обязател\w*).{0,35}(?:всех администратор|кажд\w* администратор)", "MFA указана для всех администраторов"),
        (0.5, r"(?:удал[её]нн\w*|vpn|rdp).{0,70}(?:mfa (?:включен|обязател)|многофакторн\w* аутентификац\w* обязательн)", "MFA указана, охват администраторов неизвестен"),
    ],
    "remote_scope": [
        (0, r"(?:удал[её]нн\w* доступ|vpn|rdp).{0,65}(?:без ограничен|ко всем узлам|во всю сеть)", "Удалённый доступ без ограничений"),
        (1, r"(?:удал[её]нн\w* доступ|vpn|rdp).{0,65}(?:ограничен|только к|по ролям)", "Удалённый доступ ограничен"),
    ],
    "dc_segmentation": [
        (0, r"(?:сеть|контроллер\w* домен\w*).{0,60}(?:не сегментирован|без сегментац|плоск\w* сеть)", "Сеть без сегментации"),
        (1, r"(?:контроллер\w* домен\w*|\bкд\b).{0,70}(?:выделен\w* сегмент|изолирован|отдельн\w* vlan)", "Контроллеры изолированы"),
    ],
    "network_rules": [
        (0, r"(?:межсегментн\w*|между сегментами).{0,60}(?:не ограничен|без правил|разрешен\w* все)", "Межсегментные соединения не ограничены"),
        (1, r"(?:межсегментн\w*|между сегментами).{0,60}(?:правил\w* проверен|соединен\w* ограничен)", "Указаны проверенные межсегментные правила"),
    ],
    "ad_backup": [
        (0, r"(?:резервн\w* копи\w*|бэкап\w*).{0,50}(?:ad|active directory|домен\w*).{0,30}(?:нет|отсутству|не созда)", "Нет резервных копий AD"),
        (1, r"(?:резервн\w* копи\w*|бэкап\w*).{0,50}(?:ad|active directory|домен\w*).{0,35}(?:ежедневн|регулярн|актуальн)", "Указаны актуальные резервные копии AD"),
        (0.5, r"(?:резервн\w* копи\w*|бэкап\w*).{0,50}(?:ad|active directory|домен\w*)", "Копии AD упомянуты; актуальность неизвестна"),
    ],
    "restore_test": [
        (0, r"(?:восстановлен\w*).{0,70}(?:не проверял|не тестировал|не проводил)", "Восстановление не проверялось"),
        (1, r"(?:восстановлен\w*).{0,70}(?:регулярно проверя|успешно провер|тестирован\w* успешно)", "Указана проверка восстановления"),
    ],
}


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _read_text(data: bytes) -> list[dict[str, str]]:
    try:
        content = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        content = data.decode("cp1251")
    return [{"locator": f"строка {n}", "text": _clean(line)}
            for n, line in enumerate(content.splitlines(), 1) if _clean(line)]


def _read_docx(data: bytes) -> list[dict[str, str]]:
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            info = archive.getinfo("word/document.xml")
            if info.file_size > MAX_EXTRACTED_CHARS * 8:
                raise ValueError("Слишком большой текст DOCX")
            root = ET.fromstring(archive.read(info))
    except (zipfile.BadZipFile, KeyError, ET.ParseError) as exc:
        raise ValueError("Не удалось прочитать DOCX") from exc
    ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    units = []
    for n, p in enumerate(root.findall(".//w:p", ns), 1):
        line = _clean("".join(t.text or "" for t in p.findall(".//w:t", ns)))
        if line:
            units.append({"locator": f"абзац {n}", "text": line})
    return units


def _read_pdf(data: bytes) -> list[dict[str, str]]:
    try:
        import pymupdf
    except ImportError as exc:
        raise ValueError("Для PDF установите PyMuPDF: pip install pymupdf") from exc
    units = []
    try:
        with pymupdf.open(stream=data, filetype="pdf") as doc:
            for page_number, page in enumerate(doc, 1):
                for line_number, line in enumerate(page.get_text().splitlines(), 1):
                    if _clean(line):
                        units.append({"locator": f"стр. {page_number}, строка {line_number}", "text": _clean(line)})
    except RuntimeError as exc:
        raise ValueError("Не удалось прочитать PDF") from exc
    if not units:
        raise ValueError("В PDF нет извлекаемого текста. Сканированному отчёту потребуется OCR.")
    return units


def read_report(name: str, data: bytes) -> tuple[list[dict[str, str]], dict[str, Any]]:
    if not data or len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("Размер файла должен быть от 1 байта до 10 МБ")
    suffix = Path(name).suffix.lower()
    if suffix in (".txt", ".md"):
        units = _read_text(data)
    elif suffix == ".docx":
        units = _read_docx(data)
    elif suffix == ".pdf":
        units = _read_pdf(data)
    else:
        raise ValueError("Поддерживаются TXT, MD, DOCX и текстовые PDF")
    if sum(len(unit["text"]) for unit in units) > MAX_EXTRACTED_CHARS:
        raise ValueError("В отчёте слишком много текста")
    return units, {"name": Path(name).name, "sha256": hashlib.sha256(data).hexdigest(),
                   "units": len(units), "characters": sum(len(u["text"]) for u in units)}


def extract_observations(units: list[dict[str, str]]) -> dict[str, dict[str, Any]]:
    found: dict[str, list[dict[str, Any]]] = {key: [] for key in FEATURES}
    for unit in units:
        text = unit["text"]
        for key, rules in RULES.items():
            for score, pattern, reason in rules:
                if re.search(pattern, text, re.IGNORECASE):
                    found[key].append({"value": score, "reason": reason,
                                       "locator": unit["locator"], "excerpt": text[:300]})
                    break
    observations = {}
    for key in FEATURES:
        hits = found[key][:5]
        values = {hit["value"] for hit in found[key]}
        if len(values) == 1:
            value, status = next(iter(values)), "known"
        elif len(values) > 1:
            value, status = None, "conflict"
        else:
            value, status = None, "unknown"
        observations[key] = {"value": value, "status": status,
                             "method": "rule" if hits else "none", "evidence": hits}
    return observations


def extract_context(units: list[dict[str, str]]) -> dict[str, Any]:
    inventory: dict[str, list[dict[str, Any]]] = {"workstations": [], "remote_hosts": []}
    patterns = {
        "workstations": r"\b(\d{1,5})\s*(?:арм\b|рабоч\w* станц\w*)",
        "remote_hosts": r"\b(\d{1,5})\s*удал[её]нн\w*\s+хост\w*",
    }
    for unit in units:
        for key, pattern in patterns.items():
            for match in re.finditer(pattern, unit["text"], re.IGNORECASE):
                inventory[key].append({"count": int(match.group(1)),
                                       "locator": unit["locator"], "excerpt": unit["text"][:300]})
    return {"inventory": inventory, "authorized_scope": None,
            "scope_note": "Границы разрешённого тестирования задаются отдельно; из описания ИС не выводятся"}


def score_ids(ids: list[str], observations: dict[str, dict[str, Any]]) -> dict[str, Any]:
    applicable = [key for key in ids if observations[key]["status"] != "not_applicable"]
    if not applicable:
        return {"status": "not_applicable", "lower": None, "upper": None,
                "limiting": [], "unknown": []}
    known = [key for key in applicable if observations[key]["status"] == "known"]
    unknown = [key for key in applicable if observations[key]["status"] != "known"]
    upper = min((observations[key]["value"] for key in known), default=1)
    lower = 0 if unknown else upper
    limiting = [key for key in known if observations[key]["value"] == upper]
    return {"status": "interval" if lower != upper else "exact", "lower": lower,
            "upper": upper, "limiting": limiting, "unknown": unknown}


def evaluate(observations: dict[str, dict[str, Any]]) -> dict[str, Any]:
    validated = {}
    for key in FEATURES:
        item = observations.get(key, {"status": "unknown", "value": None})
        status, value = item.get("status"), item.get("value")
        if status not in ("known", "unknown", "conflict", "not_applicable"):
            raise ValueError(f"Неверный статус признака {key}")
        if status == "known" and (type(value) not in (int, float) or value not in (0, 0.5, 1)):
            raise ValueError(f"Неверная оценка признака {key}")
        validated[key] = {**item, "status": status, "value": value if status == "known" else None}
    vector = {name: score_ids(ids, validated) for name, ids in GROUPS.items()}
    scenarios = {}
    for name, ids in SCENARIOS.items():
        if name == "Захват AD через удалённого администратора" and any(
            validated[key]["status"] == "not_applicable" for key in ("remote_mfa", "remote_scope")
        ):
            scenarios[name] = {"status": "not_applicable", "lower": None,
                               "upper": None, "limiting": [], "unknown": []}
        else:
            scenarios[name] = score_ids(ids, validated)
    return {"vector": vector, "scenarios": scenarios}


def analyze(name: str, data: bytes) -> dict[str, Any]:
    units, source = read_report(name, data)
    observations = extract_observations(units)
    return {"schema_version": SCHEMA_VERSION, "source": source, "context": extract_context(units),
            "features": {key: {"group": group, "title": title}
                         for key, (group, title) in FEATURES.items()},
            "observations": observations, "evaluation": evaluate(observations)}
