"""Clasificación verificable de servicios de Windows (Fase 7B-Fix1).

Problema real (ravenslg): Windows crea una instancia de cada servicio por usuario al iniciar
sesión (WpnUserService_6df11, OneSyncSvc_6df11...). El inventario la ve como "servicio
nuevo" y, junto a un 4104 cercano, CORR-002 la presentaba como persistencia. Esa instancia
no es una instalación.

Aquí se decide qué es un servicio con lo que se puede comprobar, nunca solo por el nombre:

- `installed`: lo registra el evento 7045 del SCM (instalación verificable);
- `user_service_instance`: instancia por usuario. Se exige todo esto para `verified`:
  - nombre `<plantilla>_<sufijo hex>` y la plantilla existe en el mismo inventario;
  - el tipo del registro lleva el bit SERVICE_USERSERVICE_INSTANCE (0x80);
  - el ejecutable es exactamente %SystemRoot%\\System32\\svchost.exe;
  - si la plantilla informa de su grupo (-k), es el mismo;
  - la firma Authenticode del ejecutable es válida y de Microsoft.
  Con agentes anteriores a 0.6.2 (sin tipo, ruta ni firma) solo puede quedar `probable`.
  Un nombre de instancia con otro ejecutable, sin el bit o con firma inválida es
  `suspicious`: alguien usa la forma del nombre para esconderse;
- `modified`: el ImagePath de un servicio existente cambió entre dos inventarios;
- `discovered`: apareció en el inventario sin evento 7045 (puede ser una instalación o algo
  que ya existía y el agente no veía).

Funciones puras: sin base de datos, para probar cada caso.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

SERVICE_USER_SERVICE = 0x40
SERVICE_USERSERVICE_INSTANCE = 0x80

INSTALLED = "installed"
USER_INSTANCE = "user_service_instance"
MODIFIED = "modified"
DISCOVERED = "discovered"

VERIFIED = "verified"
PROBABLE = "probable"
UNVERIFIED = "unverified"
SUSPICIOUS = "suspicious"

PASS, FAIL, MISSING = "pass", "fail", "missing"

_INSTANCE_NAME = re.compile(r"^(?P<template>[A-Za-z][A-Za-z0-9]{2,})_(?P<suffix>[0-9a-fA-F]{4,8})$")
_GROUP = re.compile(r"\s-k\s+(?P<group>\S+)", re.IGNORECASE)
_SVCHOST = "\\windows\\system32\\svchost.exe"
# Firmantes de los binarios del sistema (Subject del certificado de Get-AuthenticodeSignature).
_MICROSOFT_SIGNER = re.compile(r"O=Microsoft Corporation\b", re.IGNORECASE)


@dataclass(frozen=True)
class Check:
    code: str
    result: str
    detail: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {"code": self.code, "result": self.result, "detail": self.detail}


@dataclass(frozen=True)
class ServiceClass:
    kind: str
    verification: str
    template: str | None = None
    session_suffix: str | None = None
    checks: tuple[Check, ...] = field(default_factory=tuple)
    explanation: str = ""

    @property
    def legitimate_user_instance(self) -> bool:
        """Instancia por usuario demostrada (o probable con agente antiguo)."""
        return self.kind == USER_INSTANCE and self.verification in (VERIFIED, PROBABLE)

    @property
    def suspicious(self) -> bool:
        return self.verification == SUSPICIOUS

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "verification": self.verification,
            "template": self.template,
            "session_suffix": self.session_suffix,
            "checks": [c.to_json() for c in self.checks],
            "explanation": self.explanation,
        }


def instance_name(name: str) -> tuple[str, str] | None:
    """(plantilla, sufijo) si el nombre tiene la forma de una instancia por usuario."""
    match = _INSTANCE_NAME.match(name.strip())
    if match is None:
        return None
    return match.group("template"), match.group("suffix").lower()


def normalize_image(path: str | None) -> str | None:
    """Ruta comparable: minúsculas, sin comillas, %SystemRoot% y \\SystemRoot\\ resueltos."""
    if not path:
        return None
    text = path.strip().strip('"').lower().replace("/", "\\")
    for prefix in ("%systemroot%", "%windir%", "\\systemroot"):
        if text.startswith(prefix):
            text = "c:\\windows" + text[len(prefix) :]
    if text.startswith("\\??\\"):
        text = text[4:]
    return text


def is_system_svchost(path: str | None) -> bool:
    """¿Es el svchost.exe de System32? Solo la ruta exacta: un svchost.exe en otra carpeta
    es el disfraz clásico de un malware."""
    image = normalize_image(path)
    return image is not None and len(image) > 2 and image[1] == ":" and image[2:] == _SVCHOST


def service_group(binpath: str | None) -> str | None:
    match = _GROUP.search(binpath or "")
    return match.group("group").lower() if match else None


def signature_check(signature: Any) -> Check:
    if not isinstance(signature, Mapping) or not signature.get("status"):
        return Check("signature", MISSING, "El agente no informó de la firma del ejecutable.")
    status = str(signature.get("status"))
    signer = str(signature.get("signer") or "")
    if status.lower() != "valid":
        return Check("signature", FAIL, f"Firma {status}.")
    if not _MICROSOFT_SIGNER.search(signer):
        return Check("signature", FAIL, f"Firma válida de otro emisor: {signer[:120]}.")
    return Check("signature", PASS, signer[:120])


def classify_inventory_service(
    name: str, info: Mapping[str, Any], inventory: Mapping[str, Mapping[str, Any]]
) -> ServiceClass:
    """Clasifica un servicio que apareció en el inventario.

    `inventory` son todos los servicios del mismo snapshot por nombre en minúsculas: la
    plantilla y las demás instancias de la misma sesión se buscan ahí.
    """
    parts = instance_name(name)
    if parts is None:
        return ServiceClass(
            DISCOVERED,
            UNVERIFIED,
            explanation=(
                "Apareció en el inventario sin evento 7045: no se sabe quién lo instaló ni"
                " cuándo exactamente (el inventario solo acota el momento)."
            ),
        )
    template_name, suffix = parts
    template = inventory.get(template_name.lower())
    checks: list[Check] = []
    checks.append(
        Check("template", PASS, template_name)
        if template is not None
        else Check("template", FAIL, f"No existe la plantilla {template_name} en el inventario.")
    )
    peers = sorted(
        other
        for other in inventory
        if other != name.lower()
        and (p := instance_name(other)) is not None
        and p[1] == suffix
        and p[0].lower() in inventory
    )
    checks.append(
        Check("session_peers", PASS, f"{len(peers)} instancia(s) más de la sesión _{suffix}")
        if peers
        else Check("session_peers", MISSING, "Ninguna otra instancia comparte el sufijo.")
    )
    kind = info.get("service_type")
    if isinstance(kind, int):
        checks.append(
            Check("service_type", PASS, hex(kind))
            if kind & SERVICE_USERSERVICE_INSTANCE
            else Check("service_type", FAIL, f"Tipo {hex(kind)} sin el bit de instancia (0x80).")
        )
    else:
        checks.append(Check("service_type", MISSING, "Agente sin tipo de servicio (< 0.6.2)."))
    image = info.get("image") or info.get("image_path")
    if image:
        checks.append(
            Check("host_image", PASS, str(image))
            if is_system_svchost(str(image))
            else Check("host_image", FAIL, f"Ejecutable {image}, no el svchost.exe de System32.")
        )
    else:
        checks.append(Check("host_image", MISSING, "Agente sin ruta del ejecutable (< 0.6.2)."))
    group, template_group = service_group(info.get("binpath")), None
    if template is not None:
        template_group = service_group(template.get("binpath"))
    if group and template_group:
        checks.append(
            Check("host_group", PASS, group)
            if group == template_group
            else Check("host_group", FAIL, f"Grupo {group}; la plantilla usa {template_group}.")
        )
    checks.append(signature_check(info.get("image_signature")))

    results = {c.code: c.result for c in checks}
    decisive = ("service_type", "host_image", "host_group", "signature")
    if any(results.get(code) == FAIL for code in decisive):
        verification = SUSPICIOUS
        explanation = (
            "Tiene nombre de instancia por usuario, pero lo que se pudo comprobar no casa"
            " (tipo, ejecutable, grupo o firma). Puede ser una suplantación: revíselo."
        )
    elif results["template"] != PASS:
        verification = UNVERIFIED
        explanation = (
            "El nombre parece de instancia por usuario, pero su plantilla no está en el"
            " inventario: se trata como un servicio nuevo."
        )
    elif all(results.get(code) == PASS for code in ("service_type", "host_image", "signature")):
        verification = VERIFIED
        explanation = (
            f"Instancia por usuario de {template_name} (sesión _{suffix}): tipo de instancia,"
            " svchost.exe de System32 y firma de Microsoft válida. Windows la crea al iniciar"
            " sesión; no es una instalación."
        )
    else:
        verification = PROBABLE
        explanation = (
            f"Probable instancia por usuario de {template_name} (sesión _{suffix}): la"
            " plantilla existe, pero el agente no informó del tipo, la ruta o la firma."
            " Actualice el agente a 0.6.2 para verificarla."
        )
    return ServiceClass(
        USER_INSTANCE, verification, template_name, suffix, tuple(checks), explanation
    )


def classify_modified(before: Mapping[str, Any], after: Mapping[str, Any]) -> ServiceClass:
    """Servicio existente cuyo ejecutable cambió entre dos inventarios."""
    checks = [
        Check("previous_image", PASS, str(before.get("binpath") or "")[:200]),
        signature_check(after.get("image_signature")),
    ]
    suspicious = checks[-1].result == FAIL
    return ServiceClass(
        MODIFIED,
        SUSPICIOUS if suspicious else UNVERIFIED,
        checks=tuple(checks),
        explanation=(
            "El servicio ya existía y su ejecutable cambió: es una forma conocida de"
            " persistencia (secuestro de servicio). También lo hacen las actualizaciones."
        ),
    )
