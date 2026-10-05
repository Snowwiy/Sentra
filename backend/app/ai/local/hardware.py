"""Perfil de hardware del SERVIDOR de Sentra (Fase 4J.2): CPU, RAM, GPU, VRAM y disco.

Decisiones:
- Solo APIs del sistema y ficheros del kernel (stdlib): /proc y /sys en Linux, registro y
  kernel32 (ctypes) en Windows. La única herramienta externa es `nvidia-smi`, buscada en
  PATH y ejecutada con argumentos FIJOS (lista, sin shell, con timeout): ningún dato del
  usuario llega nunca a un comando.
- Minimizar datos: no se guardan hostname, números de serie, UUIDs de GPU ni rutas. Solo
  lo necesario para estimar qué modelos caben.
- Nunca falla por falta de GPU o de una fuente: cada sonda devuelve None y el perfil lleva
  `warnings` legibles. "Desconocido" es un valor válido; inventar uno no lo es.
- Rápido (<~3 s en el peor caso): sin recorrer el disco ni enumerar dispositivos por WMI.

`SystemSource` encapsula todo el acceso al sistema para que los tests usen fuentes falsas
deterministas (CPU-only, NVIDIA, AMD, varias GPU...) sin hardware real.
"""

import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Literal

# Tipo real del handle de winreg. Python y mypy entienden esta comprobación de plataforma:
# en Windows se usa HKEYType sin cast; fuera de Windows el alias solo hace válida la firma
# (las funciones de registro salen antes de tocarlo).
if sys.platform == "win32":
    from winreg import HKEYType as RegistryKey
else:
    RegistryKey = int

GPUVendor = Literal["nvidia", "amd", "intel", "other"]
MemoryKind = Literal["dedicated", "shared", "unknown"]

MIB = 1024 * 1024
GIB = 1024 * MIB
NVIDIA_SMI_TIMEOUT = 3.0
# Una "VRAM" menor que esto en AMD es la reserva de una gráfica integrada (APU), no memoria
# dedicada: contarla como VRAM haría creer que el modelo cabe en GPU.
AMD_DEDICATED_MIN_BYTES = 2 * GIB
_PCI_VENDORS: dict[str, GPUVendor] = {"10de": "nvidia", "1002": "amd", "8086": "intel"}
_NVIDIA_QUERY = (
    "--query-gpu=index,name,memory.total,memory.free,driver_version",
    "--format=csv,noheader,nounits",
)
_NVIDIA_USED_QUERY = ("--query-gpu=memory.used", "--format=csv,noheader,nounits")


@dataclass(frozen=True)
class CPUInfo:
    model: str | None
    physical_cores: int | None
    logical_cores: int | None


@dataclass(frozen=True)
class GPUDevice:
    index: int
    vendor: GPUVendor
    model: str | None
    vram_total_bytes: int | None
    # Solo cuando la fuente lo da de forma fiable (nvidia-smi, amdgpu); si no, None.
    vram_free_bytes: int | None
    memory_kind: MemoryKind
    # nvidia-smi, sysfs, procfs o registry: de dónde salen los datos (transparencia).
    source: str
    driver: str | None = None

    @property
    def usable_for_offload(self) -> bool:
        """Cuenta como VRAM para cargar capas: dedicada y con tamaño conocido."""
        return self.memory_kind == "dedicated" and bool(self.vram_total_bytes)


@dataclass(frozen=True)
class HardwareProfile:
    os: str
    os_version: str | None
    architecture: str
    cpu: CPUInfo
    ram_total_bytes: int | None
    ram_available_bytes: int | None
    gpu_devices: tuple[GPUDevice, ...]
    disk_free_bytes: int | None
    disk_total_bytes: int | None
    # "model_directory" si se midió en AI_MODEL_DIRECTORIES; "server" si en el directorio de
    # trabajo de la API. Nunca la ruta: no aporta y revela la estructura del servidor.
    disk_scope: str
    detected_at: datetime
    duration_ms: int
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def offload_vram_bytes(self) -> int:
        return sum(g.vram_total_bytes or 0 for g in self.gpu_devices if g.usable_for_offload)


class SystemSource:
    """Acceso real al sistema. Cada método devuelve None si la fuente no existe o falla."""

    def system(self) -> str:
        return platform.system()

    def release(self) -> str | None:
        return platform.release() or None

    def machine(self) -> str:
        return platform.machine() or "unknown"

    def logical_cores(self) -> int | None:
        return os.cpu_count()

    def read_text(self, path: str, limit: int = 1024 * 1024) -> str | None:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                return handle.read(limit)
        except OSError:
            return None

    def list_dir(self, path: str) -> list[str]:
        try:
            return sorted(os.listdir(path))
        except OSError:
            return []

    def nvidia_smi(self, query: tuple[str, ...]) -> str | None:
        executable = shutil.which("nvidia-smi")
        if not executable:
            return None
        try:
            # Lista de argumentos fija (constantes de este módulo), sin shell y con timeout.
            result = subprocess.run(  # noqa: S603
                [executable, *query],
                capture_output=True,
                text=True,
                timeout=NVIDIA_SMI_TIMEOUT,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return result.stdout if result.returncode == 0 else None

    def disk_usage(self, path: str) -> tuple[int, int] | None:
        try:
            usage = shutil.disk_usage(path)
        except OSError:
            return None
        return usage.total, usage.free

    # --- Windows ---------------------------------------------------------------------------

    def windows_memory(self) -> tuple[int, int] | None:
        if sys.platform != "win32":
            return None
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return None
        return int(status.ullTotalPhys), int(status.ullAvailPhys)

    def windows_physical_cores(self) -> int | None:
        if sys.platform != "win32":
            return None
        import ctypes

        # GetLogicalProcessorInformation: una entrada RelationProcessorCore (0) por núcleo
        # físico. Primero se pide el tamaño necesario y luego se lee el buffer.
        kernel32 = ctypes.windll.kernel32
        size = ctypes.c_ulong(0)
        kernel32.GetLogicalProcessorInformation(None, ctypes.byref(size))
        if not size.value or size.value > 1024 * 1024:
            return None
        buffer = ctypes.create_string_buffer(size.value)
        if not kernel32.GetLogicalProcessorInformation(buffer, ctypes.byref(size)):
            return None
        # SYSTEM_LOGICAL_PROCESSOR_INFORMATION: ULONG_PTR mask + int relationship + union 16 B.
        pointer = ctypes.sizeof(ctypes.c_void_p)
        entry = pointer + 4 + (4 if pointer == 8 else 0) + 16
        raw = buffer.raw[: size.value]
        cores = 0
        for offset in range(0, len(raw) - entry + 1, entry):
            if int.from_bytes(raw[offset + pointer : offset + pointer + 4], "little") == 0:
                cores += 1
        return cores or None

    def windows_cpu_name(self) -> str | None:
        return self._registry_value(
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString"
        )

    def windows_display_adapters(self) -> list[dict[str, object]]:
        """Adaptadores de la clase Display del registro (sin WMI ni PowerShell)."""
        if sys.platform != "win32":
            return []
        import winreg

        base = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
        adapters: list[dict[str, object]] = []
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
        except OSError:
            return []
        with root:
            for i in range(64):
                try:
                    name = winreg.EnumKey(root, i)
                except OSError:
                    break
                if not name.isdigit():
                    continue
                try:
                    with winreg.OpenKey(root, name) as key:
                        adapters.append(
                            {
                                k: self._reg(key, k)
                                for k in (
                                    "DriverDesc",
                                    "MatchingDeviceId",
                                    "DriverVersion",
                                    "HardwareInformation.qwMemorySize",
                                    "HardwareInformation.MemorySize",
                                )
                            }
                        )
                except OSError:
                    continue
        return adapters

    @staticmethod
    def _reg(key: RegistryKey, value_name: str) -> object:
        if sys.platform != "win32":
            return None
        import winreg

        try:
            return winreg.QueryValueEx(key, value_name)[0]
        except OSError:
            return None

    def _registry_value(self, path: str, value_name: str) -> str | None:
        if sys.platform != "win32":
            return None
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                value = winreg.QueryValueEx(key, value_name)[0]
        except OSError:
            return None
        return str(value).strip() or None


# --- Detección ------------------------------------------------------------------------------


def _parse_cpuinfo(text: str) -> tuple[str | None, int | None]:
    model: str | None = None
    cores: set[tuple[str, str]] = set()
    physical = core = None
    for line in [*text.splitlines(), ""]:
        if not line.strip():
            if physical is not None and core is not None:
                cores.add((physical, core))
            physical = core = None
            continue
        name, _, value = line.partition(":")
        name, value = name.strip(), value.strip()
        if name in ("model name", "Model", "Hardware", "cpu model") and model is None and value:
            model = value
        elif name == "physical id":
            physical = value
        elif name == "core id":
            core = value
    return model, (len(cores) or None)


def _parse_meminfo(text: str) -> tuple[int | None, int | None]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        name, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            values[name.strip()] = int(parts[0]) * 1024
    return values.get("MemTotal"), values.get("MemAvailable")


def _mib(value: str) -> int | None:
    value = value.strip()
    return int(float(value) * MIB) if value.replace(".", "", 1).isdigit() else None


def parse_nvidia_smi(text: str) -> list[GPUDevice]:
    devices: list[GPUDevice] = []
    for line in text.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 5 or not parts[0].isdigit():
            continue
        devices.append(
            GPUDevice(
                index=int(parts[0]),
                vendor="nvidia",
                model=parts[1][:128] or None,
                vram_total_bytes=_mib(parts[2]),
                vram_free_bytes=_mib(parts[3]),
                memory_kind="dedicated",
                source="nvidia-smi",
                driver=parts[4][:32] or None,
            )
        )
    return devices


def _linux_gpus(source: SystemSource, warnings: list[str]) -> list[GPUDevice]:
    smi = source.nvidia_smi(_NVIDIA_QUERY)
    devices = parse_nvidia_smi(smi) if smi else []
    have_nvidia = bool(devices)
    if not have_nvidia:
        # Sin nvidia-smi el driver aún expone el modelo, pero no la VRAM.
        for entry in source.list_dir("/proc/driver/nvidia/gpus"):
            info = source.read_text(f"/proc/driver/nvidia/gpus/{entry}/information") or ""
            model = next(
                (
                    line.split(":", 1)[1].strip()
                    for line in info.splitlines()
                    if line.startswith("Model:")
                ),
                None,
            )
            devices.append(
                GPUDevice(len(devices), "nvidia", model, None, None, "unknown", "procfs")
            )
            have_nvidia = True
        if have_nvidia:
            warnings.append("NVIDIA detectada sin nvidia-smi: VRAM desconocida.")
    for card in source.list_dir("/sys/class/drm"):
        if not card.startswith("card") or not card[4:].isdigit():
            continue
        base = f"/sys/class/drm/{card}/device"
        vendor_id = (source.read_text(f"{base}/vendor") or "").strip().lower().removeprefix("0x")
        vendor = _PCI_VENDORS.get(vendor_id)
        if vendor is None or vendor == "nvidia":
            # NVIDIA ya se cubre con nvidia-smi/procfs (evita duplicados).
            continue
        device_id = (source.read_text(f"{base}/device") or "").strip().lower()
        total = used = None
        if vendor == "amd":
            total = _to_int(source.read_text(f"{base}/mem_info_vram_total"))
            used = _to_int(source.read_text(f"{base}/mem_info_vram_used"))
        model = (source.read_text(f"{base}/product_name") or "").strip() or (
            f"{vendor.upper()} GPU ({device_id})" if device_id else None
        )
        kind: MemoryKind = "unknown"
        if vendor == "amd" and total:
            kind = "dedicated" if total >= AMD_DEDICATED_MIN_BYTES else "shared"
        elif vendor == "intel":
            # Las Intel integradas comparten la RAM; las Arc no exponen VRAM por sysfs estándar.
            kind = "unknown"
        devices.append(
            GPUDevice(
                index=len(devices),
                vendor=vendor,
                model=model[:128] if model else None,
                vram_total_bytes=total if kind == "dedicated" else None,
                vram_free_bytes=(total - used)
                if kind == "dedicated" and total and used is not None
                else None,
                memory_kind=kind,
                source="sysfs",
            )
        )
    return devices


def _to_int(text: str | None) -> int | None:
    value = (text or "").strip()
    return int(value) if value.isdigit() else None


def _vendor_from_device_id(device_id: str) -> GPUVendor | None:
    upper = device_id.upper()
    for vendor_id, vendor in _PCI_VENDORS.items():
        if f"VEN_{vendor_id.upper()}" in upper:
            return vendor
    return None


def _windows_gpus(source: SystemSource, warnings: list[str]) -> list[GPUDevice]:
    smi = source.nvidia_smi(_NVIDIA_QUERY)
    devices = parse_nvidia_smi(smi) if smi else []
    for adapter in source.windows_display_adapters():
        vendor = _vendor_from_device_id(str(adapter.get("MatchingDeviceId") or ""))
        if vendor is None:
            # Adaptador básico de Microsoft, escritorio remoto, etc.: no es una GPU útil.
            continue
        if vendor == "nvidia" and devices:
            continue
        size = adapter.get("HardwareInformation.qwMemorySize")
        if not isinstance(size, int):
            legacy = adapter.get("HardwareInformation.MemorySize")
            if isinstance(legacy, bytes) and len(legacy) >= 4:
                size = int.from_bytes(legacy[:4], "little")
            else:
                size = legacy if isinstance(legacy, int) else None
        kind: MemoryKind = "unknown"
        if vendor in ("nvidia", "amd") and size and size >= AMD_DEDICATED_MIN_BYTES:
            kind = "dedicated"
        elif vendor == "intel":
            # Intel integrada: la "memoria" es RAM compartida, no sirve para offload.
            kind = "shared"
        devices.append(
            GPUDevice(
                index=len(devices),
                vendor=vendor,
                model=str(adapter.get("DriverDesc") or "")[:128] or None,
                vram_total_bytes=size if kind == "dedicated" else None,
                # El registro no da VRAM libre de forma fiable: mejor None que un valor falso.
                vram_free_bytes=None,
                memory_kind=kind,
                source="registry",
                driver=str(adapter.get("DriverVersion") or "")[:32] or None,
            )
        )
        if vendor == "nvidia":
            warnings.append("NVIDIA detectada sin nvidia-smi: VRAM libre desconocida.")
    return devices


def profile_hardware(source: SystemSource, disk_paths: tuple[str, ...] = ()) -> HardwareProfile:
    """Perfil normalizado del servidor. Nunca lanza excepción por una sonda que falle."""
    started = time.monotonic()
    warnings: list[str] = []
    system = source.system()
    cpu_model: str | None = None
    physical: int | None = None
    ram_total = ram_available = None
    gpus: list[GPUDevice] = []
    try:
        if system == "Linux":
            cpu_model, physical = _parse_cpuinfo(source.read_text("/proc/cpuinfo") or "")
            ram_total, ram_available = _parse_meminfo(source.read_text("/proc/meminfo") or "")
            gpus = _linux_gpus(source, warnings)
        elif system == "Windows":
            cpu_model = source.windows_cpu_name()
            physical = source.windows_physical_cores()
            memory = source.windows_memory()
            if memory:
                ram_total, ram_available = memory
            gpus = _windows_gpus(source, warnings)
        else:
            warnings.append(f"Sistema {system} sin detección de hardware específica.")
    except Exception:
        # Una sonda rota (driver raro, registro inaccesible) no tumba la página: se informa.
        warnings.append("Parte del hardware no se pudo detectar.")
    if ram_total is None:
        warnings.append("RAM total desconocida: no se puede estimar el uso de CPU/RAM.")
    if not any(g.usable_for_offload for g in gpus):
        warnings.append("Sin GPU con VRAM dedicada conocida: las estimaciones son solo CPU/RAM.")

    disk = None
    scope = "server"
    for path in disk_paths:
        disk = source.disk_usage(path)
        if disk:
            scope = "model_directory"
            break
    if disk is None:
        disk = source.disk_usage(os.getcwd())
    return HardwareProfile(
        os=system or "unknown",
        os_version=source.release(),
        architecture=source.machine(),
        cpu=CPUInfo(cpu_model[:128] if cpu_model else None, physical, source.logical_cores()),
        ram_total_bytes=ram_total,
        ram_available_bytes=ram_available,
        gpu_devices=tuple(replace(g, index=i) for i, g in enumerate(gpus)),
        disk_total_bytes=disk[0] if disk else None,
        disk_free_bytes=disk[1] if disk else None,
        disk_scope=scope,
        detected_at=datetime.now(UTC),
        duration_ms=int((time.monotonic() - started) * 1000),
        warnings=tuple(warnings),
    )


def sample_memory_usage(source: SystemSource) -> tuple[int | None, int | None]:
    """(RAM usada del sistema, VRAM usada total) en este instante. Para el benchmark.

    Son valores de TODO el sistema, no solo del runtime: la medición es "observada", no
    atribuida, y así se muestra en la UI.
    """
    ram_used: int | None = None
    vram_used: int | None = None
    system = source.system()
    if system == "Linux":
        total, available = _parse_meminfo(source.read_text("/proc/meminfo") or "")
        if total is not None and available is not None:
            ram_used = total - available
    elif system == "Windows":
        memory = source.windows_memory()
        if memory:
            ram_used = memory[0] - memory[1]
    smi = source.nvidia_smi(_NVIDIA_USED_QUERY)
    if smi:
        values = [_mib(line) for line in smi.splitlines() if line.strip()]
        known = [v for v in values if v is not None]
        vram_used = sum(known) if known else None
    elif system == "Linux":
        used = 0
        found = False
        for card in source.list_dir("/sys/class/drm"):
            if card.startswith("card") and card[4:].isdigit():
                value = _to_int(
                    source.read_text(f"/sys/class/drm/{card}/device/mem_info_vram_used")
                )
                if value is not None:
                    used += value
                    found = True
        vram_used = used if found else None
    return ram_used, vram_used
