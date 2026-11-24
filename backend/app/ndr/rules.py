"""Catálogo de reglas NDR (Fase 7E). Identificadores estables NDR-<ÁREA>-<NNN>.

Los identificadores no colisionan con el catálogo del motor de detecciones (AUTH-*, SYS-*,
TI-*, LIN-*, PS-*...): se comprueba en tests/test_ndr_7e2.py. Cada regla documenta qué
evidencia lleva a cada veredicto; "confirmed" solo existe en las reglas que pueden reunir
indicios independientes suficientes y nunca por volumen sin más.
"""

from dataclasses import dataclass, field

VERDICT_RANK = {"observed": 0, "suspicious": 1, "probable": 2, "confirmed": 3}
SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class NdrMitre:
    """Mapeo MITRE ATT&CK opcional y justificado (Fase 7E.5): táctica, técnica y subtécnica.
    Solo donde la regla describe la técnica; una regla de higiene (protocolos en claro) o de
    contexto externo (TI) no lleva mapeo."""

    tactic: str
    technique: str
    subtechnique: str | None = None


@dataclass(frozen=True)
class NdrRule:
    id: str
    version: int
    category: str
    title: str
    description: str
    why: str
    recommendations: tuple[str, ...]
    # Qué evidencia corresponde a cada veredicto que la regla puede emitir.
    verdicts: dict[str, str] = field(default_factory=dict)
    mitre: NdrMitre | None = None


ARP_001 = NdrRule(
    id="NDR-ARP-001",
    version=1,
    mitre=NdrMitre("TA0006", "T1557", "T1557.002"),
    category="arp",
    title="Cambio de la MAC asociada a una IP",
    description=(
        "Una respuesta ARP anuncia para una IP una MAC distinta de la que la red venía usando"
        " (asociación vista en las últimas 24 h)."
    ),
    why=(
        "Es la base del envenenamiento de caché ARP: quien anuncia una IP ajena recibe su"
        " tráfico. También lo produce un cambio legítimo de tarjeta, una VM movida o un"
        " clúster con IP flotante."
    ),
    recommendations=(
        "Identificar el equipo de la MAC nueva (fabricante, puerto del switch, inventario).",
        "Confirmar con el responsable del equipo de la IP si hubo un cambio de hardware.",
        "Si no hay explicación, aislar el puerto del switch según el procedimiento.",
    ),
    verdicts={
        "suspicious": "La IP pasó a anunciarse con otra MAC y la anterior seguía activa.",
        "probable": "Las dos MAC alternan para la misma IP en la misma ventana (disputa).",
    },
)

ARP_002 = NdrRule(
    id="NDR-ARP-002",
    version=1,
    mitre=NdrMitre("TA0006", "T1557", "T1557.002"),
    category="arp",
    title="Una MAC anuncia varias IP con respuestas ARP no solicitadas",
    description=(
        "Una misma MAC envía respuestas ARP no solicitadas para varias IP distintas en una"
        " ventana de exportación del sensor."
    ),
    why=(
        "Las herramientas de suplantación ARP anuncian a la vez la IP de la víctima y la de la"
        " puerta de enlace. Un router con proxy ARP o un balanceador también lo hacen."
    ),
    recommendations=(
        "Comprobar si la MAC es de un router, cortafuegos o balanceador con proxy ARP.",
        "Revisar las IP anunciadas y si alguna es la puerta de enlace (ver NDR-MITM-001).",
    ),
    verdicts={
        "suspicious": "3 o más IP anunciadas por la misma MAC sin petición previa.",
        "probable": "Además, 10 o más respuestas no solicitadas en la ventana.",
    },
)

ARP_003 = NdrRule(
    id="NDR-ARP-003",
    version=1,
    mitre=NdrMitre("TA0006", "T1557", "T1557.002"),
    category="arp",
    title="La MAC de la trama no coincide con la del mensaje ARP",
    description="Una respuesta ARP llega en una trama Ethernet con otra MAC de origen.",
    why=(
        "Indica un ARP fabricado o reenviado por un tercero. Algunos equipos de alta"
        " disponibilidad (VRRP/HSRP) o puentes lo producen de forma legítima."
    ),
    recommendations=("Identificar ambas MAC y el puerto del switch por el que llegan.",),
    verdicts={"suspicious": "MAC de trama y MAC de remitente ARP distintas."},
)

MITM_001 = NdrRule(
    id="NDR-MITM-001",
    version=1,
    mitre=NdrMitre("TA0006", "T1557", "T1557.002"),
    category="mitm",
    title="Suplantación ARP de la puerta de enlace",
    description=(
        "La IP de una puerta de enlace (anunciada por DHCP, opción 3) pasa a anunciarse con una"
        " MAC distinta de la habitual."
    ),
    why=(
        "Redirigir la puerta de enlace es la forma más directa de interceptar el tráfico de"
        " todo un segmento (man-in-the-middle). Un cambio de router o una conmutación de alta"
        " disponibilidad también cambia la MAC, normalmente de forma estable y sin disputa."
    ),
    recommendations=(
        "Verificar de inmediato con el equipo de red si hubo un cambio o conmutación del router.",
        "Localizar la MAC nueva en las tablas de los switches y aislar el puerto si no es"
        " un equipo de la infraestructura.",
        "Revisar el tráfico de los equipos del segmento durante la ventana afectada.",
    ),
    verdicts={
        "probable": "MAC nueva para la IP de la puerta de enlace con la anterior activa.",
        "confirmed": (
            "Además, la MAC nueva anuncia otras IP con respuestas no solicitadas y la MAC"
            " original sigue respondiendo en la misma ventana: dos indicios independientes del"
            " envenenamiento bidireccional."
        ),
    },
)

DNS_001 = NdrRule(
    id="NDR-DNS-001",
    version=1,
    mitre=NdrMitre("TA0011", "T1568", "T1568.002"),
    category="dns",
    title="Ráfaga de dominios inexistentes (NXDOMAIN)",
    description=(
        "Un equipo consulta muchos nombres distintos que no existen (NXDOMAIN) en una ventana."
    ),
    why=(
        "Es el patrón de un malware con generación de dominios (DGA) buscando su servidor de"
        " control. También lo producen sufijos de búsqueda mal configurados o software roto."
    ),
    recommendations=(
        "Revisar los nombres consultados y el proceso del equipo que los genera.",
        "Comprobar la configuración de sufijos DNS del equipo.",
    ),
    verdicts={
        "suspicious": "20 o más nombres NXDOMAIN distintos y al menos la mitad de las respuestas.",
        "probable": "50 o más nombres NXDOMAIN de al menos 10 dominios padre distintos.",
    },
)

DNS_002 = NdrRule(
    id="NDR-DNS-002",
    version=1,
    mitre=NdrMitre("TA0011", "T1071", "T1071.004"),
    category="dns",
    title="Indicios de túnel DNS",
    description=(
        "Muchos subdominios distintos y largos (o de alta entropía) bajo un mismo dominio, o"
        " uso intensivo de consultas TXT/NULL hacia él."
    ),
    why=(
        "Un túnel DNS codifica datos en los nombres consultados para sacar información o"
        " controlar un equipo saltándose el cortafuegos. CDNs, antivirus y telemetría usan"
        " también subdominios largos, de ahí que no se confirme solo con esto."
    ),
    recommendations=(
        "Identificar el dominio padre y su propietario.",
        "Revisar el volumen de consultas del equipo hacia ese dominio en el tiempo.",
    ),
    verdicts={
        "suspicious": "30 o más subdominios distintos largos o de alta entropía, o 20 TXT/NULL.",
        "probable": "Ambas condiciones a la vez para el mismo dominio padre.",
    },
)

DNS_003 = NdrRule(
    id="NDR-DNS-003",
    version=1,
    category="dns",
    title="Resolvedor DNS distinto del anunciado por DHCP",
    description=(
        "Un equipo resuelve contra un servidor DNS que no es ninguno de los que anuncia el"
        " DHCP del site."
    ),
    why=(
        "Saltarse el DNS corporativo evita su filtrado y registro. Es habitual en equipos con"
        " DNS público configurado a mano o navegadores con DNS propio."
    ),
    recommendations=("Revisar la configuración DNS del equipo y la política del site.",),
    verdicts={"observed": "Consultas a un resolvedor no anunciado por el DHCP del site."},
)

DHCP_001 = NdrRule(
    id="NDR-DHCP-001",
    version=1,
    mitre=NdrMitre("TA0006", "T1557", "T1557.003"),
    category="dhcp",
    title="Servidor DHCP no habitual",
    description=(
        "Ofertas o confirmaciones DHCP de un servidor distinto del que venía sirviendo el segmento."
    ),
    why=(
        "Un servidor DHCP no autorizado puede entregar otra puerta de enlace u otro DNS y"
        " desviar el tráfico de los equipos (man-in-the-middle). También aparece al conectar"
        " por error un router doméstico."
    ),
    recommendations=(
        "Localizar el equipo del servidor nuevo (MAC, puerto del switch).",
        "Activar DHCP snooping en los switches si está disponible.",
    ),
    verdicts={
        "suspicious": "Servidor DHCP nuevo en un segmento con servidor establecido.",
        "probable": "Además entrega una puerta de enlace o DNS distintos del establecido.",
    },
)


SCAN_001 = NdrRule(
    id="NDR-SCAN-001",
    version=1,
    mitre=NdrMitre("TA0007", "T1046"),
    category="scan",
    title="Barrido de puertos o equipos",
    description=(
        "Un equipo intenta conexiones TCP a muchos destinos (IP y puerto) distintos que no"
        " responden o rechazan la conexión, en una ventana."
    ),
    why=(
        "El reconocimiento de la red es el paso previo al movimiento lateral. Los escáneres"
        " de inventario o de vulnerabilidades autorizados producen el mismo patrón: si coincide"
        " con un discovery de Sentra del site, el veredicto baja a observed."
    ),
    recommendations=(
        "Comprobar si el origen es un escáner autorizado (inventario, vulnerabilidades).",
        "Si no lo es, revisar el equipo de origen y su actividad reciente.",
    ),
    verdicts={
        "observed": "El patrón coincide con un discovery autorizado de Sentra en el site.",
        "suspicious": "50 o más destinos distintos sin completar el saludo TCP.",
        "probable": "200 o más destinos distintos sin completar el saludo TCP.",
    },
)

PROTO_001 = NdrRule(
    id="NDR-PROTO-001",
    version=1,
    category="protocol",
    title="Protocolo de administración en claro",
    description=(
        "Conexión establecida a un servicio que transporta credenciales sin cifrar (Telnet,"
        " FTP, rlogin/rsh/rexec, TFTP)."
    ),
    why=(
        "Cualquiera en el camino puede leer las credenciales y los comandos. Es una"
        " exposición, no un ataque: el veredicto es siempre observed."
    ),
    recommendations=("Sustituir por SSH/SFTP o restringir el servicio a una red de gestión.",),
    verdicts={"observed": "Conexión con respuesta del servidor a un puerto en claro."},
)

PROTO_002 = NdrRule(
    id="NDR-PROTO-002",
    version=1,
    mitre=NdrMitre("TA0008", "T1021"),
    category="lateral",
    title="Un equipo abre sesiones de administración contra muchos equipos",
    description=(
        "Conexiones establecidas desde un mismo origen a SMB, RDP, WinRM, SSH o RPC de"
        " muchos equipos internos distintos en una ventana."
    ),
    why=(
        "Es el patrón del movimiento lateral (y de la propagación de ransomware por SMB)."
        " También lo producen servidores de gestión, copias de seguridad o despliegue."
    ),
    recommendations=(
        "Comprobar si el origen es un servidor de gestión, copias o despliegue autorizado.",
        "Si no lo es, revisar las cuentas usadas en esos equipos y aislar el origen.",
    ),
    verdicts={
        "suspicious": "5 o más equipos internos distintos en el mismo servicio.",
        "probable": "15 o más equipos internos distintos en el mismo servicio.",
    },
)

BEH_001 = NdrRule(
    id="NDR-BEH-001",
    version=1,
    mitre=NdrMitre("TA0010", "T1048"),
    category="behavior",
    title="Volumen de salida muy superior a lo habitual",
    description=(
        "Los bytes enviados por un equipo en una hora superan con mucho su línea base"
        " aprendida (media + 4 desviaciones y al menos 50 MB)."
    ),
    why=(
        "Una exfiltración o una copia masiva no autorizada se ve primero como volumen anómalo."
        " Copias de seguridad, actualizaciones o un cambio de uso también lo producen."
    ),
    recommendations=(
        "Revisar a qué destinos fue el volumen (pestaña de flujos filtrando por la IP).",
        "Confirmar con el responsable del equipo si hubo una tarea programada.",
    ),
    verdicts={
        "suspicious": "Más de media + 4 desviaciones y más de 50 MB en la hora.",
        "probable": "Más de media + 8 desviaciones y más de 500 MB en la hora.",
    },
)

BEH_002 = NdrRule(
    id="NDR-BEH-002",
    version=1,
    mitre=NdrMitre("TA0007", "T1046"),
    category="behavior",
    title="Número de destinos muy superior a lo habitual",
    description=(
        "Los destinos distintos contactados por un equipo en una hora superan con mucho su"
        " línea base (media + 4 desviaciones y al menos 50 destinos)."
    ),
    why=(
        "Un equipo comprometido que explora la red o propaga malware contacta de repente con"
        " muchos más equipos de lo normal."
    ),
    recommendations=("Revisar los destinos y servicios contactados por el equipo en esa hora.",),
    verdicts={"suspicious": "Más de media + 4 desviaciones y al menos 50 destinos."},
)

BEH_003 = NdrRule(
    id="NDR-BEH-003",
    version=1,
    mitre=NdrMitre("TA0011", "T1071"),
    category="behavior",
    title="Conexiones periódicas a un destino externo (beaconing)",
    description=(
        "Un equipo conecta al mismo destino externo y puerto a intervalos muy regulares"
        " (coeficiente de variación bajo) durante horas."
    ),
    why=(
        "El malware consulta a su servidor de control a intervalos fijos. Las actualizaciones,"
        " sincronizaciones y monitorización legítimas también son periódicas: por eso no pasa"
        " de suspicious sin otra evidencia (p. ej. una coincidencia de Threat Intelligence)."
    ),
    recommendations=(
        "Identificar el destino (dominio, propietario) y el proceso del equipo que conecta.",
        "Si el destino no es conocido, comprobarlo contra Threat Intelligence.",
    ),
    verdicts={
        "suspicious": "12 o más conexiones en 6 h con intervalos de variación inferior al 15 %.",
    },
)
TI_001 = NdrRule(
    id="NDR-TI-001",
    version=1,
    category="threat_intel",
    title="Tráfico con un indicador de Threat Intelligence",
    description=(
        "Un equipo interno intercambió tráfico con una IP, red, dominio o SNI que figura como"
        " indicador activo (no revocado, no benigno, vigente) en las fuentes de Threat"
        " Intelligence de Sentra."
    ),
    why=(
        "La fuente asocia ese valor a actividad maliciosa o sospechosa. Que un equipo lo"
        " contacte merece revisión, pero la inteligencia puede estar desactualizada o ser un"
        " falso positivo (IPs compartidas, CDNs, sinkholes)."
    ),
    recommendations=(
        "Revisar el indicador (fuente, fecha, confianza) en Threat Intelligence.",
        "Identificar el proceso que originó el tráfico en el equipo (agente o forense).",
        "Si es legítimo, marcar la anomalía como falso positivo o revocar el indicador.",
    ),
    verdicts={
        "suspicious": "Coincidencia con un indicador activo (o con una red cidr).",
        "probable": (
            "Indicador malicious de confianza alta, de una fuente oficial o de confianza,"
            " sobre un valor exacto (IP, dominio o SNI)."
        ),
    },
)


RULES: tuple[NdrRule, ...] = (
    ARP_001,
    ARP_002,
    ARP_003,
    MITM_001,
    DNS_001,
    DNS_002,
    DNS_003,
    DHCP_001,
    SCAN_001,
    PROTO_001,
    PROTO_002,
    BEH_001,
    BEH_002,
    BEH_003,
    TI_001,
)


def rules_by_id() -> dict[str, NdrRule]:
    return {rule.id: rule for rule in RULES}
