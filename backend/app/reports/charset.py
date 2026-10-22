# ruff: noqa: RUF001, RUF003
# (Este módulo trabaja a propósito con símbolos Unicode parecidos a ASCII: ×, –, comillas.)
"""Texto Unicode → bytes WinAnsi (cp1252) para el PDF v2 (Fase 6D.5).

El PDF propio usa solo las fuentes estándar Helvetica con WinAnsiEncoding: no se incrusta
ninguna fuente (licencia, tamaño y determinismo). cp1252 cubre el español, el euro, las
comillas tipográficas, las rayas, la elipsis y la viñeta, pero no flechas, símbolos
matemáticos, otras escrituras ni emojis. La plantilla v1 sustituía lo que no cabía por "?",
que es ambiguo (parece un dato real). En v2:

1. el texto se normaliza a NFC (una "é" descompuesta pasa a ser el carácter cp1252);
2. los símbolos frecuentes se transliteran a un equivalente ASCII legible y fijo
   (→ "->", ≥ ">=", ✓ "[OK]", espacios especiales → espacio, guiones Unicode → "-"...);
3. las letras con diacríticos fuera de cp1252 (ł, ő, ș, ā...) se reducen a su base por NFKD
   cuando el resultado es ASCII legible;
4. lo que siga sin representación se escribe como un marcador visible "[U+XXXX]": quien lee
   el PDF sabe que ahí había un carácter que el PDF no puede mostrar y cuál era. El HTML
   conserva siempre el Unicode completo.

Es una función pura y determinista: el mismo texto produce siempre los mismos bytes (el
SHA-256 del artefacto sigue siendo reproducible). Solo la usa el renderer v2; el v1 conserva
su salida.
"""

import unicodedata

# Símbolos frecuentes con un equivalente legible. Lo que ya existe en cp1252 (comillas
# tipográficas, «», ‹›, –, —, …, •, €, ™, ×, ±, °, ¹²³) NO está aquí: se conserva tal cual.
TRANSLITERATIONS: dict[str, str] = {
    # Flechas
    "→": "->",
    "←": "<-",
    "↔": "<->",
    "⇒": "=>",
    "⇐": "<=",
    "⇔": "<=>",
    "↑": "^",
    "↓": "v",
    "➔": "->",
    "➜": "->",
    "⟶": "->",
    "⟵": "<-",
    # Comparaciones y matemáticas
    "≥": ">=",
    "≤": "<=",
    "≠": "!=",
    "≈": "~",
    "≃": "~",
    "∞": "inf",
    "−": "-",
    "∑": "Sum",
    "√": "sqrt",
    "∆": "Delta",
    "Δ": "Delta",
    "µ": "µ",
    "μ": "µ",
    # Marcas de verificación y casillas
    "✓": "[OK]",
    "✔": "[OK]",
    "✗": "[X]",
    "✘": "[X]",
    "✕": "[X]",
    "☐": "[ ]",
    "☑": "[x]",
    "☒": "[x]",
    # Viñetas y formas que no están en cp1252
    "●": "•",
    "◦": "-",
    "▪": "-",
    "■": "-",
    "□": "-",
    "▸": ">",
    "►": ">",
    "◆": "-",
    # Guiones y comillas Unicode fuera de cp1252
    "‐": "-",
    "‑": "-",
    "‒": "-",
    "―": "—",
    "⁃": "-",
    "′": "'",
    "″": '"',
    "‛": "'",
    "‟": '"',
    "〈": "<",
    "〉": ">",
    "⟨": "<",
    "⟩": ">",
    "「": '"',
    "」": '"',
    # Superíndices que cp1252 no tiene (¹²³ sí están): x⁴ → x^4, no x4.
    "⁰": "^0",
    "⁴": "^4",
    "⁵": "^5",
    "⁶": "^6",
    "⁷": "^7",
    "⁸": "^8",
    "⁹": "^9",
    "⁺": "^+",
    "⁻": "^-",
    "ⁿ": "^n",
    # Letras sin descomposición NFKD
    "ł": "l",
    "Ł": "L",
    "đ": "d",
    "Đ": "D",
    "ħ": "h",
    "Ħ": "H",
    "ı": "i",
    "ŀ": "l",
    "Ŀ": "L",
    "ŧ": "t",
    "Ŧ": "T",
    "ĸ": "k",
    "ŉ": "'n",
    "ſ": "s",
    "ǝ": "e",
    # Controles habituales que en PDF no tienen sentido (\n lo trata quien parte las líneas)
    "\t": " ",
    "\r": " ",
}
# Espacios especiales → espacio normal; invisibles de ancho cero → nada.
_SPACES = {
    *(chr(c) for c in range(0x2000, 0x200B)),
    " ",
    " ",
    "　",
    " ",
}
_INVISIBLE = {"​", "‌", "‍", "⁠", "﻿", "­"}
# Selectores de variación (p. ej. el que sigue a un emoji): no son caracteres visibles.
_VARIATION = {chr(c) for c in range(0xFE00, 0xFE10)}


def marker(char: str) -> str:
    """Marcador visible y determinista de un carácter sin representación: "[U+2603]"."""
    return f"[U+{ord(char):04X}]"


def _encodable(text: str) -> bool:
    try:
        text.encode("cp1252")
    except UnicodeEncodeError:
        return False
    return True


def _char(char: str) -> str:
    """Un carácter (ya en NFC) → texto que cp1252 sí representa."""
    if char == "\n":
        return char
    if char in TRANSLITERATIONS:
        return TRANSLITERATIONS[char]
    if char in _SPACES:
        return " "
    if char in _INVISIBLE or char in _VARIATION:
        return ""
    code = ord(char)
    # Controles C0/C1 y DEL: el códec cp1252 de Python traduce algunos C1 a bytes que el PDF
    # mostraría como otro glifo; se marcan para que nunca se confundan con texto.
    if code < 0x20 or 0x7F <= code <= 0x9F:
        return marker(char)
    if _encodable(char):
        return char
    # Diacríticos fuera de cp1252: base + marcas combinantes → solo la base si es ASCII.
    decomposed = unicodedata.normalize("NFKD", char)
    base = "".join(c for c in decomposed if not unicodedata.combining(c))
    if base and base.isascii() and base.isprintable():
        return base
    return marker(char)


def to_winansi(text: str) -> str:
    """Texto equivalente que se puede codificar en cp1252 sin pérdidas silenciosas."""
    text = unicodedata.normalize("NFC", text)
    if _encodable(text) and not any(
        (ord(c) < 0x20 and c != "\n") or 0x7F <= ord(c) <= 0x9F for c in text
    ):
        # Camino rápido (casi todo el texto de un informe): nada que transliterar salvo los
        # invisibles que cp1252 sí codifica (guion blando).
        return text.replace("­", "")
    return "".join(_char(c) for c in text)


def encode_winansi(text: str) -> bytes:
    """Bytes cp1252 del texto ya transliterado (nunca contiene el "?" de reemplazo)."""
    return to_winansi(text).encode("cp1252")
