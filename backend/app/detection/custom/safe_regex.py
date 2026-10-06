"""Subconjunto seguro de expresiones regulares para reglas personalizadas (Fase 5A).

El motor `re` de Python no tiene timeout: una expresión patológica ("(a+)+$") puede tardar
minutos sobre un texto de pocos KB (backtracking catastrófico) y bloquearía el motor de
detección entero. En vez de intentar cortar la ejecución, se valida la expresión ANTES de
guardarla y solo se aceptan construcciones cuyo coste está acotado:

- longitud máxima MAX_PATTERN y como mucho MAX_UNBOUNDED cuantificador no acotado
  (*, +, {m,}); los acotados ({m,n}) con n <= MAX_REPEAT;
- presupuesto de backtracking: el producto de los rangos de todos los cuantificadores (un
  no acotado cuenta como MAX_SUBJECT) por las alternativas no puede pasar de MAX_COST. Con
  dos ".*" seguidos el peor caso medido sobre 1 KB era ~1 s; con este presupuesto el peor
  caso queda en unos pocos milisegundos;
- los cuantificadores solo se aplican a un átomo simple (carácter, escape, '.', clase): un
  grupo cuantificado ("(ab)+", "(a|b)*") es exactamente lo que produce la explosión, así
  que no se admite;
- sin retroreferencias, lookarounds, grupos con nombre, flags en línea ni recursión
  (solo "(...)" y "(?:...)");
- el texto evaluado está acotado (MAX_SUBJECT): el coste peor queda en un polinomio pequeño
  sobre unos cientos de caracteres (ver tests/test_rule_compiler.py, peor caso medido).

Todo lo que no encaja se rechaza con un motivo; la regla se puede escribir con
contains/starts_with/ends_with, que no tienen este riesgo.
"""

import re

MAX_PATTERN = 128
MAX_UNBOUNDED = 1
MAX_REPEAT = 32
MAX_ALTERNATIVES = 16
MAX_GROUP_DEPTH = 3
# Caracteres del valor sobre los que se ejecuta la expresión (el resto se ignora).
MAX_SUBJECT = 512
# Producto máximo de rangos de repetición (ver docstring): 512 x 8.
MAX_COST = MAX_SUBJECT * 8

_SIMPLE_ESCAPES = set("dDwWsSbBAZtnr")
_META = set(".^$*+?{}[]\\|()")
_BOUND = re.compile(r"\{(\d{1,3})(,(\d{0,3}))?\}")


class UnsafeRegexError(ValueError):
    pass


def check(pattern: str) -> None:
    """Lanza UnsafeRegexError si `pattern` no pertenece al subconjunto seguro."""
    if not pattern:
        raise UnsafeRegexError("empty regular expression")
    if len(pattern) > MAX_PATTERN:
        raise UnsafeRegexError(f"regular expression longer than {MAX_PATTERN} characters")
    unbounded = 0
    cost = 1
    alternatives = 0
    depth = 0
    # ¿Qué hay justo antes? "atom" (cuantificable), "group" (no cuantificable), "quant" o
    # "start" (inicio, '(' o '|': un cuantificador aquí no tiene átomo).
    previous = "start"
    i = 0
    n = len(pattern)
    while i < n:
        char = pattern[i]
        if char == "\\":
            if i + 1 >= n:
                raise UnsafeRegexError("trailing backslash")
            escaped = pattern[i + 1]
            if escaped.isdigit() or escaped in ("k", "g", "N", "x", "u", "U", "0"):
                raise UnsafeRegexError("backreferences and numeric escapes are not allowed")
            if escaped.isalnum() and escaped not in _SIMPLE_ESCAPES:
                raise UnsafeRegexError(f"unsupported escape \\{escaped}")
            previous = "atom"
            i += 2
            continue
        if char == "[":
            end = _class_end(pattern, i)
            previous = "atom"
            i = end + 1
            continue
        if char == "(":
            if pattern.startswith("(?", i):
                if not pattern.startswith("(?:", i):
                    raise UnsafeRegexError(
                        "lookarounds, named groups and inline flags are not allowed"
                    )
                i += 3
            else:
                i += 1
            depth += 1
            if depth > MAX_GROUP_DEPTH:
                raise UnsafeRegexError(f"more than {MAX_GROUP_DEPTH} nested groups")
            previous = "start"
            continue
        if char == ")":
            if depth == 0:
                raise UnsafeRegexError("unbalanced parenthesis")
            depth -= 1
            previous = "group"
            i += 1
            continue
        if char == "|":
            alternatives += 1
            if alternatives > MAX_ALTERNATIVES:
                raise UnsafeRegexError(f"more than {MAX_ALTERNATIVES} alternatives")
            previous = "start"
            i += 1
            continue
        if char in "*+?{":
            if char == "{":
                match = _BOUND.match(pattern, i)
                if match is None:
                    # Llave literal (como hace re): no es un cuantificador.
                    previous = "atom"
                    i += 1
                    continue
                low = int(match.group(1))
                high_text = match.group(3)
                is_unbounded = match.group(2) is not None and not high_text
                high = low if match.group(2) is None else (int(high_text) if high_text else None)
                if high is not None and (high > MAX_REPEAT or high < low):
                    raise UnsafeRegexError(f"repetition bounds must be <= {MAX_REPEAT}")
                span = MAX_SUBJECT if high is None else high - low + 1
                length = match.end() - i
            else:
                is_unbounded = char in "*+"
                span = MAX_SUBJECT if is_unbounded else 2
                length = 1
            if previous == "group":
                raise UnsafeRegexError("quantified groups are not allowed (catastrophic risk)")
            if previous != "atom":
                raise UnsafeRegexError("quantifier without a preceding character")
            if is_unbounded:
                unbounded += 1
                if unbounded > MAX_UNBOUNDED:
                    raise UnsafeRegexError(f"more than {MAX_UNBOUNDED} unbounded quantifier")
            cost *= span
            if cost * (alternatives + 1) > MAX_COST:
                raise UnsafeRegexError("regular expression too expensive to evaluate safely")
            i += length
            # Variante perezosa ("*?") permitida; posesiva ("*+") no.
            if i < n and pattern[i] == "?":
                i += 1
            elif i < n and pattern[i] in "*+{":
                raise UnsafeRegexError("nested or possessive quantifiers are not allowed")
            previous = "quant"
            continue
        previous = "atom"
        i += 1
    if depth != 0:
        raise UnsafeRegexError("unbalanced parenthesis")
    if cost * (alternatives + 1) > MAX_COST:
        raise UnsafeRegexError("regular expression too expensive to evaluate safely")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise UnsafeRegexError(f"invalid regular expression: {exc.msg}") from None


def _class_end(pattern: str, start: int) -> int:
    i = start + 1
    if i < len(pattern) and pattern[i] == "^":
        i += 1
    if i < len(pattern) and pattern[i] == "]":
        i += 1
    while i < len(pattern):
        char = pattern[i]
        if char == "\\":
            i += 2
            continue
        if char == "[":
            raise UnsafeRegexError("nested character classes are not allowed")
        if char == "]":
            return i
        i += 1
    raise UnsafeRegexError("unterminated character class")


def compile_safe(pattern: str, case_sensitive: bool) -> re.Pattern[str]:
    check(pattern)
    return re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
