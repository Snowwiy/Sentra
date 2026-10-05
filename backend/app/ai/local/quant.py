"""Cuantizaciones conocidas: nombre, bits por peso aproximados y factor de calidad.

Fuentes y supuestos:
- `GGUF_FILE_TYPES` replica el enum `llama_ftype` de llama.cpp (general.file_type). Los
  valores retirados (Q4_0_4_4...) no se incluyen: un fichero con ellos queda "desconocido".
- `GGML_TENSOR_TYPES` replica `ggml_type`; sirve para inferir la cuantización dominante
  cuando el fichero no declara general.file_type.
- `BITS_PER_WEIGHT` son medias publicadas por llama.cpp (incluyen escalas de bloque). Solo
  se usan para estimar el tamaño de un modelo del catálogo que aún no está en disco; para un
  fichero registrado se usa su tamaño real.
- `QUALITY_FACTOR` es una heurística (tendencia de perplejidad publicada): 1.0 = sin
  pérdida apreciable. Multiplica los parámetros para obtener "parámetros efectivos". No es
  una medida exacta de calidad y se documenta como tal.

Una cuantización que no está aquí NO se adivina: el motor la trata como datos insuficientes
y no produce una recomendación (mejor ninguna que una falsa).
"""

GGUF_FILE_TYPES: dict[int, str] = {
    0: "F32",
    1: "F16",
    2: "Q4_0",
    3: "Q4_1",
    7: "Q8_0",
    8: "Q5_0",
    9: "Q5_1",
    10: "Q2_K",
    11: "Q3_K_S",
    12: "Q3_K_M",
    13: "Q3_K_L",
    14: "Q4_K_S",
    15: "Q4_K_M",
    16: "Q5_K_S",
    17: "Q5_K_M",
    18: "Q6_K",
    19: "IQ2_XXS",
    20: "IQ2_XS",
    21: "Q2_K_S",
    22: "IQ3_XS",
    23: "IQ3_XXS",
    24: "IQ1_S",
    25: "IQ4_NL",
    26: "IQ3_S",
    27: "IQ3_M",
    28: "IQ2_S",
    29: "IQ2_M",
    30: "IQ4_XS",
    31: "IQ1_M",
    32: "BF16",
    36: "TQ1_0",
    37: "TQ2_0",
}

GGML_TENSOR_TYPES: dict[int, str] = {
    0: "F32",
    1: "F16",
    2: "Q4_0",
    3: "Q4_1",
    6: "Q5_0",
    7: "Q5_1",
    8: "Q8_0",
    10: "Q2_K",
    11: "Q3_K",
    12: "Q4_K",
    13: "Q5_K",
    14: "Q6_K",
    16: "IQ2_XXS",
    17: "IQ2_XS",
    18: "IQ3_XXS",
    19: "IQ1_S",
    20: "IQ4_NL",
    21: "IQ3_S",
    22: "IQ2_S",
    23: "IQ4_XS",
    29: "IQ1_M",
    30: "BF16",
    34: "TQ1_0",
    35: "TQ2_0",
}

BITS_PER_WEIGHT: dict[str, float] = {
    "F32": 32.0,
    "F16": 16.0,
    "BF16": 16.0,
    "Q8_0": 8.5,
    "Q6_K": 6.56,
    "Q5_K_M": 5.69,
    "Q5_K_S": 5.54,
    "Q5_1": 6.0,
    "Q5_0": 5.5,
    "Q4_K_M": 4.85,
    "Q4_K_S": 4.58,
    "Q4_1": 5.0,
    "Q4_0": 4.55,
    "IQ4_XS": 4.25,
    "IQ4_NL": 4.5,
    "Q3_K_L": 4.27,
    "Q3_K_M": 3.91,
    "Q3_K_S": 3.5,
    "IQ3_M": 3.66,
    "IQ3_S": 3.44,
    "IQ3_XS": 3.3,
    "IQ3_XXS": 3.06,
    "Q2_K": 3.35,
    "Q2_K_S": 2.96,
    "IQ2_M": 2.7,
    "IQ2_S": 2.5,
    "IQ2_XS": 2.31,
    "IQ2_XXS": 2.06,
    "IQ1_M": 1.75,
    "IQ1_S": 1.56,
}

QUALITY_FACTOR: dict[str, float] = {
    "F32": 1.0,
    "F16": 1.0,
    "BF16": 1.0,
    "Q8_0": 1.0,
    "Q6_K": 0.98,
    "Q5_K_M": 0.96,
    "Q5_K_S": 0.95,
    "Q5_K": 0.95,
    "Q5_1": 0.95,
    "Q5_0": 0.94,
    "Q4_K_M": 0.92,
    "Q4_K_S": 0.9,
    "Q4_K": 0.9,
    "Q4_1": 0.89,
    "Q4_0": 0.88,
    "IQ4_XS": 0.9,
    "IQ4_NL": 0.9,
    "Q3_K_L": 0.82,
    "Q3_K_M": 0.78,
    "Q3_K": 0.76,
    "Q3_K_S": 0.72,
    "IQ3_M": 0.78,
    "IQ3_S": 0.76,
    "IQ3_XS": 0.72,
    "IQ3_XXS": 0.7,
    "Q2_K": 0.6,
    "Q2_K_S": 0.56,
    "IQ2_M": 0.58,
    "IQ2_S": 0.55,
    "IQ2_XS": 0.52,
    "IQ2_XXS": 0.5,
    "IQ1_M": 0.4,
    "IQ1_S": 0.35,
}


def normalize_quantization(value: str | None) -> str | None:
    """'q4_k_m' -> 'Q4_K_M'. Devuelve None si no es una cuantización conocida."""
    if not value:
        return None
    name = value.strip().upper().replace("-", "_")
    return name if name in QUALITY_FACTOR else None


def quantization_from_filename(filename: str) -> str | None:
    """Cuantización que sugiere el nombre del fichero. Solo es una pista: manda la metadata."""
    upper = filename.upper().replace("-", "_").replace(".", "_")
    # Los nombres más largos primero: "Q4_K_M" antes que "Q4_K".
    for name in sorted(QUALITY_FACTOR, key=len, reverse=True):
        if f"_{name}_" in f"_{upper}_":
            return name
    return None
