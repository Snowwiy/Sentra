"""Errores de formato de la inteligencia importada o descargada (sin datos del contenido)."""


class IntelFormatError(ValueError):
    """Error estructural: el fichero o feed entero se rechaza (nada se guarda)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class IntelRecordError(ValueError):
    """Un registro concreto es inválido: se descarta solo (con su índice y código)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
