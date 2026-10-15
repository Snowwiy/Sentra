"""Filtro centralizado de visibilidad de datos para informes (Fase 5E).

Hoy Sentra es single-site: todo usuario con monitoring:read ve todos los activos. Aun así,
ningún builder de informes consulta activos "a pelo": todos pasan por `DataScope`, así la
Fase 5F (multi-site) podrá restringir por sitio en UN sitio sin revisar cada consulta.

No hay tenants ni sitios todavía: `asset_condition()` devuelve hoy la condición neutra.
"""

from dataclasses import dataclass

from sqlalchemy import ColumnElement, true

from app.core.permissions import Permission


@dataclass(frozen=True)
class DataScope:
    permissions: frozenset[Permission]

    def asset_condition(self) -> ColumnElement[bool]:
        """Condición SQL sobre `Asset`: activos que el solicitante puede ver."""
        # Punto de extensión de 5F (sitios). Sin monitoring:read no se ve ningún activo; en
        # la práctica el catálogo ya lo exige como permiso de dominio de todos los tipos.
        if Permission.MONITORING_READ not in self.permissions:
            return ~true()
        return true()
