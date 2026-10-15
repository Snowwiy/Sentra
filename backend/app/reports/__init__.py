"""Reporting Engine (Fase 5E): catálogo cerrado, snapshots reproducibles y render local.

Flujo: petición validada (service) → snapshot estructurado en una transacción REPEATABLE
READ (builders) → documento neutro (templates) → HTML/PDF/CSV/ZIP (renderers) → fichero
atómico con SHA-256 (storage). Sin IA, sin Internet y sin plantillas del usuario.
"""
