"""Dossier assembly for VVP Issuer.

This module provides functionality to assemble credentials into complete
dossiers that the VVP Verifier can consume.
"""

from app.dossier.builder import DossierBuilder, DossierContent, get_dossier_builder
from app.dossier.exceptions import DossierBuildError
from app.dossier.formats import DossierFormat, serialize_dossier

__all__ = [
    "DossierBuilder",
    "DossierContent",
    "DossierBuildError",
    "DossierFormat",
    "get_dossier_builder",
    "serialize_dossier",
]
