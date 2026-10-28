# SPDX-License-Identifier: MIT
from fastapi import APIRouter

from app.services import capabilities as caps

router = APIRouter(prefix="/api/capabilities", tags=["platform"])


@router.get("")
def capabilities():
    return {
        "asset_types": caps.ASSET_TYPES,
        "methodologies": caps.METHODOLOGIES,
        "modes": caps.MODES,
        "audiences": caps.AUDIENCES,
        "exclusions": caps.EXCLUSIONS,
    }
