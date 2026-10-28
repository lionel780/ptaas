# SPDX-License-Identifier: MIT
"""Stockage JSON simple (users, orgs, targets, scans, credits)."""
import json
import os
import uuid
import threading
from typing import Dict, Any, List, Optional

from app.core.config import settings

_lock = threading.Lock()


def _path(name: str) -> str:
    os.makedirs(settings.data_dir, exist_ok=True)
    return os.path.join(settings.data_dir, f"{name}.json")


def _load(name: str) -> Dict[str, Any]:
    p = _path(name)
    if not os.path.exists(p):
        return {}
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(name: str, data: Dict[str, Any]) -> None:
    with _lock:
        with open(_path(name), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


def insert(collection: str, doc: Dict[str, Any]) -> Dict[str, Any]:
    doc = dict(doc)
    doc.setdefault("id", uuid.uuid4().hex)
    data = _load(collection)
    data[doc["id"]] = doc
    _save(collection, data)
    return doc


def get(collection: str, doc_id: str) -> Optional[Dict[str, Any]]:
    return _load(collection).get(doc_id)


def update(collection: str, doc_id: str, patch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    data = _load(collection)
    if doc_id not in data:
        return None
    data[doc_id].update(patch)
    _save(collection, data)
    return data[doc_id]


def find(collection: str, **filters) -> List[Dict[str, Any]]:
    return [
        d for d in _load(collection).values()
        if all(d.get(k) == v for k, v in filters.items())
    ]


def all_docs(collection: str) -> List[Dict[str, Any]]:
    return list(_load(collection).values())
