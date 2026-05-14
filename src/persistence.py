import json
import os
from pathlib import Path
from threading import Lock
from settings import RUNTIME_DIR, MAX_LIMIT_KBPS

CONFIG_FILE = RUNTIME_DIR / ".balevpn_config.json"
LEGACY_TOKEN_FILE = RUNTIME_DIR / ".bale-token"

_data: dict = None
_lock = Lock()

MAX_LIMIT_BPS = MAX_LIMIT_KBPS * 1000 // 8


def _load() -> dict:
    global _data
    if _data is not None:
        return _data
    try:
        raw = CONFIG_FILE.read_text(encoding="utf-8")
        _data = json.loads(raw) or {}
    except (FileNotFoundError, json.JSONDecodeError):
        _data = {}
    if _data.get("token") is None:
        try:
            t = LEGACY_TOKEN_FILE.read_text(encoding="utf-8").strip()
            if t:
                _data["token"] = t
                print("[Config] migrated token from .bale-token")
                _save()
        except FileNotFoundError:
            pass
    return _data


def _save():
    try:
        CONFIG_FILE.write_text(json.dumps(_data, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as e:
        print(f"[Config] save failed: {e}")


def cfg_get(key: str, fallback=None):
    with _lock:
        v = _load().get(key)
        return fallback if v is None else v


def cfg_set(key: str, value):
    with _lock:
        _load()[key] = value
        _save()


def cfg_delete(key: str):
    with _lock:
        d = _load()
        if key in d:
            del d[key]
            _save()


def _clamp_bps(v: int) -> int:
    return max(0, min(MAX_LIMIT_BPS, int(v) if v else 0))


class AdmissionStore:
    _map: dict = None  # {callerId: {"upBps": int, "downBps": int}}

    @classmethod
    def _load(cls) -> dict:
        if cls._map is not None:
            return cls._map
        arr = cfg_get("admission", [])
        cls._map = {}
        for e in arr:
            if not e or not isinstance(e.get("callerId"), int) or e["callerId"] <= 0:
                continue
            up = _clamp_bps(e.get("upBps", 0))
            down = _clamp_bps(e.get("downBps", 0))
            cls._map[e["callerId"]] = {"upBps": up, "downBps": down}
        return cls._map

    @classmethod
    def _save(cls):
        arr = [{"callerId": k, "upBps": v["upBps"], "downBps": v["downBps"]}
               for k, v in cls._map.items()]
        cfg_set("admission", arr)

    @classmethod
    def is_allowed(cls, uid: int) -> bool:
        return int(uid) > 0 and int(uid) in cls._load()

    @classmethod
    def get_all(cls) -> list:
        return list(cls._load().keys())

    @classmethod
    def get_limit(cls, uid: int):
        v = cls._load().get(int(uid))
        return dict(v) if v else None

    @classmethod
    def get_all_limits(cls) -> dict:
        return {k: dict(v) for k, v in cls._load().items()}

    @classmethod
    def add(cls, uid: int) -> bool:
        n = int(uid)
        if n <= 0:
            return False
        m = cls._load()
        newly_added = n not in m
        if newly_added:
            m[n] = {"upBps": 0, "downBps": 0}
            cls._save()
        BlacklistStore.remove(n)
        return newly_added

    @classmethod
    def remove(cls, uid: int) -> bool:
        n = int(uid)
        m = cls._load()
        if n in m:
            del m[n]
            cls._save()
            return True
        return False

    @classmethod
    def set_limit(cls, uid: int, up_bps: int, down_bps: int) -> bool:
        n = int(uid)
        if n <= 0:
            return False
        m = cls._load()
        if n not in m:
            return False
        m[n] = {"upBps": _clamp_bps(up_bps), "downBps": _clamp_bps(down_bps)}
        cls._save()
        return True


class BlacklistStore:
    _set: set = None

    @classmethod
    def _load(cls) -> set:
        if cls._set is not None:
            return cls._set
        arr = cfg_get("blacklist", [])
        cls._set = {n for n in arr if isinstance(n, int) and n > 0}
        return cls._set

    @classmethod
    def _save(cls):
        cfg_set("blacklist", list(cls._set))

    @classmethod
    def is_blocked(cls, uid: int) -> bool:
        return int(uid) > 0 and int(uid) in cls._load()

    @classmethod
    def get_all(cls) -> list:
        return list(cls._load())

    @classmethod
    def add(cls, uid: int) -> bool:
        n = int(uid)
        if n <= 0:
            return False
        s = cls._load()
        newly_added = n not in s
        if newly_added:
            s.add(n)
            cls._save()
        AdmissionStore.remove(n)
        return newly_added

    @classmethod
    def remove(cls, uid: int) -> bool:
        n = int(uid)
        s = cls._load()
        if n in s:
            s.discard(n)
            cls._save()
            return True
        return False
