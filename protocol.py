import struct
import os
from settings import (
    API_VERSION, PROTO_VERSION, AUTH_APP_ID, AUTH_API_KEY, SENDCODE_SMS,
    PEERTYPE_GROUP, EXPEERTYPE_GROUP, EXPEERTYPE_PRIVATE,
)


def _encode_varint(value: int) -> bytes:
    parts = []
    while value > 0x7F:
        parts.append((value & 0x7F) | 0x80)
        value >>= 7
    parts.append(value & 0x7F)
    return bytes(parts)


def _encode_signed_varint(value: int) -> bytes:
    if value >= 0:
        return _encode_varint(value)
    value = value & 0xFFFFFFFFFFFFFFFF
    return _encode_varint(value)


def _decode_varint(data: bytes, pos: int) -> tuple:
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def _encode_tag(field_num: int, wire_type: int) -> bytes:
    return _encode_varint((field_num << 3) | wire_type)


def _encode_int32_field(field_num: int, value: int) -> bytes:
    return _encode_tag(field_num, 0) + _encode_signed_varint(value)


def _encode_int64_field(field_num: int, value) -> bytes:
    return _encode_tag(field_num, 0) + _encode_signed_varint(int(value))


def _encode_string_field(field_num: int, value: str) -> bytes:
    encoded = value.encode("utf-8")
    return _encode_tag(field_num, 2) + _encode_varint(len(encoded)) + encoded


def _encode_bytes_field(field_num: int, value: bytes) -> bytes:
    return _encode_tag(field_num, 2) + _encode_varint(len(value)) + value


def _encode_bool_field(field_num: int, value: bool) -> bytes:
    return _encode_tag(field_num, 0) + _encode_varint(1 if value else 0)


def _skip_field(data: bytes, pos: int, wire_type: int) -> int:
    if wire_type == 0:  # varint
        while pos < len(data) and data[pos] & 0x80:
            pos += 1
        pos += 1
    elif wire_type == 1:  # 64-bit
        pos += 8
    elif wire_type == 2:  # length-delimited
        length, pos = _decode_varint(data, pos)
        pos += length
    elif wire_type == 5:  # 32-bit
        pos += 4
    return pos


def build_start_phone_auth_request(phone: str) -> bytes:
    device_hash = os.urandom(16)
    digits = phone.replace("+", "").replace("-", "").replace(" ", "")
    result = b""
    result += _encode_int64_field(1, int(digits))
    result += _encode_int32_field(2, AUTH_APP_ID)
    result += _encode_string_field(3, AUTH_API_KEY)
    result += _encode_bytes_field(4, device_hash)
    result += _encode_string_field(5, "Bale Web")
    result += _encode_string_field(7, "fa")
    result += _encode_int32_field(9, SENDCODE_SMS)
    return result


def decode_start_phone_auth_response(data: bytes) -> dict:
    pos = 0
    result = {"transactionHash": "", "isRegistered": False}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["transactionHash"] = data[pos:pos + length].decode("utf-8")
            pos += length
        elif field_num == 2 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["isRegistered"] = bool(val)
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def build_validate_code_request(transaction_hash: str, code: str) -> bytes:
    is_jwt_bytes = _encode_bool_field(1, True)
    result = b""
    result += _encode_string_field(1, transaction_hash)
    result += _encode_string_field(2, code)
    result += _encode_bytes_field(3, is_jwt_bytes)
    return result


def decode_auth_response(data: bytes) -> dict:
    pos = 0
    result = {}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 2 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["user"] = data[pos:pos + length]
            pos += length
        elif field_num == 4 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["jwt"] = _decode_wrapped_string(data[pos:pos + length])
            pos += length
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def build_signup_request(transaction_hash: str, name: str) -> bytes:
    result = b""
    result += _encode_string_field(1, transaction_hash)
    result += _encode_string_field(2, name)
    return result


def encode_handshake() -> bytes:
    inner = b""
    inner += _encode_int32_field(1, PROTO_VERSION)
    inner += _encode_int64_field(2, API_VERSION)
    return _encode_bytes_field(3, inner)


def encode_ping(ping_id: int) -> bytes:
    inner = _encode_int64_field(1, ping_id)
    return _encode_bytes_field(2, inner)


def encode_rpc_request(service_name: str, method: str, payload: bytes, index: int) -> bytes:
    inner = b""
    inner += _encode_string_field(1, service_name)
    inner += _encode_string_field(2, method)
    if payload and len(payload) > 0:
        inner += _encode_bytes_field(3, payload)
    inner += _encode_int64_field(5, index)
    return _encode_bytes_field(1, inner)


def _build_peer_bytes(peer_type: int, peer_id: int) -> bytes:
    result = b""
    if peer_type != 0:
        result += _encode_int32_field(1, peer_type)
    if peer_id != 0:
        result += _encode_int32_field(2, peer_id)
    return result


def build_accept_call_request(call_id) -> bytes:
    return _encode_int64_field(1, int(call_id))


def build_discard_call_request(call_id) -> bytes:
    return _encode_int64_field(1, int(call_id))


def build_start_call_request(peer_id: int, peer_type: int, rid: str) -> bytes:
    peer_bytes = _build_peer_bytes(peer_type, peer_id)
    lk_call_bytes = b""
    lk_call_bytes += _encode_bytes_field(1, peer_bytes)
    lk_call_bytes += _encode_int64_field(2, int(rid))
    result = b""
    result += _encode_bytes_field(1, peer_bytes)
    result += _encode_int64_field(2, int(rid))
    result += _encode_bytes_field(6, lk_call_bytes)
    return result


def build_get_contacts_request() -> bytes:
    return _encode_string_field(1, "")


def build_load_users_request(user_peers: list) -> bytes:
    result = b""
    for p in user_peers:
        peer = b""
        peer += _encode_int32_field(1, p["uid"])
        peer += _encode_int64_field(2, int(p.get("accessHash", "0")))
        result += _encode_bytes_field(1, peer)
    return result


def build_send_message_request(peer_id: int, peer_type: int, ex_peer_type: int, rid: str, text: str) -> bytes:
    text_msg_bytes = _encode_string_field(1, text)
    qbz_bytes = _encode_bytes_field(15, text_msg_bytes)
    result = b""
    result += _encode_bytes_field(1, _build_peer_bytes(peer_type, peer_id))
    result += _encode_int64_field(2, int(rid))
    result += _encode_bytes_field(3, qbz_bytes)
    result += _encode_bytes_field(6, _build_peer_bytes(ex_peer_type, peer_id))
    return result


def build_import_contacts_request(phone: str) -> bytes:
    digits = phone.replace("+", "").replace("-", "").replace(" ", "")
    phone_entry = _encode_int64_field(1, int(digits))
    return _encode_bytes_field(1, phone_entry)


def decode_server_frame(data: bytes) -> dict:
    pos = 0
    frame = {}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            frame["response"] = decode_rpc_response(data[pos:pos + length])
            pos += length
        elif field_num == 2 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            frame["update"] = _decode_update_container(data[pos:pos + length])
            pos += length
        elif field_num == 3:
            frame["terminateSession"] = True
            pos = _skip_field(data, pos, wire_type)
        elif field_num == 4 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            frame["pong"] = _decode_pong(data[pos:pos + length])
            pos += length
        elif field_num == 5 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            frame["handshakeResponse"] = _decode_handshake_response(data[pos:pos + length])
            pos += length
        else:
            pos = _skip_field(data, pos, wire_type)
    return frame


def _decode_handshake_response(data: bytes) -> dict:
    pos = 0
    result = {}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["mkprotoVersion"] = val
        elif field_num == 2 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["apiVersion"] = val
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def _decode_update_container(data: bytes) -> dict:
    pos = 0
    result = {}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["update"] = data[pos:pos + length]
            pos += length
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def decode_rpc_response(data: bytes) -> dict:
    pos = 0
    result = {}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["error"] = data[pos:pos + length]
            pos += length
        elif field_num == 2 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["response"] = data[pos:pos + length]
            pos += length
        elif field_num == 3 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["index"] = val
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def _decode_pong(data: bytes) -> dict:
    pos = 0
    result = {}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["id"] = val
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def decode_rpc_error(data: bytes) -> dict:
    pos = 0
    code = 0
    message = ""
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 0:
            code, pos = _decode_varint(data, pos)
        elif field_num == 2 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            message = data[pos:pos + length].decode("utf-8")
            pos += length
        else:
            pos = _skip_field(data, pos, wire_type)
    return {"code": code, "message": message or f"0x{data.hex()}"}


def decode_subscribe_response(data: bytes) -> dict:
    pos = 0
    result = {}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["update"] = decode_xc(data[pos:pos + length])
            pos += length
        elif field_num == 2 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["routeId"] = val
        elif field_num == 3 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["sequence"] = val
        elif field_num == 4 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["timestamp"] = val
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def decode_xc(data: bytes) -> dict:
    pos = 0
    result = {}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 55 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["message"] = decode_tif(data[pos:pos + length])
            pos += length
        elif field_num == 52807 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["callStarted"] = decode_call_response(data[pos:pos + length])
            pos += length
        elif field_num == 52808 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["callAccepted"] = decode_call_response(data[pos:pos + length])
            pos += length
        elif field_num == 52809 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["callEnded"] = _decode_call_ended(data[pos:pos + length])
            pos += length
        elif field_num == 52810 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["callReceived"] = _decode_call_received(data[pos:pos + length])
            pos += length
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def _decode_call_received(data: bytes) -> dict:
    pos = 0
    result = {"callId": "0"}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["callId"] = str(val)
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def _decode_call_ended(data: bytes) -> dict:
    pos = 0
    result = {"callId": "0"}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["callId"] = str(val)
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def decode_call_entity(data: bytes) -> dict:
    pos = 0
    result = {
        "id": "0", "token": "", "room": "", "url": "", "isLivekit": False,
        "callerId": 0, "video": False, "createDate": "0", "startDate": "0",
        "duration": 0, "discardReason": 0,
    }
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["id"] = str(val)
        elif field_num == 2 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["token"] = data[pos:pos + length].decode("utf-8")
            pos += length
        elif field_num == 3 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["room"] = data[pos:pos + length].decode("utf-8")
            pos += length
        elif field_num == 4 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["url"] = _decode_wrapped_string(data[pos:pos + length])
            pos += length
        elif field_num == 5 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["video"] = bool(val)
        elif field_num == 6 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["createDate"] = str(val)
        elif field_num == 7 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["startDate"] = str(val)
        elif field_num == 8 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["callerId"] = val
        elif field_num == 10 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["duration"] = val
        elif field_num == 11 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["discardReason"] = val
        elif field_num == 12 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["isLivekit"] = bool(val)
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def decode_call_response(data: bytes) -> dict:
    pos = 0
    result = {}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["call"] = decode_call_entity(data[pos:pos + length])
            pos += length
        elif field_num == 3 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["seq"] = val
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def decode_tif(data: bytes) -> dict:
    pos = 0
    result = {}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 2 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["senderUid"] = val
        elif field_num == 3 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["date"] = val
        elif field_num == 4 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["rid"] = str(val)
        elif field_num == 5 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["message"] = _decode_qbz(data[pos:pos + length])
            pos += length
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def _decode_qbz(data: bytes) -> dict:
    pos = 0
    result = {}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 15 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["textMessage"] = _decode_text_message(data[pos:pos + length])
            pos += length
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def _decode_text_message(data: bytes) -> dict:
    pos = 0
    result = {"text": ""}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["text"] = data[pos:pos + length].decode("utf-8")
            pos += length
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def decode_get_contacts_response(data: bytes) -> dict:
    pos = 0
    result = {"users": [], "userPeers": [], "isNotChanged": False}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["users"].append(data[pos:pos + length])
            pos += length
        elif field_num == 2 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["isNotChanged"] = bool(val)
        elif field_num == 3 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["userPeers"].append(_decode_user_peer(data[pos:pos + length]))
            pos += length
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def _decode_user_peer(data: bytes) -> dict:
    pos = 0
    result = {"uid": 0, "accessHash": "0"}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["uid"] = val
        elif field_num == 2 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["accessHash"] = str(val)
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def decode_load_users_response(data: bytes) -> dict:
    pos = 0
    result = {"users": []}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["users"].append(data[pos:pos + length])
            pos += length
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def _decode_wrapped_string(data: bytes) -> str:
    pos = 0
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            return data[pos:pos + length].decode("utf-8")
        else:
            pos = _skip_field(data, pos, wire_type)
    return ""


def decode_user_entity(data: bytes) -> dict:
    pos = 0
    result = {}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 0:
            val, pos = _decode_varint(data, pos)
            result["id"] = val
        elif field_num == 3 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["name"] = data[pos:pos + length].decode("utf-8")
            pos += length
        elif field_num == 9 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["nick"] = _decode_wrapped_string(data[pos:pos + length])
            pos += length
        else:
            pos = _skip_field(data, pos, wire_type)
    return result


def decode_import_contacts_response(data: bytes) -> dict:
    pos = 0
    result = {"users": [], "userPeers": []}
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["users"].append(data[pos:pos + length])
            pos += length
        elif field_num == 4 and wire_type == 2:
            length, pos = _decode_varint(data, pos)
            result["userPeers"].append(_decode_user_peer(data[pos:pos + length]))
            pos += length
        else:
            pos = _skip_field(data, pos, wire_type)
    return result
