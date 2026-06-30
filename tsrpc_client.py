#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSRPC Python 客户端
通用的 TSRPC 消息收发及解析公共逻辑，支持：
- TSBuffer 二进制编码/解码（Interface, Intersection, Union, Enum, String, Number, Buffer, Boolean）
- ServerInputData / ServerOutputData 打包/拆包
- HTTP 通信（自动 JSON / Binary 模式适配）
- 响应解析（isSucc/err/res 标准化结构）
- 签名算法（sign/signtime）

参考 TSRPC 框架源码：
  - tsbuffer/index.js: Config.interface.maxExtendsNum = 9
  - tsbuffer/index.js: blockId = property.id + maxExtendsNum + 1
  - tsbuffer/index.js: _processIdWithLengthType: blockId << 2 | lengthType
  - tsbuffer/index.js: Intersection/Union member id 直接用 member.id
  - tsrpc-proto/index.js: ServerInputData { serviceId(0,uint), buffer(1,Buffer), sn(2,uint?) }
  - tsrpc-proto/index.js: ServerOutputData { buffer(0,Buffer?), error(1,TsrpcErrorData?), serviceId(2,uint?), sn(3,uint?) }
  - tsrpc-proto/index.js: TsrpcErrorData { message(0,string), type(1,TsrpcErrorType?), code(2,Union<string|int>?) }
  - tsrpc-proto/index.js: TsrpcErrorType Enum { id=0:NetworkError, id=1:ServerError, id=2:ClientError, id=3:ApiError }

使用示例:
    from tsrpc_client import TSRPCClient, TSB, sign

    client = TSRPCClient("http://localhost:3000/dzqst-base")

    # 编码请求（serviceId=3, ReqFetchAccountData）
    inner = TSB.intersection([
        (0, TSB.interface([...])),
        (1, TSB.interface([...])),
    ])
    req_bytes = client.encode_request(3, inner)

    # 发送请求
    result = client.post("/Account/FetchAccountData", req_bytes)

    # 检查结果
    if result.is_succ:
        data = result.res  # dict，解码后的业务响应
"""

import hashlib
import json
import struct
import time
import threading
from dataclasses import dataclass, field
from typing import Optional, Callable, Any

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================================
# TSBuffer 常量
# ============================================================================

# LengthType
LD = 0   # LengthDelimited (String, Buffer, Array)
VI = 1   # Varint (Enum, Boolean, Number-int, uint)
B64 = 2  # Bit64 (Number-double)
IB = 3   # IdBlock (Interface, Union, Intersection)

# property.id 的 BlockID 偏移 = maxExtendsNum(9) + 1 = 10
_PROP = 10

# TsrpcErrorType 枚举
TSRPC_ERROR_TYPE = {0: "NetworkError", 1: "ServerError", 2: "ClientError", 3: "ApiError"}


# ============================================================================
# Varint 编码/解码
# ============================================================================

def encode_varint(value: int) -> bytes:
    """标准 Protobuf Varint 编码"""
    result = bytearray()
    v = value & 0xFFFFFFFFFFFFFFFF
    while v > 0x7F:
        result.append((v & 0x7F) | 0x80)
        v >>= 7
    result.append(v & 0x7F)
    return bytes(result)


def encode_string(s: str) -> bytes:
    """String: Varint长度 + UTF-8"""
    encoded = s.encode('utf-8')
    return encode_varint(len(encoded)) + encoded


def read_varint(data: bytes, pos: int) -> tuple:
    """读取 Varint，返回 (value, new_pos)"""
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


# ============================================================================
# TSBuffer 编码器 - 类型构建
# ============================================================================

class _TSBType:
    """TSBuffer 编码值类型基类"""
    def encode(self) -> bytes:
        raise NotImplementedError


class _TSBInterface(_TSBType):
    """
    Interface 类型: 一组命名字段
    properties: [(prop_id, type_tag, value), ...]
    type_tag 可以是 'string', 'number', 'enum', 'uint', 'int', 'boolean', 'bytes', 'literal', 或 _TSBType 实例
    """
    def __init__(self, properties: list):
        self.properties = properties

    def encode(self) -> bytes:
        valid = []
        for pid, pt, value in self.properties:
            if pt == 'literal':
                continue
            if isinstance(pt, _TSBType):
                valid.append((pid, pt, value))
                continue
            if value is None:
                continue
            if pt == 'string' and not value:
                continue
            valid.append((pid, pt, value))

        buf = bytearray()
        buf += encode_varint(len(valid))

        for pid, pt, value in valid:
            if isinstance(pt, _TSBType):
                payload = pt.encode()
                if isinstance(pt, (_TSBInterface, _TSBUnion, _TSBIntersection)):
                    lt = IB
                elif isinstance(pt, _TSBRef):
                    lt = IB
                else:
                    lt = LD
                buf += _encode_block(pid, lt, payload)
            elif pt == 'string':
                buf += _encode_block(pid, LD, encode_string(value))
            elif pt in ('enum', 'uint', 'int'):
                buf += _encode_block(pid, VI, encode_varint(int(value)))
            elif pt == 'number':
                buf += _encode_block(pid, B64, struct.pack('>d', float(value)))
            elif pt == 'boolean':
                buf += _encode_block(pid, VI, encode_varint(1 if value else 0))
            elif pt == 'bytes':
                buf += _encode_block(pid, LD, encode_varint(len(value)) + value)
            else:
                raise ValueError(f"Unknown type tag: {pt}")
        return bytes(buf)


class _TSBUnion(_TSBType):
    """Union 类型: members: [(member_id, type_tag, value), ...]"""
    def __init__(self, members: list):
        self.members = members

    def encode(self) -> bytes:
        valid = []
        for mid, pt, v in self.members:
            if isinstance(pt, _TSBType):
                valid.append((mid, pt, v))
                continue
            if v is not None:
                valid.append((mid, pt, v))

        buf = bytearray()
        buf += encode_varint(len(valid))

        for mid, pt, value in valid:
            if isinstance(pt, _TSBType):
                payload = pt.encode()
                lt = IB
            elif pt == 'string':
                payload = encode_string(value)
                lt = LD
            elif pt in ('int', 'enum', 'uint'):
                payload = encode_varint(int(value))
                lt = VI
            elif pt == 'number':
                payload = struct.pack('>d', float(value))
                lt = B64
            else:
                raise ValueError(f"Unknown union member type: {pt}")
            buf += _encode_member_id(mid, lt) + payload
        return bytes(buf)


class _TSBIntersection(_TSBType):
    """Intersection 类型: members: [(member_id, type_tag, value), ...]"""
    def __init__(self, members: list):
        self.members = members

    def encode(self) -> bytes:
        valid = []
        for mid, pt, v in self.members:
            if isinstance(pt, _TSBType):
                valid.append((mid, pt, v))
                continue
            if v is not None:
                valid.append((mid, pt, v))

        buf = bytearray()
        buf += encode_varint(len(valid))

        for mid, pt, value in valid:
            if isinstance(pt, _TSBType):
                payload = pt.encode()
                lt = IB
            elif pt in ('enum', 'uint', 'int'):
                payload = encode_varint(int(value))
                lt = VI
            elif pt == 'string':
                payload = encode_string(value)
                lt = LD
            elif pt == 'number':
                payload = struct.pack('>d', float(value))
                lt = B64
            else:
                raise ValueError(f"Unknown intersection member type: {pt}")
            buf += _encode_member_id(mid, lt) + payload
        return bytes(buf)


class _TSBArray(_TSBType):
    """Array 类型: 元素列表，编码为 Varint长度 + 每个元素编码"""
    def __init__(self, elements: list):
        """
        elements: [(type_tag, value), ...] 或 [_TSBType, ...]
        type_tag 可以是 'string', 'number', 'uint', 'int', 'boolean' 或 _TSBType 实例
        """
        self.elements = elements

    def encode(self) -> bytes:
        buf = bytearray()
        # 先编码元素数量
        buf += encode_varint(len(self.elements))
        for elem in self.elements:
            if isinstance(elem, tuple):
                pt, value = elem
                if isinstance(pt, _TSBType):
                    buf += pt.encode()
                elif pt == 'string':
                    buf += encode_string(value)
                elif pt in ('enum', 'uint', 'int'):
                    buf += encode_varint(int(value))
                elif pt == 'number':
                    buf += struct.pack('>d', float(value))
                elif pt == 'boolean':
                    buf += encode_varint(1 if value else 0)
            elif isinstance(elem, _TSBType):
                buf += elem.encode()
        return bytes(buf)


class _TSBRef(_TSBType):
    """Reference 类型: 引用另一个类型，避免重复编码"""
    def __init__(self, target: _TSBType):
        self.target = target

    def encode(self) -> bytes:
        return self.target.encode()


def _encode_block(prop_id: int, length_type: int, payload: bytes) -> bytes:
    """编码一个 Block: BlockID(Varint) + Payload"""
    block_id = ((_PROP + prop_id) << 2) | length_type
    return encode_varint(block_id) + payload


def _encode_member_id(member_id: int, length_type: int) -> bytes:
    """编码 Intersection/Union 的 member ID"""
    return encode_varint((member_id << 2) | length_type)


# ============================================================================
# TSB - 便捷编码 API
# ============================================================================

class TSB:
    """
    TSBuffer 编码构建器，提供类型安全的 DSL。
    
    使用示例:
        # 构建一个 Interface
        inner = TSB.interface([
            (0, 'string', "hello"),
            (1, 'uint', 42),
            (2, TSB.union([(0, 'string', "choice1")]), None),
        ])
        
        # 构建一个 Intersection
        req = TSB.intersection([
            (0, TSB.interface([(0, 'string', "name")]), None),
            (1, TSB.interface([(0, 'enum', 1)]), None),
        ])
        
        # 引用已有类型（避免重复构建）
        ref = TSB.ref(inner)
    """
    @staticmethod
    def interface(properties: list) -> _TSBInterface:
        """构建 Interface 类型。properties: [(prop_id, type_tag, value), ...]"""
        return _TSBInterface(properties)

    @staticmethod
    def union(members: list) -> _TSBUnion:
        """构建 Union 类型。members: [(member_id, type_tag, value), ...]"""
        return _TSBUnion(members)

    @staticmethod
    def intersection(members: list) -> _TSBIntersection:
        """构建 Intersection 类型。members: [(member_id, type_tag, value), ...]"""
        return _TSBIntersection(members)

    @staticmethod
    def ref(target: _TSBType) -> _TSBRef:
        """引用一个已构建的类型，避免重复编码"""
        return _TSBRef(target)


# ============================================================================
# TSBuffer 通用解码器
# ============================================================================

def tsb_decode(data: bytes, pos: int = 0) -> tuple:
    """
    通用 TSBuffer 解码器，递归解码任意 Interface/Intersection/Union。
    返回 (decoded_dict, new_pos)。
    
    - Interface: 解码为 {field_name/field_id: value}
    - Intersection: 合并所有 member 到顶层 dict
    - Union: 解码为 {member_id: value}
    - String: str (可读ASCII) 或 hex string (二进制)
    - Number(Enum/int): int
    - Number(default): float
    - Buffer: hex string
    - Boolean: bool
    
    注意：由于没有 schema 信息，字段名用数字 ID 表示（格式: f{raw_id}）。
    """
    if pos >= len(data):
        return None, pos

    count, pos = read_varint(data, pos)
    result = {}

    for _ in range(count):
        block_id, pos = read_varint(data, pos)
        raw_id = block_id >> 2
        lt = block_id & 3

        key = f"f{raw_id}"

        if lt == VI:  # Varint
            val, pos = read_varint(data, pos)
            result[key] = val
        elif lt == B64:  # Bit64
            if pos + 8 > len(data):
                break
            val = struct.unpack('>d', data[pos:pos + 8])[0]
            pos += 8
            if val == int(val) and abs(val) < 2 ** 53:
                result[key] = int(val)
            else:
                result[key] = val
        elif lt == LD:  # LengthDelimited
            length, pos = read_varint(data, pos)
            if pos + length > len(data):
                break
            raw = data[pos:pos + length]
            pos += length
            try:
                s = raw.decode('utf-8')
                if all(32 <= ord(c) < 127 or c in '\n\r\t' for c in s):
                    result[key] = s
                else:
                    result[key] = raw.hex()
            except UnicodeDecodeError:
                result[key] = raw.hex()
        elif lt == IB:  # IdBlock
            sub_result, pos = tsb_decode(data, pos)
            result[key] = sub_result
        else:
            break

    return result, pos


def _decode_hex_str(val: str) -> str:
    """尝试将 hex 字符串解码为 UTF-8 文本"""
    if not isinstance(val, str) or not val:
        return val
    if len(val) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in val):
        try:
            decoded = bytes.fromhex(val).decode('utf-8')
            if all(32 <= ord(c) < 127 or c in '\n\r\t' or
                   '\u4e00' <= c <= '\u9fff' or '\u3000' <= c <= '\u303f'
                   for c in decoded):
                return decoded
        except (ValueError, UnicodeDecodeError):
            pass
    return val


# ============================================================================
# 签名算法
# ============================================================================

def sign(body: dict, signkey: str) -> str:
    """
    签名算法 (与 Utils.sign() 一致):
    1. 按 key 字母序排序
    2. 拼接 key=value
    3. 嵌套对象 JSON 序列化 (无空格)
    4. 末尾追加 signkey
    5. MD5 哈希
    """
    sorted_keys = sorted(body.keys())
    parts = []
    for key in sorted_keys:
        data = body[key]
        if key is not None and data is not None:
            if isinstance(data, (dict, list)):
                data = json.dumps(data, separators=(',', ':'))
            parts.append(f"{key}={data}")
    sign_str = "&".join(parts) + signkey
    return hashlib.md5(sign_str.encode('utf-8')).hexdigest()


# ============================================================================
# TSRPC 响应数据结构
# ============================================================================

@dataclass
class TSRPCResponse:
    """标准化的 TSRPC 响应"""
    is_succ: bool = False
    res: dict = field(default_factory=dict)   # 成功时的业务响应数据
    err: dict = field(default_factory=dict)   # 失败时的错误信息 {message, code?, type?}
    is_binary: bool = False                    # 是否来自二进制解码
    raw: bytes = b""                           # 原始响应字节

    @property
    def err_message(self) -> str:
        """获取错误消息"""
        return self.err.get("message", "")

    def get(self, *path, default=None):
        """
        按路径从 res 中取值。
        例如: response.get("f0", "f10", "f11", "f12")
        """
        current = self.res
        for key in path:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return default
            if current is None:
                return default
        return current


@dataclass
class HttpResult:
    """HTTP 请求结果"""
    success: bool = False       # HTTP 200
    status_code: int = 0
    elapsed_ms: float = 0.0
    error: str = ""
    response: TSRPCResponse = field(default_factory=TSRPCResponse)


# ============================================================================
# TSRPC 客户端
# ============================================================================

class TSRPCClient:
    """
    通用 TSRPC 客户端，封装编解码和 HTTP 通信。

    使用示例:
        client = TSRPCClient("http://localhost:3000/dzqst-base")

        # 编码请求
        req_body = TSB.intersection([...])
        req_bytes = client.encode_request(3, req_body)

        # 发送请求
        result = client.post("/Account/FetchAccountData", req_bytes)

        # 检查结果
        if result.response.is_succ:
            print(result.response.res)
    """

    def __init__(self, server_url: str, sign_key: str = "", timeout: float = 30):
        """
        server_url: 服务器基础 URL，如 "http://localhost:3000/dzqst-base"
        sign_key: 签名密钥，用于 JSON 模式的签名（可为空）
        timeout: 默认请求超时（秒）
        """
        self.server_url = server_url.rstrip('/')
        self.sign_key = sign_key
        self.default_timeout = timeout
        self._session_local = threading.local()

    # ---- Session 管理 ----

    def _get_session(self) -> requests.Session:
        if not hasattr(self._session_local, 'session'):
            self._session_local.session = requests.Session()
        return self._session_local.session

    # ---- URL 处理 ----

    def _get_binary_url(self, api_path: str = "") -> str:
        """
        获取二进制模式的 URL（jsonHostPath）。
        
        api_path 如 "/Account/FetchAccountData"
        二进制模式下 URL 只需是 jsonHostPath（如 "/dzqst-base/"）
        """
        from urllib.parse import urlparse
        parsed = urlparse(self.server_url)
        path = parsed.path

        if api_path:
            full_path = path.rstrip('/') + '/' + api_path.lstrip('/')
        else:
            full_path = path

        parts = full_path.strip('/').split('/')
        if len(parts) >= 1:
            server_path = parts[0]
            binary_path = f"/{server_path}/"
        else:
            binary_path = "/"

        return f"{parsed.scheme}://{parsed.netloc}{binary_path}"

    def _get_json_url(self, api_path: str) -> str:
        """获取 JSON 模式的完整 URL"""
        api_path = api_path.lstrip('/')
        return f"{self.server_url}/{api_path}"

    # ---- 编码 ----

    def encode_request(self, service_id: int, inner: _TSBType) -> bytes:
        """
        编码 TSRPC 请求为二进制格式。
        
        service_id: API 的 serviceId
        inner: 内层业务数据（_TSBType 实例）
        
        返回 ServerInputData 编码后的字节。
        """
        inner_bytes = inner.encode()
        return _TSBInterface([
            (0, 'uint', service_id),
            (1, 'bytes', inner_bytes),
        ]).encode()

    # ---- 解码 ----

    def decode_response(self, raw_bytes: bytes) -> TSRPCResponse:
        """
        解码 TSRPC 二进制响应。
        
        先解 ServerOutputData 外层，再解内层 API 响应。
        返回标准化的 TSRPCResponse。
        """
        try:
            outer, _ = tsb_decode(raw_bytes, 0)
            if not isinstance(outer, dict):
                return TSRPCResponse(is_binary=True, raw=raw_bytes)

            # 检查 error (f11 = field id=1 = error → TsrpcErrorData)
            if 'f11' in outer:
                err_info = outer['f11']
                err_msg = "未知错误"
                err_code = None
                err_type_str = "ApiError"

                if isinstance(err_info, dict):
                    raw_msg = err_info.get('f10', '')
                    err_msg = _decode_hex_str(raw_msg) if isinstance(raw_msg, str) else str(raw_msg)
                    err_type_val = err_info.get('f11', None)
                    if isinstance(err_type_val, int):
                        err_type_str = TSRPC_ERROR_TYPE.get(err_type_val, "ApiError")
                    err_code = err_info.get('f12', None)
                    if isinstance(err_code, dict):
                        err_code = err_code.get('f10', err_code.get('f11', err_code))
                else:
                    err_msg = str(err_info)

                return TSRPCResponse(
                    is_succ=False,
                    err={"message": str(err_msg), "code": err_code, "type": err_type_str},
                    is_binary=True,
                    raw=raw_bytes,
                )

            # 检查 buffer (f10 = field id=0 = buffer)
            if 'f10' in outer:
                buf_hex = outer['f10']
                if isinstance(buf_hex, str) and len(buf_hex) > 0:
                    try:
                        inner_raw = bytes.fromhex(buf_hex)
                        inner_result, _ = tsb_decode(inner_raw, 0)
                        return TSRPCResponse(
                            is_succ=True,
                            res=inner_result if isinstance(inner_result, dict) else {},
                            is_binary=True,
                            raw=raw_bytes,
                        )
                    except Exception:
                        return TSRPCResponse(
                            is_succ=True,
                            res={"_binary_hex": buf_hex},
                            is_binary=True,
                            raw=raw_bytes,
                        )
                else:
                    return TSRPCResponse(is_succ=True, is_binary=True, raw=raw_bytes)

            return TSRPCResponse(is_binary=True, raw=raw_bytes)
        except Exception as e:
            return TSRPCResponse(is_binary=True, raw=raw_bytes)

    def decode_json_response(self, data: dict) -> TSRPCResponse:
        """
        解析 JSON 格式的 TSRPC 响应。
        JSON 格式: { isSucc, res?, err? }
        """
        is_succ = data.get("isSucc", False)
        res = data.get("res", {})
        err = data.get("err", {})
        if isinstance(res, str):
            res = {}
        if isinstance(err, str):
            err = {"message": err}
        return TSRPCResponse(is_succ=is_succ, res=res, err=err, is_binary=False)

    # ---- HTTP 请求 ----

    def post(self, api_path: str, req_bytes: bytes = None,
             json_req: dict = None, timeout: float = None,
             verbose: bool = False) -> HttpResult:
        """
        发送 TSRPC HTTP POST 请求。
        
        参数:
            api_path: API 路径，如 "/Account/FetchAccountData"
            req_bytes: 二进制请求体（binary 模式）
            json_req: JSON 请求体 dict（json 模式，会自动加签名）
            timeout: 超时时间（秒），默认使用构造时的 default_timeout
            verbose: 打印调试信息
        
        返回 HttpResult，其中 response 是解析后的 TSRPCResponse。
        
        注意：如果同时提供 req_bytes 和 json_req，优先使用 req_bytes（binary 模式）。
        """
        timeout = timeout or self.default_timeout

        if req_bytes is not None:
            return self._post_binary(api_path, req_bytes, timeout, verbose)
        elif json_req is not None:
            return self._post_json(api_path, json_req, timeout, verbose)
        else:
            result = HttpResult(error="No request body provided")
            return result

    def _post_binary(self, api_path: str, req_bytes: bytes,
                     timeout: float, verbose: bool) -> HttpResult:
        """发送二进制模式请求"""
        binary_url = self._get_binary_url(api_path)
        result = HttpResult()

        if verbose:
            print(f"  [TSRPC] Binary POST {binary_url} ({len(req_bytes)} bytes)", flush=True)

        result_container = {"result": None, "done": False}
        result_lock = threading.Lock()

        def _do_post():
            local_result = HttpResult()
            t0 = time.perf_counter()
            try:
                import socket
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(timeout + 10)
                try:
                    resp = self._get_session().post(
                        binary_url,
                        data=req_bytes,
                        headers={"Content-Type": "application/octet-stream"},
                        timeout=timeout,
                        verify=False,
                    )
                finally:
                    socket.setdefaulttimeout(old_timeout)

                local_result.elapsed_ms = (time.perf_counter() - t0) * 1000
                local_result.status_code = resp.status_code

                # 解码响应
                raw_bytes = resp.content
                try:
                    json_data = resp.json()
                    local_result.response = self.decode_json_response(json_data)
                except json.JSONDecodeError:
                    local_result.response = self.decode_response(raw_bytes)

                local_result.success = resp.status_code == 200
                if not local_result.success:
                    local_result.error = f"HTTP {resp.status_code}"

            except requests.Timeout:
                local_result.error = "Timeout"
                local_result.elapsed_ms = (time.perf_counter() - t0) * 1000
            except requests.ConnectionError as e:
                local_result.error = f"ConnectionError: {e}"
                local_result.elapsed_ms = (time.perf_counter() - t0) * 1000
            except OSError as e:
                local_result.error = f"OSError: {e}"
                local_result.elapsed_ms = (time.perf_counter() - t0) * 1000
            except Exception as e:
                local_result.error = str(e)
                local_result.elapsed_ms = (time.perf_counter() - t0) * 1000

            with result_lock:
                result_container["result"] = local_result
                result_container["done"] = True

        t_start = time.perf_counter()
        post_thread = threading.Thread(target=_do_post, daemon=True)
        post_thread.start()
        post_thread.join(timeout=timeout + 15)

        with result_lock:
            if result_container["done"]:
                return result_container["result"]

        result.error = f"HardTimeout({timeout + 15}s)"
        result.elapsed_ms = (time.perf_counter() - t_start) * 1000
        return result

    def _post_json(self, api_path: str, req: dict,
                   timeout: float, verbose: bool) -> HttpResult:
        """发送 JSON 模式请求"""
        json_url = self._get_json_url(api_path)
        result = HttpResult()

        # 加签名
        signed_req = req.copy()
        if self.sign_key:
            signed_req["signtime"] = int(time.time() * 1000)
            signed_req["sign"] = ""
            signed_req["sign"] = sign(signed_req, self.sign_key)

        if verbose:
            print(f"  [TSRPC] JSON POST {json_url}", flush=True)

        result_container = {"result": None, "done": False}
        result_lock = threading.Lock()

        def _do_post():
            local_result = HttpResult()
            t0 = time.perf_counter()
            try:
                import socket
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(timeout + 10)
                try:
                    resp = self._get_session().post(
                        json_url,
                        json=signed_req,
                        headers={"Content-Type": "application/json"},
                        timeout=timeout,
                        verify=False,
                    )
                finally:
                    socket.setdefaulttimeout(old_timeout)

                local_result.elapsed_ms = (time.perf_counter() - t0) * 1000
                local_result.status_code = resp.status_code

                try:
                    json_data = resp.json()
                    local_result.response = self.decode_json_response(json_data)
                except json.JSONDecodeError:
                    local_result.response = self.decode_response(resp.content)

                local_result.success = resp.status_code == 200
                if not local_result.success:
                    local_result.error = f"HTTP {resp.status_code}"

            except requests.Timeout:
                local_result.error = "Timeout"
                local_result.elapsed_ms = (time.perf_counter() - t0) * 1000
            except requests.ConnectionError as e:
                local_result.error = f"ConnectionError: {e}"
                local_result.elapsed_ms = (time.perf_counter() - t0) * 1000
            except OSError as e:
                local_result.error = f"OSError: {e}"
                local_result.elapsed_ms = (time.perf_counter() - t0) * 1000
            except Exception as e:
                local_result.error = str(e)
                local_result.elapsed_ms = (time.perf_counter() - t0) * 1000

            with result_lock:
                result_container["result"] = local_result
                result_container["done"] = True

        t_start = time.perf_counter()
        post_thread = threading.Thread(target=_do_post, daemon=True)
        post_thread.start()
        post_thread.join(timeout=timeout + 15)

        with result_lock:
            if result_container["done"]:
                return result_container["result"]

        result.error = f"HardTimeout({timeout + 15}s)"
        result.elapsed_ms = (time.perf_counter() - t_start) * 1000
        return result


# ============================================================================
# 枚举映射工具
# ============================================================================

class EnumMapping:
    """
    枚举值到 TSBuffer member id 的映射工具。
    
    使用示例:
        EM = EnumMapping({10000: 0, 0: 1, 1: 2, 2: 3})
        encoded = EM.to_tsb(1)  # → 2
    """
    def __init__(self, mapping: dict):
        self._map = mapping

    def to_tsb(self, value: int) -> int:
        """将枚举值转换为 TSBuffer member id"""
        return self._map.get(value, value)


# ============================================================================
# 通用响应提取工具
# ============================================================================

def deep_find(obj, key: str, depth: int = 0, max_depth: int = 10) -> Any:
    """
    递归搜索嵌套 dict/list 中指定 key 的值。
    用于从二进制解码后的响应中提取数据。
    """
    if depth > max_depth:
        return None
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            result = deep_find(v, key, depth + 1, max_depth)
            if result is not None:
                return result
    elif isinstance(obj, list):
        for item in obj:
            result = deep_find(item, key, depth + 1, max_depth)
            if result is not None:
                return result
    return None


def deep_find_hex_str(obj, min_len: int = 4, depth: int = 0, max_depth: int = 10) -> str:
    """
    递归搜索嵌套结构中 hex 编码的字符串值。
    用于从二进制解码后的响应中提取被 hex 编码的可读文本。
    """
    if depth > max_depth:
        return ""
    if isinstance(obj, dict):
        for v in obj.values():
            result = deep_find_hex_str(v, min_len, depth + 1, max_depth)
            if result:
                return result
    elif isinstance(obj, list):
        for item in obj:
            result = deep_find_hex_str(item, min_len, depth + 1, max_depth)
            if result:
                return result
    elif isinstance(obj, str) and len(obj) >= min_len:
        hex_decoded = _decode_hex_str(obj)
        if hex_decoded != obj and len(hex_decoded) >= min_len:
            return hex_decoded
    return ""
