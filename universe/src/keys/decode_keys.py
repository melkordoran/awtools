from __future__ import annotations

import base64
from pathlib import Path
from typing import Iterable, Tuple

KEY_DIR = Path(__file__).parent

PRIVATE_KEY_PATH = KEY_DIR / "aw.priv"
PUBLIC_KEY_PATH = KEY_DIR / "aw.pub"
PRIVATE_OUTPUT = KEY_DIR / "aw_private.pem"
PUBLIC_OUTPUT = KEY_DIR / "aw_public.pem"


class AwKeyFormatError(Exception):
    """Raised when the legacy ActiveWorlds key format is invalid."""


def _read_chunks(data: bytes, lengths: Iterable[int]) -> Tuple[int, ...]:
    parts = []
    offset = 0
    for length in lengths:
        end = offset + length
        if end > len(data):
            raise AwKeyFormatError("Key data is shorter than expected")
        parts.append(int.from_bytes(data[offset:end], "big"))
        offset = end
    if offset != len(data):
        raise AwKeyFormatError("Unexpected extra data at end of key")
    return tuple(parts)


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return length.to_bytes(1, "big")
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return (0x80 | len(encoded)).to_bytes(1, "big") + encoded


def _der_int(value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    return b"\x02" + _der_length(len(body)) + body


def _der_sequence(components: Iterable[bytes]) -> bytes:
    body = b"".join(components)
    return b"\x30" + _der_length(len(body)) + body


def _load_public_key(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) != 260:
        raise AwKeyFormatError("Public key should be 260 bytes")

    bits = int.from_bytes(data[0:4], "little")
    if bits != 512:
        raise AwKeyFormatError(f"Unexpected RSA modulus size: {bits} bits")

    modulus, exponent = _read_chunks(data[4:], (128, 128))
    der = _der_sequence((_der_int(modulus), _der_int(exponent)))
    pem_body = base64.encodebytes(der).decode().replace("\n", "")
    wrapped = "\n".join(pem_body[i : i + 64] for i in range(0, len(pem_body), 64))
    return (
        "-----BEGIN RSA PUBLIC KEY-----\n"
        + wrapped
        + "\n-----END RSA PUBLIC KEY-----\n"
    ).encode()


def _load_private_key(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) != 708:
        raise AwKeyFormatError("Private key should be 708 bytes")

    bits = int.from_bytes(data[0:4], "little")
    if bits != 512:
        raise AwKeyFormatError(f"Unexpected RSA modulus size: {bits} bits")

    values = _read_chunks(
        data[4:],
        (128, 128, 128, 64, 64, 64, 64, 64),
    )
    modulus, public_exponent, exponent, p, q, dp, dq, qi = values

    der = _der_sequence(
        (
            _der_int(0),
            _der_int(modulus),
            _der_int(public_exponent),
            _der_int(exponent),
            _der_int(p),
            _der_int(q),
            _der_int(dp),
            _der_int(dq),
            _der_int(qi),
        )
    )

    pem_body = base64.encodebytes(der).decode().replace("\n", "")
    wrapped = "\n".join(pem_body[i : i + 64] for i in range(0, len(pem_body), 64))
    return (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + wrapped
        + "\n-----END RSA PRIVATE KEY-----\n"
    ).encode()


def main() -> None:
    public_pem = _load_public_key(PUBLIC_KEY_PATH)
    PRIVATE_OUTPUT.write_bytes(_load_private_key(PRIVATE_KEY_PATH))
    PUBLIC_OUTPUT.write_bytes(public_pem)


if __name__ == "__main__":
    main()
