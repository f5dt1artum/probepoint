"""Stateless ARM firmware ELF symbol resolution (v1).

The resolver works purely on the ELF image supplied in the request: it
never persists the image or the results, keeps no session state and does
not touch breakpoint records.  Only ELF32 little-endian ``EM_ARM`` files
are accepted.  Candidates are ``STT_FUNC`` symbols from ``SHT_SYMTAB``
and ``SHT_DYNSYM`` that are defined, have a non-empty name and a non-zero
size; ``STB_LOCAL`` candidates are dropped unless the request sets
``include_local``.  Query addresses and symbol start addresses are
matched with the Thumb bit cleared, and a hit requires
``start <= address < start + size``.
"""

from __future__ import annotations

MAX_ELF = 4 * 1024 * 1024  # 4 MiB decoded ELF per request
MAX_ADDRESSES = 256

_ELF_HEADER_LEN = 52
_SECTION_HEADER_LEN = 40
_SYMBOL_LEN = 16

_EI_CLASS = 4
_EI_DATA = 5
_ELFCLASS32 = 1
_ELFDATA2LSB = 1
_EM_ARM = 40

_SHT_SYMTAB = 2
_SHT_STRTAB = 3
_SHT_DYNSYM = 11

_STB_LOCAL = 0
_STB_GLOBAL = 1
_STB_WEAK = 2
_STT_FUNC = 2

_SHN_UNDEF = 0

_ADDRESS_SPACE = 1 << 32
_UINT32_MAX = _ADDRESS_SPACE - 1

_REQUIRED_FIELDS = frozenset({"elf", "addresses", "include_local"})
_HEXDIGITS = frozenset("0123456789abcdefABCDEF")

_BINDING_NAMES = {_STB_LOCAL: "local", _STB_GLOBAL: "global", _STB_WEAK: "weak"}
# Tie-break strength: global beats weak beats local.
_BINDING_RANK = {_STB_GLOBAL: 0, _STB_WEAK: 1, _STB_LOCAL: 2}


class SymbolError(Exception):
    """Validation or parse failure carrying the public error code/status."""

    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _uint(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise SymbolError("invalid_field", f"{field} must be an unsigned 32-bit integer")
    if value < 0 or value > _UINT32_MAX:
        raise SymbolError("invalid_field", f"{field} out of range for unsigned 32-bit integer")
    return value


def _hex_bytes(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        raise SymbolError("invalid_field", f"{field} must be a hex string")
    if len(value) % 2 != 0 or any(c not in _HEXDIGITS for c in value):
        raise SymbolError(
            "invalid_field", f"{field} must be even-length hex without prefix or separators"
        )
    return bytes.fromhex(value)


def _check_fields(body: object) -> dict:
    if not isinstance(body, dict):
        raise SymbolError("invalid_request", "request body must be a JSON object")
    missing = _REQUIRED_FIELDS - body.keys()
    extra = body.keys() - _REQUIRED_FIELDS
    if missing:
        raise SymbolError("invalid_field", f"missing field(s): {', '.join(sorted(missing))}")
    if extra:
        raise SymbolError("invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}")
    return body


def _u16(elf: bytes, offset: int) -> int:
    return int.from_bytes(elf[offset : offset + 2], "little")


def _u32(elf: bytes, offset: int) -> int:
    return int.from_bytes(elf[offset : offset + 4], "little")


def _read_name(elf: bytes, strtab_offset: int, strtab_size: int, name_offset: int) -> str:
    if name_offset >= strtab_size:
        raise SymbolError("invalid_elf", "symbol name offset outside the string table")
    start = strtab_offset + name_offset
    end = elf.find(b"\x00", start, strtab_offset + strtab_size)
    if end < 0:
        raise SymbolError("invalid_elf", "symbol name is not NUL-terminated within the string table")
    raw = elf[start:end]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise SymbolError("invalid_elf", "symbol name is not valid UTF-8") from None


def _collect_symbols(elf: bytes, include_local: bool) -> list[tuple[int, int, str, int, int, int]]:
    """Parse the section headers and gather candidate function symbols.

    Each candidate is ``(start, size, name, binding, section_index,
    symbol_index)`` with the Thumb bit already cleared from ``start``.
    """
    if len(elf) < _ELF_HEADER_LEN:
        raise SymbolError("invalid_elf", "ELF header is truncated")
    if elf[:4] != b"\x7fELF":
        raise SymbolError("invalid_elf", "bad ELF magic")
    if elf[_EI_CLASS] != _ELFCLASS32:
        raise SymbolError("unsupported_elf", "only ELF32 (ELFCLASS32) images are supported", 422)
    if elf[_EI_DATA] != _ELFDATA2LSB:
        raise SymbolError("unsupported_elf", "only little-endian (ELFDATA2LSB) images are supported", 422)
    if _u16(elf, 18) != _EM_ARM:
        raise SymbolError("unsupported_elf", "only EM_ARM images are supported", 422)

    e_shoff = _u32(elf, 32)
    e_shentsize = _u16(elf, 46)
    e_shnum = _u16(elf, 48)
    if e_shoff == 0:
        raise SymbolError("symbol_table_not_found", "ELF has no section header table", 422)
    if e_shentsize < _SECTION_HEADER_LEN:
        raise SymbolError("invalid_elf", "section header entry size is too small")
    if e_shnum == 0:
        # Extended numbering: the real count lives in section 0's sh_size.
        if e_shoff + _SECTION_HEADER_LEN > len(elf):
            raise SymbolError("invalid_elf", "section header table is truncated")
        e_shnum = _u32(elf, e_shoff + 20)
        if e_shnum == 0:
            raise SymbolError("symbol_table_not_found", "ELF has no sections", 422)
    if e_shoff + e_shentsize * e_shnum > len(elf):
        raise SymbolError("invalid_elf", "section header table extends past the end of the image")

    tables: list[tuple[int, int, int, int, int]] = []
    for index in range(e_shnum):
        base = e_shoff + index * e_shentsize
        sh_type = _u32(elf, base + 4)
        if sh_type in (_SHT_SYMTAB, _SHT_DYNSYM):
            tables.append(
                (
                    index,
                    _u32(elf, base + 16),  # sh_offset
                    _u32(elf, base + 20),  # sh_size
                    _u32(elf, base + 24),  # sh_link
                    _u32(elf, base + 36),  # sh_entsize
                )
            )
    if not tables:
        raise SymbolError(
            "symbol_table_not_found", "ELF has neither SHT_SYMTAB nor SHT_DYNSYM", 422
        )

    candidates: list[tuple[int, int, str, int, int, int]] = []
    for section_index, sh_offset, sh_size, sh_link, sh_entsize in tables:
        if sh_offset + sh_size > len(elf):
            raise SymbolError("invalid_elf", "symbol table extends past the end of the image")
        if sh_link >= e_shnum:
            raise SymbolError("invalid_elf", "symbol table string section index is out of range")
        str_base = e_shoff + sh_link * e_shentsize
        if _u32(elf, str_base + 4) != _SHT_STRTAB:
            raise SymbolError("invalid_elf", "symbol table link does not name a string table")
        str_offset = _u32(elf, str_base + 16)
        str_size = _u32(elf, str_base + 20)
        if str_offset + str_size > len(elf):
            raise SymbolError("invalid_elf", "string table extends past the end of the image")

        entsize = sh_entsize or _SYMBOL_LEN
        if entsize < _SYMBOL_LEN:
            raise SymbolError("invalid_elf", "symbol table entry size is too small")
        for symbol_index in range(sh_size // entsize):
            entry = sh_offset + symbol_index * entsize
            st_name = _u32(elf, entry)
            st_value = _u32(elf, entry + 4)
            st_size = _u32(elf, entry + 8)
            st_info = elf[entry + 12]
            st_shndx = _u16(elf, entry + 14)
            if st_info & 0x0F != _STT_FUNC:
                continue
            if st_shndx == _SHN_UNDEF:
                continue
            if st_size == 0 or st_name == 0:
                continue
            name = _read_name(elf, str_offset, str_size, st_name)
            if not name:
                continue
            start = st_value & ~1
            if start + st_size > _ADDRESS_SPACE:
                raise SymbolError("invalid_elf", "symbol range crosses the end of the 32-bit address space")
            binding = st_info >> 4
            if binding not in _BINDING_RANK:
                continue
            if binding == _STB_LOCAL and not include_local:
                continue
            candidates.append((start, st_size, name, binding, section_index, symbol_index))
    return candidates


def _lookup(
    candidates: list[tuple[int, int, str, int, int, int]], address: int
) -> tuple[int, int, str, int] | None:
    best: tuple[int, int, str, int] | None = None
    best_key: tuple[int, int, int, int, int] | None = None
    for start, size, name, binding, section_index, symbol_index in candidates:
        if start <= address < start + size:
            key = (-start, _BINDING_RANK[binding], size, section_index, symbol_index)
            if best_key is None or key < best_key:
                best_key = key
                best = (start, size, name, binding)
    return best


def resolve(body: object) -> dict[str, object]:
    """Resolve query addresses against the function symbols of an ARM ELF.

    Returns ``{"results": [...]}`` with one entry per submitted address,
    in input order and with duplicates preserved.  A hit carries ``name``,
    ``symbol_address``, ``offset``, ``size`` and ``binding``; on a miss
    those five fields are JSON ``null``.  The original ``address`` is
    always echoed back unchanged.
    """
    fields = _check_fields(body)

    elf = _hex_bytes(fields["elf"], "elf")
    if len(elf) > MAX_ELF:
        raise SymbolError("invalid_field", f"elf exceeds {MAX_ELF} decoded bytes")

    addresses = fields["addresses"]
    if not isinstance(addresses, list):
        raise SymbolError("invalid_field", "addresses must be an array")
    if not 1 <= len(addresses) <= MAX_ADDRESSES:
        raise SymbolError(
            "invalid_field", f"addresses must contain between 1 and {MAX_ADDRESSES} entries"
        )
    queried = [_uint(value, "address") for value in addresses]

    include_local = fields["include_local"]
    if not isinstance(include_local, bool):
        raise SymbolError("invalid_field", "include_local must be a boolean")

    candidates = _collect_symbols(elf, include_local)

    results: list[dict[str, object]] = []
    for raw_address in queried:
        address = raw_address & ~1
        hit = _lookup(candidates, address)
        entry: dict[str, object] = {"address": raw_address}
        if hit is None:
            entry.update(
                {"name": None, "symbol_address": None, "offset": None, "size": None, "binding": None}
            )
        else:
            start, size, name, binding = hit
            entry.update(
                {
                    "name": name,
                    "symbol_address": start,
                    "offset": address - start,
                    "size": size,
                    "binding": _BINDING_NAMES[binding],
                }
            )
        results.append(entry)
    return {"results": results}
