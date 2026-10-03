"""Stateless symbol resolution for ARM firmware ELF files (v1).

The resolver works purely from the ELF image supplied in the request: it
never opens files, keeps no session state and does not touch breakpoint
records.  Only 32-bit, little-endian, ``EM_ARM`` objects are accepted;
function symbols are read from ``SHT_SYMTAB``/``SHT_DYNSYM`` sections and
matched against the requested addresses after clearing the Thumb bit.
"""

from __future__ import annotations

import struct

MAX_ELF_SIZE = 1 << 22  # 4 MiB decoded
MAX_ADDRESSES = 256
_UINT32_MAX = (1 << 32) - 1
_ADDRESS_SPACE = 1 << 32  # first address past 0xffffffff

_FIELDS = frozenset({"elf", "addresses", "include_local"})

_HEXDIGITS = frozenset("0123456789abcdefABCDEF")

# ELF constants (only the values this resolver needs).
_ELF_MAGIC = b"\x7fELF"
_ELFCLASS32 = 1
_ELFDATA2LSB = 1
_EM_ARM = 40
_EHDR32_SIZE = 52
_SHDR32_SIZE = 40
_SYM32_SIZE = 16

_SHT_SYMTAB = 2
_SHT_STRTAB = 3
_SHT_NOBITS = 8
_SHT_DYNSYM = 11

_STB_LOCAL = 0
_STB_GLOBAL = 1
_STB_WEAK = 2
_STT_FUNC = 2
_SHN_UNDEF = 0

_BINDING_RANK = {_STB_GLOBAL: 0, _STB_WEAK: 1, _STB_LOCAL: 2}
_BINDING_NAME = {_STB_GLOBAL: "global", _STB_WEAK: "weak", _STB_LOCAL: "local"}


class SymbolResolveError(Exception):
    """Validation or ELF parsing failure carrying the public code/status."""

    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _hex_bytes(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        raise SymbolResolveError("invalid_field", f"{field} must be a hex string")
    if len(value) % 2 != 0 or any(c not in _HEXDIGITS for c in value):
        raise SymbolResolveError(
            "invalid_field", f"{field} must be even-length hex without prefix or separators"
        )
    return bytes.fromhex(value)


def _check_fields(body: object) -> dict:
    if not isinstance(body, dict):
        raise SymbolResolveError("invalid_request", "request body must be a JSON object")
    missing = _FIELDS - body.keys()
    extra = body.keys() - _FIELDS
    if missing:
        raise SymbolResolveError(
            "invalid_field", f"missing field(s): {', '.join(sorted(missing))}"
        )
    if extra:
        raise SymbolResolveError(
            "invalid_field", f"unexpected field(s): {', '.join(sorted(extra))}"
        )
    return body


def _parse_addresses(value: object) -> list[int]:
    if not isinstance(value, list):
        raise SymbolResolveError("invalid_field", "addresses must be an array")
    if not 1 <= len(value) <= MAX_ADDRESSES:
        raise SymbolResolveError(
            "invalid_field", f"addresses must contain between 1 and {MAX_ADDRESSES} items"
        )
    addresses: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int):
            raise SymbolResolveError(
                "invalid_field", "each address must be an unsigned 32-bit integer"
            )
        if not 0 <= item <= _UINT32_MAX:
            raise SymbolResolveError(
                "invalid_field", "address out of range for unsigned 32-bit integer"
            )
        addresses.append(item)
    return addresses


def _invalid_elf(message: str) -> SymbolResolveError:
    return SymbolResolveError("invalid_elf", message)


def _read_sections(data: bytes) -> list[tuple]:
    """Parse and bounds-check every section header.

    Returns tuples ``(type, offset, size, link, entsize)`` in section
    index order.  ``SHT_NOBITS`` sections occupy no file bytes and are
    exempt from the range check.
    """
    if len(data) < _EHDR32_SIZE:
        raise _invalid_elf("ELF header is truncated")
    (
        _e_type,
        e_machine,
        _e_version,
        _e_entry,
        _e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        _e_phentsize,
        _e_phnum,
        e_shentsize,
        e_shnum,
        _e_shstrndx,
    ) = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
    if e_machine != _EM_ARM:
        raise SymbolResolveError(
            "unsupported_elf", "only EM_ARM ELF files are supported", status=422
        )
    if e_shoff == 0 or e_shnum == 0:
        return []
    if e_shentsize < _SHDR32_SIZE:
        raise _invalid_elf("section header entry is too small")
    table_end = e_shoff + e_shnum * e_shentsize
    if table_end > len(data):
        raise _invalid_elf("section header table is truncated")

    sections: list[tuple] = []
    for index in range(e_shnum):
        entry = e_shoff + index * e_shentsize
        (
            _sh_name,
            sh_type,
            _sh_flags,
            _sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            _sh_info,
            _sh_addralign,
            sh_entsize,
        ) = struct.unpack_from("<IIIIIIIIII", data, entry)
        if sh_type != _SHT_NOBITS and sh_offset + sh_size > len(data):
            raise _invalid_elf(f"section {index} data extends past the end of the file")
        sections.append((sh_type, sh_offset, sh_size, sh_link, sh_entsize))
    return sections


def _symbol_name(strtab: bytes, name_offset: int) -> str:
    if name_offset >= len(strtab):
        raise _invalid_elf("symbol name references past the end of its string table")
    end = strtab.find(0, name_offset)
    if end < 0:
        raise _invalid_elf("symbol name is not terminated in its string table")
    raw = strtab[name_offset:end]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _invalid_elf("symbol name is not valid UTF-8") from None


def _collect_symbols(
    data: bytes, sections: list[tuple], include_local: bool
) -> list[tuple]:
    """Gather usable ``STT_FUNC`` symbols from both symbol table kinds."""
    tables = [
        (index, section)
        for index, section in enumerate(sections)
        if section[0] in (_SHT_SYMTAB, _SHT_DYNSYM)
    ]
    if not tables:
        raise SymbolResolveError(
            "symbol_table_not_found",
            "ELF file contains neither SHT_SYMTAB nor SHT_DYNSYM",
            status=422,
        )

    candidates: list[tuple] = []
    for table_index, (
        _stype,
        st_offset,
        st_size,
        st_link,
        st_entsize,
    ) in tables:
        if st_link >= len(sections):
            raise _invalid_elf(f"symbol table section {table_index} link is out of range")
        link_type, str_offset, str_size, _str_link, _str_entsize = sections[st_link]
        if link_type != _SHT_STRTAB:
            raise _invalid_elf(f"symbol table section {table_index} does not link a string table")
        strtab = data[str_offset : str_offset + str_size]

        entry_size = st_entsize if st_entsize else _SYM32_SIZE
        if entry_size < _SYM32_SIZE:
            raise _invalid_elf(f"symbol table section {table_index} entry is too small")
        if st_size % entry_size != 0:
            raise _invalid_elf(f"symbol table section {table_index} has a trailing partial entry")

        for entry_index in range(st_size // entry_size):
            record = st_offset + entry_index * entry_size
            (
                st_name,
                st_value,
                st_size_sym,
                st_info,
                _st_other,
                st_shndx,
            ) = struct.unpack_from("<IIIBBH", data, record)
            bind = st_info >> 4
            sym_type = st_info & 0xF
            if sym_type != _STT_FUNC:
                continue
            if st_shndx == _SHN_UNDEF:
                continue
            if st_size_sym == 0:
                continue
            if not include_local and bind == _STB_LOCAL:
                continue
            if bind not in _BINDING_RANK:
                continue

            name = _symbol_name(strtab, st_name)
            if not name:
                continue
            start = st_value & ~1
            end = start + st_size_sym
            if end > _ADDRESS_SPACE:
                raise _invalid_elf(
                    f"symbol table section {table_index} entry {entry_index} range overflows "
                    "the 32-bit address space"
                )
            candidates.append(
                (start, end, st_size_sym, bind, name, table_index, entry_index)
            )
    return candidates


def _parse_elf(data: bytes, include_local: bool) -> list[tuple]:
    if len(data) < 16 or data[:4] != _ELF_MAGIC:
        raise _invalid_elf("data is not an ELF file")
    ei_class = data[4]
    ei_data = data[5]
    if ei_class != _ELFCLASS32:
        raise SymbolResolveError(
            "unsupported_elf", "only 32-bit ELF files are supported", status=422
        )
    if ei_data != _ELFDATA2LSB:
        raise SymbolResolveError(
            "unsupported_elf", "only little-endian ELF files are supported", status=422
        )
    sections = _read_sections(data)
    return _collect_symbols(data, sections, include_local)


def _resolve_one(address: int, symbols: list[tuple]) -> dict[str, object]:
    target = address & ~1
    best = None
    best_key = None
    for start, end, size, bind, name, table_index, entry_index in symbols:
        if not start <= target < end:
            continue
        # Greatest start wins, then global over weak over local, then
        # smallest size, then smallest (table section index, entry index).
        key = (-start, _BINDING_RANK[bind], size, table_index, entry_index)
        if best_key is None or key < best_key:
            best_key = key
            best = (start, size, bind, name)
    item: dict[str, object] = {"address": address}
    if best is None:
        item.update(
            {"name": None, "symbol_address": None, "offset": None, "size": None, "binding": None}
        )
    else:
        start, size, bind, name = best
        item.update(
            {
                "name": name,
                "symbol_address": start,
                "offset": target - start,
                "size": size,
                "binding": _BINDING_NAME[bind],
            }
        )
    return item


def resolve_symbols(body: object) -> dict[str, object]:
    """Validate a resolve request and look each address up in the ELF.

    Returns ``{"results": [...]}`` with one entry per requested address,
    in request order and with duplicates preserved.  The ELF image and
    the resolved data are never retained.
    """
    fields = _check_fields(body)

    elf = _hex_bytes(fields["elf"], "elf")
    if len(elf) > MAX_ELF_SIZE:
        raise SymbolResolveError(
            "invalid_field", f"elf exceeds {MAX_ELF_SIZE} decoded bytes"
        )

    addresses = _parse_addresses(fields["addresses"])

    include_local = fields["include_local"]
    if not isinstance(include_local, bool):
        raise SymbolResolveError("invalid_field", "include_local must be a boolean")

    symbols = _parse_elf(elf, include_local)
    results = [_resolve_one(address, symbols) for address in addresses]
    return {"results": results}
