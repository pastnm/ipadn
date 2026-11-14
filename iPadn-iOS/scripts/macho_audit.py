#!/usr/bin/env python3
"""Read device Mach-O deployment commands and imports without Apple tools.

This is a static audit, not an iOS launch or API-availability test. SDK version
is reported separately from minimum OS. All slices must satisfy the limit.
"""
import struct

THIN = {
    b'\xce\xfa\xed\xfe': ('<', False), b'\xcf\xfa\xed\xfe': ('<', True),
    b'\xfe\xed\xfa\xce': ('>', False), b'\xfe\xed\xfa\xcf': ('>', True),
}
FAT = {
    b'\xca\xfe\xba\xbe': ('>', False), b'\xbe\xba\xfe\xca': ('<', False),
    b'\xca\xfe\xba\xbf': ('>', True), b'\xbf\xba\xfe\xca': ('<', True),
}
LC_BUILD_VERSION = 0x32
LC_VERSION_MIN_IPHONEOS = 0x25
DYLIB_COMMANDS = {0xC: 'strong', 0x80000018: 'weak', 0x8000001F: 'reexport',
                  0x20: 'lazy', 0x80000023: 'upward'}


def is_macho(data):
    return data[:4] in THIN or data[:4] in FAT


def version_tuple(value):
    parts = str(value).split('.')
    if not 1 <= len(parts) <= 3 or any(not p.isascii() or not p.isdigit() for p in parts):
        raise ValueError('Invalid OS version: ' + str(value))
    return tuple(int(p) for p in parts) + (0,) * (3 - len(parts))


def packed_version(value):
    return '%d.%d.%d' % (value >> 16, (value >> 8) & 255, value & 255)


def maximum_for_member(name):
    return '16.1' if any(part.endswith('.appex') for part in name.split('/')) else '16.0'


def region(data, offset, size):
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError('Mach-O range outside file: offset=%d size=%d' % (offset, size))
    return data[offset:offset + size]


def unpack(fmt, data, offset=0):
    return struct.unpack(fmt, region(data, offset, struct.calcsize(fmt)))


def cstring(data, offset, end=None):
    end = len(data) if end is None else end
    if not 0 <= offset < end <= len(data):
        raise ValueError('Invalid Mach-O string offset')
    nul = data.find(b'\0', offset, end)
    if nul < 0:
        raise ValueError('Unterminated Mach-O string')
    return data[offset:nul].decode('utf-8', errors='backslashreplace'), nul + 1


def leb_end(data, offset):
    # Skip either ULEB128 or SLEB128; only operand length matters to this audit.
    for _ in range(10):
        value = region(data, offset, 1)[0]
        offset += 1
        if not value & 128:
            return offset
    raise ValueError('Overlong LEB128 in bind stream')


def bind_imports(data):
    imports = set()
    offset = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        opcode, immediate = byte & 0xF0, byte & 15
        if opcode == 0x40:
            name, offset = cstring(data, offset)
            imports.add((name, bool(immediate & 1)))
        elif opcode in (0x20, 0x60, 0x70, 0x80, 0xA0):
            offset = leb_end(data, offset)
        elif opcode == 0xC0:
            offset = leb_end(data, leb_end(data, offset))
        elif opcode == 0xD0:
            if immediate == 0:
                offset = leb_end(data, offset)
            elif immediate != 1:
                raise ValueError('Unknown threaded bind opcode')
        elif opcode not in (0, 0x10, 0x30, 0x50, 0x90, 0xB0):
            raise ValueError('Unknown bind opcode: 0x%x' % byte)
    return imports


def chained_imports(data, endian):
    header = unpack(endian + '7I', data)
    version, _, imports_offset, symbols_offset, count, kind, symbols_format = header
    if version != 0 or symbols_format != 0:
        raise ValueError('Unsupported chained fixups version or symbol compression')
    sizes = {1: 4, 2: 8, 3: 16}
    if kind not in sizes:
        if count == 0:
            return set()
        raise ValueError('Unsupported chained imports format: %d' % kind)
    region(data, imports_offset, count * sizes[kind])
    region(data, symbols_offset, len(data) - symbols_offset)
    imports = set()
    for index in range(count):
        entry = imports_offset + index * sizes[kind]
        if kind == 3:
            word, = unpack(endian + 'Q', data, entry)
            name_offset, weak = word >> 32, bool((word >> 16) & 1)
        else:
            word, = unpack(endian + 'I', data, entry)
            name_offset, weak = word >> 9, bool((word >> 8) & 1)
        name, _ = cstring(data, symbols_offset + name_offset)
        imports.add((name, weak))
    return imports


def thin_audit(data):
    if data[:4] not in THIN:
        raise ValueError('Fat slice is not a thin Mach-O')
    endian, wide = THIN[data[:4]]
    header_size = 32 if wide else 28
    header = unpack(endian + ('8I' if wide else '7I'), data)
    _, cpu, subtype, filetype, count, command_bytes, flags = header[:7]
    if count > command_bytes // 8:
        raise ValueError('Impossible Mach-O command count')
    region(data, header_size, command_bytes)
    command_end = header_size + command_bytes
    offset = header_size
    deployments, dependencies, imports, sources = [], [], set(), set()
    for _ in range(count):
        cmd, size = unpack(endian + 'II', data, offset)
        if size < 8 or size % 4 or offset + size > command_end:
            raise ValueError('Invalid load command size')
        command = region(data, offset, size)
        if cmd == LC_BUILD_VERSION:
            platform, minimum, sdk, tools = unpack(endian + '4I', command, 8)
            if 24 + tools * 8 > size:
                raise ValueError('Truncated LC_BUILD_VERSION tools')
            deployments.append({'command': 'LC_BUILD_VERSION', 'platform': platform,
                                'minimum_os': packed_version(minimum), 'sdk': packed_version(sdk)})
        elif cmd == LC_VERSION_MIN_IPHONEOS:
            minimum, sdk = unpack(endian + 'II', command, 8)
            deployments.append({'command': 'LC_VERSION_MIN_IPHONEOS', 'platform': 2,
                                'minimum_os': packed_version(minimum), 'sdk': packed_version(sdk)})
        elif cmd in DYLIB_COMMANDS:
            name_offset, _, _, _ = unpack(endian + '4I', command, 8)
            if name_offset < 24:
                raise ValueError('Invalid dylib name offset')
            name, _ = cstring(command, name_offset)
            dependencies.append({'name': name, 'linkage': DYLIB_COMMANDS[cmd]})
        elif cmd == 2:  # LC_SYMTAB, nlist/nlist_64 undefined external entries
            symoff, nsyms, stroff, strsize = unpack(endian + '4I', command, 8)
            strings = region(data, stroff, strsize)
            entry_size = 16 if wide else 12
            region(data, symoff, nsyms * entry_size)
            for index in range(nsyms):
                values = unpack(endian + ('IBBHQ' if wide else 'IBBHI'), data, symoff + index * entry_size)
                name_offset, symbol_type, _, description, value = values
                if symbol_type & 0xE0 or symbol_type & 0x0E or not symbol_type & 1 or value:
                    continue
                name, _ = cstring(strings, name_offset)
                imports.add((name, bool(description & 0x40)))  # N_WEAK_REF
            sources.add('LC_SYMTAB undefined externals')
        elif cmd in (0x22, 0x80000022):  # LC_DYLD_INFO[_ONLY]
            fields = unpack(endian + '10I', command, 8)
            # Weak-bind describes coalesced definitions, not weak imports.
            for start, length in ((fields[2], fields[3]), (fields[6], fields[7])):
                imports.update(bind_imports(region(data, start, length)))
            sources.add('dyld bind/lazy-bind streams')
        elif cmd == 0x80000034:  # LC_DYLD_CHAINED_FIXUPS
            start, length = unpack(endian + 'II', command, 8)
            imports.update(chained_imports(region(data, start, length), endian))
            sources.add('dyld chained import table')
        offset += size
    if offset != command_end:
        raise ValueError('Load commands do not consume sizeofcmds')
    return {'cpu_type': cpu, 'cpu_subtype': subtype, 'bits': 64 if wide else 32,
            'file_type': filetype, 'header_flags': flags, 'deployment': deployments,
            'dylib_dependencies': dependencies, 'import_sources': sorted(sources),
            'strong_imports': sorted({name for name, weak in imports if not weak}),
            'weak_imports': sorted({name for name, weak in imports if weak})}


def audit_macho(data):
    if data[:4] in THIN:
        return [thin_audit(data)]
    if data[:4] not in FAT:
        raise ValueError('Not a Mach-O file')
    endian, wide = FAT[data[:4]]
    count, = unpack(endian + 'I', data, 4)
    if not 1 <= count <= 64:
        raise ValueError('Invalid fat slice count')
    entry_size = 32 if wide else 20
    table_end = 8 + count * entry_size
    region(data, 0, table_end)
    results, ranges = [], []
    for index in range(count):
        entry = unpack(endian + ('IIQQII' if wide else '5I'), data, 8 + index * entry_size)
        cpu, subtype, start, length, alignment = entry[:5]
        if start < table_end or length == 0 or alignment > 63 or start % (1 << alignment):
            raise ValueError('Invalid fat slice bounds/alignment')
        if any(start < end and begin < start + length for begin, end in ranges):
            raise ValueError('Overlapping fat slices')
        ranges.append((start, start + length))
        result = thin_audit(region(data, start, length))
        if result['cpu_type'] != cpu or result['cpu_subtype'] != subtype:
            raise ValueError('Fat architecture does not match slice header')
        results.append(result)
    return results


def deployment_errors(slices, maximum):
    errors = []
    for index, item in enumerate(slices):
        label = 'slice %d' % index
        if item['cpu_type'] not in (12, 0x100000C):
            errors.append(label + ': not an ARM iOS device architecture')
        if not item['deployment']:
            errors.append(label + ': missing device minimum-OS load command')
        for deployment in item['deployment']:
            if deployment['platform'] != 2:
                errors.append(label + ': not PLATFORM_IOS (platform %s)' % deployment['platform'])
            if version_tuple(deployment['minimum_os']) > version_tuple(maximum):
                errors.append(label + ': minimum %s exceeds %s' % (deployment['minimum_os'], maximum))
    return errors
