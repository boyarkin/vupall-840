# -*- coding: utf-8 -*-
"""Язык меню и часовой пояс в прошивке Panasonic Strada vupall.dat.

Команды:
  python vupall_tool.py info
  python vupall_tool.py extract
  python vupall_tool.py set-language 2
  python vupall_tool.py set-timezone +3
  python vupall_tool.py apply

set-language и set-timezone сразу записывают значение в vupall.dat.
apply записывает в vupall.dat уже измененные extracted\\HMIBZ_CE.INI и extracted\\default.hv.
Перед первой записью оригинальный файл копируется в vupall.dat.bak.
"""

import argparse
import hashlib
import importlib.util
import os
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
FIRMWARE = os.path.join(ROOT, "vupall.dat")
BACKUP = os.path.join(ROOT, "vupall.dat.bak")
OUT_DIR = os.path.join(ROOT, "extracted")
DECOMPRESSOR = os.path.join(ROOT, "wincedecompr.py")

BIN_OFFSET = 0x1BD0
IMAGE_BASE_VA = 0x80E00000
# Линейная копия того же образа CE. Конец совпадает с границей секции.
LINEAR_OFFSET = 0x4A9227B
# Диапазоны, чьи MD5 лежат в заголовке. Слоты ищутся по текущему дайджесту.
SECTIONS = (
    (0x1BD0, 0x4A9227B),
    (0x4A9227B, 0x958DA47),
)

WANTED = {
    "HMIBZ_CE.INI",
    "user.hv",
    "boot.hv",
    "default.hv",
    "SYS_PATH.INI",
    "SM_SET.ini",
    "CARWINGS.ini",
}

LANGUAGE_NAMES = {
    1: "японский",
    2: "английский",
    3: "корейский",
    13: "традиционный китайский",
}


def load_module():
    spec = importlib.util.spec_from_file_location("wincedecompr", DECOMPRESSOR)
    if spec is None or spec.loader is None:
        raise SystemExit("Не найден wincedecompr.py рядом со скриптом.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_decompressor():
    return load_module().CEDecompressROM


def load_firmware(path):
    data = open(path, "rb").read()
    if data[BIN_OFFSET : BIN_OFFSET + 7] != b"B000FF\n":
        raise SystemExit("В файле нет образа Windows CE (сигнатура B000FF).")
    image_start, image_len = struct.unpack_from("<II", data, BIN_OFFSET + 7)
    if image_start != IMAGE_BASE_VA:
        raise SystemExit("Неожиданный адрес образа: %#x" % image_start)
    mem = bytearray(image_len)
    pos = BIN_OFFSET + 15
    records = 0
    while True:
        addr, length, checksum = struct.unpack_from("<III", data, pos)
        pos += 12
        if addr == 0:
            break
        blob = data[pos : pos + length]
        pos += length
        if len(blob) != length or (sum(blob) & 0xFFFFFFFF) != checksum:
            raise SystemExit("Повреждена запись образа #%d" % records)
        mem[addr - image_start : addr - image_start + length] = blob
        records += 1
    return data, image_start, mem, records


def cstr(mem, image_start, va):
    off = va - image_start
    end = mem.find(b"\x00", off, off + 260)
    if end < 0:
        return ""
    return bytes(mem[off:end]).decode("ascii", "replace")


def iter_files(image_start, mem):
    def u32(va):
        return struct.unpack_from("<I", mem, va - image_start)[0]

    ptoc = u32(image_start + 0x44)
    nummods = u32(ptoc + 0x10)
    numfiles = u32(ptoc + 0x30)
    files_va = ptoc + 0x54 + nummods * 32
    for index in range(numfiles):
        entry = files_va + index * 28
        attr, _lo, _hi, real, comp, name_va, load = struct.unpack_from(
            "<IIIIIII", mem, entry - image_start
        )
        yield cstr(mem, image_start, name_va), real, comp, load, attr, name_va, entry


def read_file(image_start, mem, decomp, name, real, comp, load, attr):
    blob = bytes(mem[load - image_start : load - image_start + comp])
    if attr & 0x800:
        out = bytearray(real + 4096)
        size = decomp(blob, comp, out, real, 0, 1, 4096)
        if size < 0:
            raise SystemExit("Не удалось распаковать %s" % name)
        return bytes(out[:size])
    return blob[:real]


def decode_text(blob):
    if blob.startswith(b"\xff\xfe") or (len(blob) > 3 and blob[1] == 0 and blob[3] == 0):
        return blob.decode("utf-16")
    for encoding in ("cp932", "utf-8", "latin1"):
        try:
            return blob.decode(encoding)
        except UnicodeDecodeError:
            continue
    return blob.decode("latin1")


def collect(path):
    _raw, image_start, mem, records = load_firmware(path)
    decomp = load_decompressor()
    found = {}
    meta = {}
    for name, real, comp, load, attr, name_va, entry in iter_files(image_start, mem):
        if name in WANTED:
            found[name] = read_file(image_start, mem, decomp, name, real, comp, load, attr)
            meta[name] = (real, comp, load, attr, name_va, entry)
    missing = WANTED - set(found)
    if missing:
        raise SystemExit("В образе нет файлов: %s" % ", ".join(sorted(missing)))
    return found, records, image_start, mem, meta


def language_default(text):
    for line in text.splitlines():
        if line.startswith("DEFAULT_LANGUAGE="):
            return line.split("=", 1)[1].strip()
    return None


def enabled_languages(text):
    values = []
    for line in text.splitlines():
        if line.startswith("LANGUAGE_") and "=" in line:
            key, value = line.split("=", 1)
            if value.strip() == "1":
                values.append(key.split("_", 1)[1])
    return values


def utf16_string(blob, offset):
    chars = []
    pos = offset
    while pos + 1 < len(blob):
        code = struct.unpack_from("<H", blob, pos)[0]
        pos += 2
        if code == 0:
            break
        chars.append(chr(code))
        if len(chars) > 80:
            break
    return "".join(chars)


def default_zone_name(blob):
    needle = "Default".encode("utf-16le")
    start = 0
    while True:
        index = blob.find(needle, start)
        if index < 0:
            break
        name = utf16_string(blob, index + len(needle))
        if "Standard Time" in name:
            return name
        start = index + 2
    raise SystemExit("В default.hv не найдено имя текущего часового пояса.")


def zone_bias_offsets(blob, zone_name):
    token = zone_name.encode("utf-16le")
    marker = "TZI".encode("utf-16le")
    offsets = []
    start = 0
    while True:
        index = blob.find(token, start)
        if index < 0:
            break
        window = blob[index : index + len(token) + 96]
        marker_at = window.find(marker)
        if marker_at >= 0:
            offsets.append(index + marker_at + len(marker))
        start = index + 2
    if not offsets:
        raise SystemExit("У пояса %s нет значения TZI." % zone_name)
    return offsets


def active_timezone(blob):
    name = default_zone_name(blob)
    offset = zone_bias_offsets(blob, name)[0]
    bias = struct.unpack_from("<i", blob, offset)[0]
    return name, bias, offset


def format_hours(bias):
    hours = -bias / 60.0
    if hours == int(hours):
        return "%+d" % int(hours)
    return "%+.1f" % hours


def command_info(path):
    found, records, _image_start, _mem, _meta = collect(path)
    text = decode_text(found["HMIBZ_CE.INI"])
    zone, bias, _offset = active_timezone(found["default.hv"])
    print("Файл: %s" % path)
    print("Записей образа CE: %d" % records)
    print("Язык меню по умолчанию: %s" % language_default(text))
    print("Включенные языки:")
    for code in enabled_languages(text):
        number = int(code)
        print("  %s — %s" % (code, LANGUAGE_NAMES.get(number, "нет текстов в этой прошивке")))
    print("Текущий пояс: %s, UTC%s (смещение Windows %d мин)." % (zone, format_hours(bias), bias))
    locale = found["user.hv"]
    if "ja-JP".encode("utf-16le") in locale:
        print("Локаль Windows CE: ja-JP (0411)")
    elif "en-US".encode("utf-16le") in locale:
        print("Локаль Windows CE: en-US (0409)")


def command_extract(path):
    found, _records, _image_start, _mem, _meta = collect(path)
    os.makedirs(OUT_DIR, exist_ok=True)
    for name, blob in sorted(found.items()):
        dest = os.path.join(OUT_DIR, name)
        open(dest, "wb").write(blob)
        print(dest)
    text = decode_text(found["HMIBZ_CE.INI"])
    zone, bias, _offset = active_timezone(found["default.hv"])
    print("Язык меню сейчас: %s" % language_default(text))
    for code in enabled_languages(text):
        number = int(code)
        print("  %s — %s" % (code, LANGUAGE_NAMES.get(number, "нет текстов в этой прошивке")))
    print("Текущий пояс: %s, UTC%s." % (zone, format_hours(bias)))


def set_language_text(text, number):
    enabled = enabled_languages(text)
    token = "%03d" % number
    if token not in enabled:
        raise SystemExit(
            "Язык %s в этой прошивке не включен. Доступны: %s" % (token, ", ".join(enabled))
        )
    lines = []
    changed = False
    for line in text.splitlines(keepends=True):
        if line.startswith("DEFAULT_LANGUAGE="):
            ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            line = "DEFAULT_LANGUAGE=%d%s" % (number, ending)
            changed = True
        lines.append(line)
    if not changed:
        raise SystemExit("В HMIBZ_CE.INI нет строки DEFAULT_LANGUAGE.")
    return "".join(lines).encode("cp932")


def set_timezone_hive(blob, hours):
    if hours < -12 or hours > 14:
        raise SystemExit("Пояс должен быть от -12 до +14 часов.")
    bias = -int(round(hours * 60))
    zone, _old, offset = active_timezone(blob)
    updated = bytearray(blob)
    for bias_at in zone_bias_offsets(blob, zone):
        struct.pack_into("<i", updated, bias_at, bias)
    return bytes(updated), zone, bias, offset


def compress_lzx(plain, window):
    work = tempfile.mkdtemp(prefix="vupall-cab-")
    try:
        open(os.path.join(work, "in.bin"), "wb").write(plain)
        directive = (
            ".Set Cabinet=on\r\n"
            ".Set Compress=on\r\n"
            ".Set CompressionType=LZX\r\n"
            ".Set CompressionMemory=%d\r\n"
            ".Set CabinetNameTemplate=out.cab\r\n"
            ".Set DiskDirectoryTemplate=%s\r\n"
            "in.bin\r\n" % (window, work)
        )
        open(os.path.join(work, "f.ddf"), "w", encoding="ascii", newline="").write(directive)
        proc = subprocess.run(
            ["makecab.exe", "/F", "f.ddf"],
            cwd=work,
            capture_output=True,
        )
        if proc.returncode != 0:
            detail = (proc.stdout or b"").decode("utf-8", "replace")
            raise SystemExit("makecab не сжал блок:\n%s" % detail)
        cab = open(os.path.join(work, "out.cab"), "rb").read()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if cab[:4] != b"MSCF":
        raise SystemExit("makecab вернул не cabinet.")
    flags = struct.unpack_from("<H", cab, 30)[0]
    if flags != 0:
        raise SystemExit("Неожиданные флаги cabinet: %#x" % flags)
    coff, count, _tcomp = struct.unpack_from("<IHH", cab, 36)
    if count != 1:
        raise SystemExit("Блок сжался в %d фрагмента, а нужен один." % count)
    _csum, cb_data, cb_plain = struct.unpack_from("<IHH", cab, coff)
    if cb_plain != len(plain):
        raise SystemExit("makecab вернул %d байт вместо %d." % (cb_plain, len(plain)))
    return cab[coff + 8 : coff + 8 + cb_data]


def chunk_spans(blob):
    usize = int.from_bytes(blob[:3], "little")
    blocks = ((usize - 1) >> 12) + 2
    spans = []
    previous = blocks * 3
    for index in range(1, blocks):
        end = int.from_bytes(blob[index * 3 : index * 3 + 3], "little")
        spans.append((previous, end))
        previous = end
    return usize, spans


def decompress_chunk(module, chunk):
    out = bytearray(65536)
    status, size = module.bin_decompress_rom(chunk, len(chunk), out)
    if status != 0 or size < 0:
        raise SystemExit("Не распаковался сжатый блок прошивки.")
    return bytes(out[:size])


class FitError(Exception):
    pass


def make_chunk(window, plain, payload, size):
    chunk = bytearray(size)
    struct.pack_into("<IIII", chunk, 0, window, len(plain), len(payload), len(plain))
    chunk[16 : 16 + len(payload)] = payload
    return bytes(chunk)


def compress_chunk(plain, old_chunk, budget):
    preferred = struct.unpack_from("<I", old_chunk, 0)[0]
    windows = [preferred] + [window for window in range(15, 22) if window != preferred]
    shortest = None
    for window in windows:
        payload = compress_lzx(plain, window)
        if shortest is None or len(payload) < len(shortest[1]):
            shortest = (window, payload)
        if len(payload) <= len(old_chunk) - 16:
            return make_chunk(window, plain, payload, len(old_chunk))
    window, payload = shortest
    need = 16 + len(payload)
    extra = need - len(old_chunk)
    if extra > budget:
        raise FitError("нужно еще %d байт, свободно %d" % (extra, budget))
    return make_chunk(window, plain, payload, need)


def rebuild_compressed(old_blob, new_plain, module, max_extra):
    usize, spans = chunk_spans(old_blob)
    if len(new_plain) != usize:
        blocks = ((len(new_plain) - 1) >> 12) + 2
        if blocks != len(spans) + 1:
            raise FitError("новый файл меняет число блоков сжатия")
    budget = max_extra
    chunks = []
    for index, (start, end) in enumerate(spans):
        plain = new_plain[index * 4096 : (index + 1) * 4096]
        old_chunk = bytes(old_blob[start:end])
        if len(new_plain) == usize and decompress_chunk(module, old_chunk) == plain:
            chunks.append(old_chunk)
            continue
        chunk = compress_chunk(plain, old_chunk, budget)
        budget -= max(0, len(chunk) - len(old_chunk))
        chunks.append(chunk)
    table = (len(spans) + 1) * 3
    cursor = table
    ends = []
    for chunk in chunks:
        cursor += len(chunk)
        ends.append(cursor)
    extra = cursor - len(old_blob)
    if extra < 0:
        chunks[-1] += b"\x00" * (-extra)
        cursor = len(old_blob)
        extra = 0
        ends[-1] = cursor
    if extra > max_extra:
        raise FitError("файл вырос на %d байт, свободно %d" % (extra, max_extra))
    out = bytearray(cursor)
    out[0:3] = len(new_plain).to_bytes(3, "little")
    for index, end in enumerate(ends):
        out[3 + index * 3 : 6 + index * 3] = end.to_bytes(3, "little")
    cursor = table
    for chunk in chunks:
        out[cursor : cursor + len(chunk)] = chunk
        cursor += len(chunk)
    check = bytearray(len(new_plain) + 4096)
    size = module.CEDecompressROM(bytes(out), len(out), check, len(new_plain), 0, 1, 4096)
    if size != len(new_plain) or bytes(check[:size]) != new_plain:
        raise FitError("после сжатия файл не совпал с исходным текстом")
    return bytes(out)


def blank_line_variants(plain):
    text = plain.decode("cp932")
    lines = text.splitlines(keepends=True)
    variants = []
    for index, line in enumerate(lines):
        if line in ("\r\n", "\n"):
            variants.append("".join(lines[:index] + lines[index + 1 :]).encode("cp932"))
    return variants


def section_md5_slots(data):
    header = data[:BIN_OFFSET]
    slots = []
    for start, end in SECTIONS:
        digest = hashlib.md5(data[start:end]).digest()
        found = []
        pos = 0
        while True:
            index = header.find(digest, pos)
            if index < 0:
                break
            found.append(index)
            pos = index + 1
        if not found:
            raise SystemExit("В заголовке нет MD5 диапазона %#x-%#x." % (start, end))
        slots.append((start, end, found))
    return slots


def refresh_section_md5(data, slots):
    for start, end, places in slots:
        digest = hashlib.md5(data[start:end]).digest()
        for place in places:
            data[place : place + 16] = digest


def refresh_header_sum(data):
    data[0:4] = b"\x00\x00\x00\x00"
    total = sum(data[4:BIN_OFFSET]) & 0xFFFFFFFF
    struct.pack_into("<I", data, 0, total)


def backup_firmware():
    if os.path.isfile(BACKUP):
        return
    print("Копирую оригинал в %s" % BACKUP)
    shutil.copy2(FIRMWARE, BACKUP)


def image_files(image_start, mem):
    rows = []
    for name, real, comp, load, attr, _name_va, entry in iter_files(image_start, mem):
        rows.append(
            {
                "name": name,
                "real": real,
                "comp": comp,
                "load": load,
                "attr": attr,
                "entry": entry,
            }
        )
    rows.sort(key=lambda item: item["load"])
    return rows


def growth_room(mem, image_start, files, name):
    index = next(i for i, item in enumerate(files) if item["name"] == name)
    room = 0
    end = files[index]["load"] + files[index]["comp"]
    for item in files[index + 1 :]:
        gap = item["load"] - end
        if gap < 0:
            break
        if gap:
            hole = mem[end - image_start : item["load"] - image_start]
            if any(hole):
                break
            room += gap
        end = item["load"] + item["comp"]
        if room >= 64:
            break
    return room


def place_file(mem, image_start, files, name, new_blob, new_real):
    index = next(i for i, item in enumerate(files) if item["name"] == name)
    current = files[index]
    extra = len(new_blob) - current["comp"]
    if extra < 0:
        raise FitError("сжатый файл стал короче, это не записано")
    if extra:
        moves = []
        cursor = current["load"] + len(new_blob)
        for item in files[index + 1 :]:
            if item["load"] >= cursor:
                break
            delta = cursor - item["load"]
            moves.append((item, delta))
            cursor = item["load"] + delta + item["comp"]
        else:
            raise FitError("после %s нет места" % name)
        if moves:
            last, delta = moves[-1]
            old_end = last["load"] + last["comp"]
            hole = mem[old_end - image_start : old_end + delta - image_start]
            if any(hole):
                raise FitError("после %s нет свободных байт" % name)
        for item, delta in reversed(moves):
            src = item["load"] - image_start
            block = bytes(mem[src : src + item["comp"]])
            mem[src + delta : src + delta + item["comp"]] = block
            item["load"] += delta
            struct.pack_into("<I", mem, item["entry"] + 24 - image_start, item["load"])
        print("%s: файл в образе удлинен на %d байт, сдвинуто файлов: %d" % (name, extra, len(moves)))
    mem[current["load"] - image_start : current["load"] - image_start + len(new_blob)] = new_blob
    struct.pack_into("<I", mem, current["entry"] + 16 - image_start, len(new_blob))
    struct.pack_into("<I", mem, current["entry"] + 12 - image_start, new_real)
    current["comp"] = len(new_blob)
    current["real"] = new_real


def commit_image(path, mem, image_start):
    data = bytearray(open(path, "rb").read())
    slots = section_md5_slots(data)
    pos = BIN_OFFSET + 15
    while True:
        addr, length, _checksum = struct.unpack_from("<III", data, pos)
        if addr == 0:
            break
        chunk = mem[addr - image_start : addr - image_start + length]
        data[pos + 12 : pos + 12 + length] = chunk
        struct.pack_into("<I", data, pos + 8, sum(chunk) & 0xFFFFFFFF)
        pos += 12 + length
    data[LINEAR_OFFSET : LINEAR_OFFSET + len(mem)] = mem
    refresh_section_md5(data, slots)
    refresh_header_sum(data)
    if os.path.abspath(path) == os.path.abspath(FIRMWARE):
        backup_firmware()
    open(path, "wb").write(data)
    print("Записано: %s" % path)


def compressed_blob(image_start, mem, load, comp):
    return bytes(mem[load - image_start : load - image_start + comp])


def store_files(path, new_plains):
    """new_plains: имя файла образа -> новые распакованные байты."""
    _found, _records, image_start, mem, meta = collect(path)
    module = load_module()
    files = image_files(image_start, mem)
    written = {}
    changed = False
    for name, new_plain in new_plains.items():
        real, comp, load, attr, _name_va, _entry = meta[name]
        if not attr & 0x800:
            raise SystemExit("%s в образе не сжат, запись этого файла не предусмотрена." % name)
        old_plain = read_file(image_start, mem, module.CEDecompressROM, name, real, comp, load, attr)
        if old_plain == new_plain:
            written[name] = new_plain
            continue
        old_blob = compressed_blob(image_start, mem, load, comp)
        room = growth_room(mem, image_start, files, name)
        variants = [new_plain]
        if name == "HMIBZ_CE.INI":
            variants.extend(blank_line_variants(new_plain))
        chosen = None
        new_blob = None
        errors = []
        for plain in variants:
            try:
                new_blob = rebuild_compressed(old_blob, plain, module, room)
                chosen = plain
                break
            except FitError as exc:
                errors.append(str(exc))
        if new_blob is None:
            raise SystemExit("Не удалось записать %s: %s" % (name, errors[-1] if errors else ""))
        place_file(mem, image_start, files, name, new_blob, len(chosen))
        written[name] = chosen
        changed = True
        if chosen != new_plain:
            print("%s: убрана пустая строка, иначе сжатый файл не помещается в образ." % name)
    if not changed:
        print("vupall.dat уже содержит эти значения.")
        return
    commit_image(path, mem, image_start)
    os.makedirs(OUT_DIR, exist_ok=True)
    for name, plain in written.items():
        open(os.path.join(OUT_DIR, name), "wb").write(plain)


def command_set_language(path, number):
    found, _records, _image_start, _mem, _meta = collect(path)
    text = decode_text(found["HMIBZ_CE.INI"])
    new_plain = set_language_text(text, number)
    print("DEFAULT_LANGUAGE=%d (%s)" % (number, LANGUAGE_NAMES.get(number, "")))
    store_files(path, {"HMIBZ_CE.INI": new_plain})


def command_set_timezone(path, hours):
    found, _records, _image_start, _mem, _meta = collect(path)
    new_plain, zone, bias, _offset = set_timezone_hive(found["default.hv"], hours)
    print("Пояс %s теперь UTC%s (смещение Windows %d мин)." % (zone, format_hours(bias), bias))
    print("Летнее время у этого пояса не добавляется: меняется только постоянное смещение.")
    store_files(path, {"default.hv": new_plain})


def command_apply(path):
    ini_path = os.path.join(OUT_DIR, "HMIBZ_CE.INI")
    hive_path = os.path.join(OUT_DIR, "default.hv")
    if not os.path.isfile(ini_path) or not os.path.isfile(hive_path):
        raise SystemExit("Сначала измените файлы в extracted или выполните extract.")
    store_files(
        path,
        {
            "HMIBZ_CE.INI": open(ini_path, "rb").read(),
            "default.hv": open(hive_path, "rb").read(),
        },
    )


def main():
    parser = argparse.ArgumentParser(description="Язык и часовой пояс в vupall.dat")
    parser.add_argument("command", choices=("info", "extract", "set-language", "set-timezone", "apply"))
    parser.add_argument("value", nargs="?", help="Номер языка или пояс, например +3")
    parser.add_argument("--firmware", default=FIRMWARE, help=argparse.SUPPRESS)
    args = parser.parse_args()

    if not os.path.isfile(args.firmware):
        raise SystemExit("Нет файла %s" % args.firmware)

    if args.command == "info":
        command_info(args.firmware)
    elif args.command == "extract":
        command_extract(args.firmware)
    elif args.command == "set-language":
        if args.value is None:
            raise SystemExit("Укажите номер языка, например: python vupall_tool.py set-language 2")
        command_set_language(args.firmware, int(args.value))
    elif args.command == "set-timezone":
        if args.value is None:
            raise SystemExit("Укажите пояс, например: python vupall_tool.py set-timezone +3")
        command_set_timezone(args.firmware, float(args.value))
    elif args.command == "apply":
        command_apply(args.firmware)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
