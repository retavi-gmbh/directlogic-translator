#!/usr/bin/env python3
"""
DirectSOFT / DirectLogic DL405 PLC Project Parser
==================================================
Parst DirectSOFT-Projektdateien (.ESD, .PRJ, .LCD, .LDA, .LDO, .PRT, .VD, .TLS)
und extrahiert Symboltabelle und Ladder-Logik-Programm.

Dateiformate:
- .ESD: Element/Symbol Description - Symboltabelle (unverschlüsselt, Latin-1/ISO 8859-1)
- .PRJ: Project - Hauptprojektdatei mit Ladder-Code (verschlüsselt)
- .LCD: Ladder Code Document - Ladder-Referenzdaten (unverschlüsselt)
- .LDA: Ladder Addresses - Adresszuweisungstabelle (verschlüsselt)
- .LDO: Ladder Object - Objektcode (verschlüsselt)
- .PRT: Print/Project Text - Drucktext/Beschreibung (verschlüsselt)
- .VD:  V-Data registers - V-Speicher-Initialisierung (verschlüsselt, dient als Keystream)
- .TLS: Tool Settings (verschlüsselt)
- .INF: Project Info (Klartext INI)
- .wsp: Workspace (Klartext INI)

Verschlüsselung:
  Alle "PLC Data File."-Dateien verwenden XOR-Verschlüsselung.
  Der Schlüsselstrom wird aus der VD-Datei gewonnen (VD enthält bei uninitialisierten
  V-Registern nur Nullen, daher sind die verschlüsselten Bytes = Keystream).
  Der Keystream hat 7 individuelle Anfangsbytes, danach ein 50-Byte-Zyklus.
"""

import struct
import sys
import os
from collections import defaultdict

# ============================================================================
# Verschlüsselung
# ============================================================================

HEADER_MAGIC = b'PLC Data File.     \x1a'
HEADER_LEN = 20
KEYSTREAM_UNIQUE_PREFIX = 7
KEYSTREAM_CYCLE = 50


def load_keystream(vd_path):
    """Extrahiert den XOR-Keystream aus der VD-Datei.

    Die VD-Datei enthält verschlüsselte V-Register-Daten. Da die meisten
    V-Register mit 0x00 initialisiert sind, entspricht der verschlüsselte
    Inhalt weitgehend dem Keystream. Allerdings können einzelne V-Register
    Initialwerte != 0 haben, die den Keystream kontaminieren.

    Lösung: Der Keystream besteht aus 7 individuellen Prefix-Bytes und
    einem 50-Byte-Zyklus. Wir extrahieren den Zyklus aus den ersten
    sauberen Bytes und rekonstruieren den kompletten Keystream daraus.
    Damit werden V-Register-Initialwerte herausgefiltert.
    """
    with open(vd_path, 'rb') as f:
        data = f.read()
    if not data.startswith(HEADER_MAGIC):
        raise ValueError(f"{vd_path}: Kein gültiger 'PLC Data File.' Header")
    raw = data[HEADER_LEN:]

    # Die 7 Prefix-Bytes und der 50-Byte-Zyklus (Bytes 7..56) sind
    # in den ersten 57 Bytes zuverlässig, da die niedrigen V-Register
    # (V0-V27) typischerweise nicht initialisiert werden.
    prefix = raw[:KEYSTREAM_UNIQUE_PREFIX]
    cycle = raw[KEYSTREAM_UNIQUE_PREFIX:KEYSTREAM_UNIQUE_PREFIX + KEYSTREAM_CYCLE]

    # Rekonstruiere sauberen Keystream über die gesamte Länge
    clean = bytearray(len(raw))
    for i in range(len(raw)):
        if i < KEYSTREAM_UNIQUE_PREFIX:
            clean[i] = prefix[i]
        else:
            clean[i] = cycle[(i - KEYSTREAM_UNIQUE_PREFIX) % KEYSTREAM_CYCLE]

    return bytes(clean)


def decrypt_file(filepath, keystream):
    """Entschlüsselt eine 'PLC Data File.'-Datei mittels XOR-Keystream."""
    with open(filepath, 'rb') as f:
        data = f.read()
    if not data.startswith(HEADER_MAGIC):
        raise ValueError(f"{filepath}: Kein gültiger Header")
    encrypted = data[HEADER_LEN:]
    result = bytearray(len(encrypted))
    for i in range(len(encrypted)):
        if i < len(keystream):
            result[i] = encrypted[i] ^ keystream[i]
        else:
            cycle_pos = KEYSTREAM_UNIQUE_PREFIX + ((i - KEYSTREAM_UNIQUE_PREFIX) % KEYSTREAM_CYCLE)
            result[i] = encrypted[i] ^ keystream[cycle_pos]
    return bytes(result)


# ============================================================================
# ESD-Parser: Symboltabelle
# ============================================================================

ESD_RECORD_SIZE = 0xCD  # 205 Bytes pro Record
ESD_FIRST_RECORD_OFFSET = 0x0408  # Beginn des Header-Blocks im ESD
ESD_FIRST_RECORD_START = 0x04C9   # Erster eigentlicher Record
ESD_FIRST_RECORD_LEN = 211        # Erster Record etwas länger
ESD_TEXT_OFFSET_FIRST = 45         # Text-Offset im ersten Record
ESD_TEXT_OFFSET = 39               # Text-Offset in normalen Records

# Adresstyp-Marker im ESD
ESD_TYPE_MAP = {
    0x08: 'X',    # Eingänge (Inputs)
    0x09: 'Y',    # Ausgänge (Outputs)
    0x0a: 'C',    # Steuerrelais (Control Relays)
    0x0b: 'T',    # Timer
    0x0c: 'CT',   # Zähler (Counters)
    0x0d: 'T',    # Timer/Stufen (Stages) - shared type 0x0D
    0x0e: 'SP',   # Spezialrelais
    0x0f: 'SP',   # Spezialrelais (alt.)
    0x11: 'V',    # Datenregister (V-Memory)
}


def decode_esd_text(raw_bytes):
    """Dekodiert ESD-Textdaten (Latin-1 mit 0x0D 0x0D 0x0A als Zeilenumbruch)."""
    result = bytearray()
    i = 0
    while i < len(raw_bytes):
        b = raw_bytes[i]
        if b == 0x00:
            # Prüfe ob nach der Null noch relevanter Text kommt
            # (einige Records haben mehrzeilige Beschreibungen mit Null-Lücken)
            remaining = raw_bytes[i:]
            next_text = -1
            for j in range(1, min(10, len(remaining))):
                if remaining[j] >= 0x20:
                    next_text = j
                    break
            if next_text > 0 and next_text <= 5:
                result.append(0x20)  # Ersetze Lücke durch Leerzeichen
                i += next_text
                continue
            break
        if (i + 2 < len(raw_bytes) and b == 0x0D
                and raw_bytes[i+1] == 0x0D and raw_bytes[i+2] == 0x0A):
            result.append(0x0A)
            i += 3
        else:
            result.append(b)
            i += 1
    return bytes(result).decode('latin-1', errors='replace').strip()


def format_address(addr_type, addr_value):
    """Formatiert eine PLC-Adresse je nach Typ."""
    prefix = ESD_TYPE_MAP.get(addr_type, f'?{addr_type:02X}')
    if prefix in ('X', 'Y'):
        return f"{prefix}{addr_value:o}"  # Oktal für Ein/Ausgänge
    elif prefix == 'V':
        return f"V{addr_value:o}"  # Oktal für V-Memory
    elif prefix in ('T', 'CT'):
        return f"{prefix}{addr_value:o}"  # Oktal (DL405 convention)
    elif prefix == 'C':
        return f"C{addr_value:o}"  # Oktal
    elif prefix == 'S':
        return f"S{addr_value:o}"  # Oktal
    elif prefix in ('SP',):
        return f"SP{addr_value}"
    else:
        return f"{prefix}{addr_value}"


def parse_esd(filepath):
    """Parst die ESD-Symboltabelle und gibt eine Liste von Symbolen zurück."""
    with open(filepath, 'rb') as f:
        data = f.read()

    symbols = []

    # Erster Record (leicht abweichendes Format)
    pos = ESD_FIRST_RECORD_START
    if pos + ESD_FIRST_RECORD_LEN <= len(data):
        rec = data[pos:pos + ESD_FIRST_RECORD_LEN]
        marker_type = rec[0]
        addr_value = rec[1]
        text = decode_esd_text(rec[ESD_TEXT_OFFSET_FIRST:])
        if text:
            addr = format_address(marker_type, addr_value)
            meta_bytes = rec[2:9]
            symbols.append({
                'type': ESD_TYPE_MAP.get(marker_type, f'?{marker_type:02X}'),
                'address': addr,
                'addr_raw': addr_value,
                'marker': marker_type,
                'description': text,
            })
        pos += ESD_FIRST_RECORD_LEN

    # Restliche Records (je 205 Bytes)
    while pos + ESD_RECORD_SIZE <= len(data):
        rec = data[pos:pos + ESD_RECORD_SIZE]
        marker_type = rec[0]
        addr_value = rec[1]
        text = decode_esd_text(rec[ESD_TEXT_OFFSET:])

        if text or marker_type in ESD_TYPE_MAP:
            addr = format_address(marker_type, addr_value)
            symbols.append({
                'type': ESD_TYPE_MAP.get(marker_type, f'?{marker_type:02X}'),
                'address': addr,
                'addr_raw': addr_value,
                'marker': marker_type,
                'description': text if text else '(leer)',
            })

        pos += ESD_RECORD_SIZE

    return symbols


# ============================================================================
# PRJ-Parser: Ladder-Code
# ============================================================================

# DL405/DL430 Ladder-Instruktionsformat (aus Binäranalyse rekonstruiert):
#   Jede Instruktion = 8 Bytes:
#     Byte 0: Opcode
#     Byte 1: Flags (meist 0x00, bei Konstanten-Ops 0x01)
#     Byte 2: Adresstyp
#     Byte 3: 0x00 (Padding)
#     Byte 4-7: Operand (32-bit Little-Endian)

# Adresstyp-Codes
ADDR_TYPE = {
    0x00: None,    # Kein Typ / Spezial
    0x08: 'X',     # Eingang (Input) - Oktal
    0x09: 'Y',     # Ausgang (Output) - Oktal
    0x0A: 'C',     # Steuerrelais (Control Relay) - Oktal
    0x0B: 'T',     # Timer - Dezimal
    0x0C: 'CT',    # Zähler (Counter) - Dezimal
    0x0D: 'TS',    # Timer/Stage (shared) - context-dependent
    0x0E: 'SP',    # Spezialrelais - Dezimal
    0x11: 'V',     # V-Memory (Datenregister) - Oktal
    0x16: 'RNG',   # Sprossen-Marker (intern)
    0x18: 'K',     # Konstante - Hexadezimal
    0x21: 'BCD',   # BCD-Wert
    0x27: 'FMT',   # Format-Spezifikation
    0x83: 'END',   # Programmende-Marker (main ladder end, NOT program end)
    0x91: 'SPL',   # Spezial (1 occurrence)
}

# Set of address types that represent "real" PLC addresses (not RNG/K/END/etc.)
REAL_ADDR_TYPES = {0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x11}

# Output opcodes - after these, a new STR with real address starts a new rung
OUTPUT_OPCODES = {
    'OUT', 'OUTD', 'OUTX', 'OUTN', 'TMR', 'CNT', 'JMP', 'RET',
    'SET', 'RST', 'SHFR', 'SHFL',
}

# Contact opcodes that can start a new rung after an output
CONTACT_START_OPCODES = {
    0x1A,  # STR
    0x1B,  # STRN
    0x1C,  # STREQ (compare V = K)
    0x1D,  # STRNE (compare V != K) - via STRN V
    0x1E,  # STR V
    0x1F,  # STRNE (compare V != K)
    0x8B,  # LD V - unconditional accumulator rungs (On SP1, only math/store)
}

# Parameter word: LD K (op=0x00, at=0x18) after output instructions
# These are arguments to TMR/CNT/SHFR/BCD and should NOT clear last_was_output
PARAM_INSTRUCTION = (0x00, 0x18)  # (opcode, addr_type)

# V-memory special address mappings (operand ranges are decimal values)
# V40400-V40477 -> VX0-VX77
# V40500-V40577 -> VY0-VY77
# V40600-V40777 -> VC0-VC177
# V41000-V41177 -> VS0-VS177
# These operand values are stored as decimal in the binary but displayed as octal.
# V40400 octal = 16640 decimal
V_SPECIAL_RANGES = [
    (0o40400, 0o40477, 'VX', 0o40400),   # VX: subtract base, format as octal
    (0o40500, 0o40577, 'VY', 0o40500),   # VY: subtract base, format as octal
    (0o40600, 0o40777, 'VC', 0o40600),   # VC: subtract base, format as octal
    (0o41000, 0o41177, 'VS', 0o41000),   # VS: subtract base, format as octal
]


def format_v_address(operand):
    """Format a V-memory address, checking for special VX/VY/VC/VS mappings.

    The operand is stored as a decimal value that represents an octal V-address.
    E.g., operand 768 -> V1400 (oct).
    """
    for range_start, range_end, prefix, base in V_SPECIAL_RANGES:
        if range_start <= operand <= range_end:
            offset = operand - base
            return f"{prefix}{offset:o}"
    return f"V{operand:o}"


def format_ladder_addr(addr_type_byte, operand, opcode_byte=None):
    """Formatiert eine Ladder-Instruktions-Adresse.

    Args:
        addr_type_byte: The address type byte from the instruction
        operand: The 32-bit operand value
        opcode_byte: The raw opcode byte (used for timer/stage disambiguation)
    """
    type_name = ADDR_TYPE.get(addr_type_byte)

    if type_name is None:
        return ''
    if type_name == 'RNG':
        # addr_type=0x16 is 'RNG' (rung marker) for STR/AND, but those are
        # caught earlier in the parse loop and never reach here. If we get
        # here with 'RNG', it's a non-rung-marker usage (e.g., OR/ORN with
        # an internal address). Format the operand to avoid silent data loss.
        if operand == 0:
            return 'SP1'  # Always-on relay (rung-control bit 0)
        return f"SP{operand}"
    if type_name == 'END':
        return '[END]'

    # K: Hexadezimal
    if type_name == 'K':
        return f"K{operand:X}"

    # X, Y, C: Oktal
    if type_name in ('X', 'Y', 'C'):
        return f"{type_name}{operand:o}"

    # V: Oktal with special VX/VY/VC/VS mapping
    if type_name == 'V':
        return format_v_address(operand)

    # T (pure timer type 0x0B): Oktal (DL405 convention)
    if type_name == 'T':
        return f"T{operand:o}"

    # CT (counter): Oktal (DL405 convention)
    if type_name == 'CT':
        return f"CT{operand:o}"

    # TS (type 0x0D shared between Timer and Stage):
    # - With TMR opcode (0xCE, 0x6A): display as T (timer number, octal)
    # - With contact opcodes: Timer range T0-T177 (operand 0-127),
    #   Stage range S0-S927 (operand 0-599)
    #   DL405 timer contacts reference the same address as TMR output.
    #   Heuristic: operand <= 127 → T (timer status contact), else S (stage).
    if type_name == 'TS':
        if opcode_byte in (0xCE, 0x6A):
            return f"T{operand:o}"
        if operand <= 127:
            return f"T{operand:o}"
        return f"S{operand:o}"

    # SP (type 0x0E): shared between Special Relays and Counter contacts
    # - With CNT opcode (0x6F): display as CT (counter number)
    # - Otherwise: display as CT for user counters, SP for system relays
    if type_name == 'SP':
        if opcode_byte == 0x6F:
            return f"CT{operand:o}"  # Oktal (DL405 convention)
        return f"SP{operand}"

    # BCD, FMT, SPL
    if type_name in ('BCD', 'FMT'):
        return f"{type_name}({operand})"

    if type_name == 'SPL':
        return f"SPL{operand}"

    return f"{type_name}{operand}"


def resolve_opcode(opcode, flags, addr_type, operand):
    """Resolve the mnemonic name for a given instruction.

    This handles context-dependent opcodes where the same byte value
    maps to different instructions based on flags, address type, etc.

    Returns: (mnemonic_string, is_output_instruction)
    """
    # ---- flags=0x01: Math/accumulator operations with K constant ----
    if flags == 0x01 and addr_type == 0x18:
        f1_map = {
            0x08: 'MUL',
            0x02: 'DIV',
            0x0E: 'SUBD',
            0x05: 'LD',     # LD K (load constant to accumulator)
        }
        return f1_map.get(opcode, f'?{opcode:02X}_F1'), False

    # ---- Opcode 0x08: dual meaning based on flags ----
    if opcode == 0x08:
        if flags == 0x00:
            return 'ANDSTR', False
        # flags==0x01 handled above
        return f'?08_F{flags:02X}', False

    # ---- Opcode 0x18: NOP/ANDSTR block separator ----
    if opcode == 0x18:
        if addr_type == 0x00:
            return 'ANDSTR', False
        # Other addr_types (e.g. 0x20): treat as NOP/block separator
        return 'NOP', False

    # ---- Contact operations (flags=0x00 typically) ----
    # STR (0x1A)
    if opcode == 0x1A:
        if addr_type == 0x16:
            return 'STR_RNG', False  # STR SP1 rung marker - handled separately
        return 'STR', False

    # STRN (0x1B)
    if opcode == 0x1B:
        return 'STRN', False

    # STRN for V-compare (0x1F)
    if opcode == 0x1F:
        return 'STRN', False

    # STR V alternate (0x1E)
    if opcode == 0x1E:
        return 'STR', False

    # STRN V (0x1D)
    if opcode == 0x1D:
        return 'STRN', False

    # AND (0x24)
    if opcode == 0x24:
        if addr_type == 0x16:
            return 'AND_RNG', False  # AND SP1 rung header - handled separately
        return 'AND', False

    # ANDN (0x28)
    if opcode == 0x28:
        return 'ANDN', False

    # OR (0x2E)
    if opcode == 0x2E:
        return 'OR', False

    # ORN (0x25)
    if opcode == 0x25:
        return 'ORN', False

    # AND V compare (0x29)
    if opcode == 0x29:
        return 'AND', False

    # ORN V alternate (0x27)
    if opcode == 0x27:
        return 'ORN', False

    # ANDN V (0x31)
    if opcode == 0x31:
        return 'ANDN', False

    # ORN V alternate (0x33)
    if opcode == 0x33:
        return 'ORN', False

    # ORSTR (0x19)
    if opcode == 0x19:
        return 'ORSTR', False

    # 0x26: dual meaning based on addr_type
    # addr_type=0x11 (V-Memory): AND V-compare (AND V = K, consumes following LD K)
    # addr_type=0x00: ANDSTR (block AND)
    if opcode == 0x26:
        if addr_type == 0x11:
            return 'AND', False  # AND V-compare
        return 'ANDSTR', False

    # CMP (0x2F) - comparison contact
    if opcode == 0x2F:
        return 'CMP', False

    # ---- Output operations ----
    # OUT Y/C (0x4A)
    if opcode == 0x4A:
        return 'OUT', True

    # PD - Positive Differential / Pulse Differentiate (0x4D)
    # One-scan pulse on positive transition
    if opcode == 0x4D:
        return 'PD', True

    # OUTN C alternate (0x4E)
    if opcode == 0x4E:
        return 'OUTN', True

    # OUT V (0xA7)
    if opcode == 0xA7:
        return 'OUT', True

    # OUTD V (0xA8)
    if opcode == 0xA8:
        return 'OUTD', True

    # OUTX V (0xAE)
    if opcode == 0xAE:
        return 'OUTX', True

    # RST C (0x53)
    if opcode == 0x53:
        return 'RST', True

    # ---- Timer/Counter ----
    # TMR (0xCE) - timer with S/T type
    if opcode == 0xCE:
        return 'TMR', True

    # TMR alternate (0x6A) - context-dependent
    # addr_type=0x0D (TS): TMR timer instruction
    # addr_type=0x00: accumulator operation (e.g., load timer accumulator),
    #   NOT a timer output — treat as non-output math instruction
    if opcode == 0x6A:
        if addr_type == 0x0D:
            return 'TMR', True
        return 'LDTA', False  # Load Timer Accumulator (or similar acc op)

    # CNT/BCD (0x68) - context-dependent
    # addr_type=0x00: BCD conversion (accumulator binary to BCD)
    # addr_type=0x0C: CNT counter instruction
    if opcode == 0x68:
        if addr_type == 0x00:
            return 'BCD', False
        return 'CNT', True

    # CNT (0x6F) - counter instruction with addr_type=0x0E
    if opcode == 0x6F:
        return 'CNT', True

    # ---- Math/Accumulator operations (flags=0x00) ----
    # LD V (0x8B)
    if opcode == 0x8B:
        return 'LD', False

    # ANDD K (0xFF)
    if opcode == 0xFF:
        return 'ANDD', False

    # ADDD K (0xFC)
    if opcode == 0xFC:
        return 'ADDD', False

    # LD K / LD V (0x00)
    if opcode == 0x00:
        if addr_type == 0x18:
            return 'LD', False
        if addr_type == 0x11:
            return 'LD', False
        return 'LD', False

    # ADDD V (0x8D)
    if opcode == 0x8D:
        return 'ADDD', False

    # LD K alternates (0x43, 0x44)
    if opcode == 0x43:
        return 'LD', False

    if opcode == 0x44:
        return 'LD', False

    # ---- Data manipulation ----
    # SHFR (0xBE)
    if opcode == 0xBE:
        return 'SHFR', True

    # STREQ V K (0x1C) - compare equal contact (step chain logic)
    # e.g., CTA0 = K5 means "if counter accumulator V1001 equals 5"
    if opcode == 0x1C:
        return 'STREQ', False

    # OUT V / store to V-memory (0x30) - step chain transition
    # Stores K-value (from following LD K instruction) into V-memory
    if opcode == 0x30:
        return 'OUT', True

    # ---- Control ----
    # JMP (0x3A)
    if opcode == 0x3A:
        return 'JMP', True

    # RET/END (0x47)
    if opcode == 0x47:
        return 'RET', True

    # ---- Special ----
    # NOP/SPECIAL (0xD5)
    if opcode == 0xD5:
        return 'NOP', False

    # SPECIAL (0x90)
    if opcode == 0x90:
        return 'SPECIAL', False

    # SPECIAL (0x2A)
    if opcode == 0x2A:
        return 'SPECIAL', False

    # Unknown
    return f'?{opcode:02X}', False


def parse_prj_ladder(decrypted_data, symbols=None):
    """Parst den Ladder-Code aus der entschlüsselten PRJ-Datei.

    Parses ALL 8-byte instructions from ladder_start to end of file.
    Does NOT stop at END marker (addr_type=0x83) - subroutines/stages
    continue after the main ladder END.

    Rung detection:
      1. STR RUNG (0x1A, addr_type=0x16) = explicit rung marker
      2. AND RUNG (0x24, addr_type=0x16) = part of rung header
      3. Natural boundary: new STR (0x1A) with real address type
         after an output instruction starts a new rung.

    Instruktionsformat: 8 Bytes
      [0] opcode  [1] flags  [2] addr_type  [3] 0x00
      [4-7] operand (32-bit LE)
    """
    d = decrypted_data

    # Symboltabelle als Lookup aufbauen
    sym_lookup = {}
    if symbols:
        for sym in symbols:
            sym_lookup[sym['address']] = sym['description']

    # Finde den Ladder-Code-Startpunkt
    # Suche nach dem ersten STR RUNG-Pattern: 1A 00 16 00
    ladder_start = None
    for i in range(0x0100, len(d) - 8):
        if d[i] == 0x1A and d[i+1] == 0x00 and d[i+2] == 0x16 and d[i+3] == 0x00:
            ladder_start = i
            break

    if ladder_start is None:
        return [], "Kein Ladder-Code gefunden"

    # Parsen - 8-Byte-Instruktionen
    rungs = []
    current_rung = {'number': 0, 'instructions': []}
    rung_count = 0
    pos = ladder_start
    last_was_output = False   # Track if previous instruction was an output
    last_output_opcode = 0    # Raw opcode byte of the last output instruction
    total_instructions = 0

    while pos + 8 <= len(d):
        opcode = d[pos]
        flags = d[pos + 1]
        addr_type = d[pos + 2]
        pad = d[pos + 3]
        operand = struct.unpack_from('<I', d, pos + 4)[0]

        # Terminating pattern: 0x47 0x00 at the very end (RET with no following data)
        if opcode == 0x47 and flags == 0x00 and pos + 16 > len(d):
            # Final RET at end of file - add it and stop
            op_name, is_output = resolve_opcode(opcode, flags, addr_type, operand)
            addr_str = format_ladder_addr(addr_type, operand, opcode)
            comment = sym_lookup.get(addr_str, '') if addr_str else ''
            instr = {
                'offset': pos,
                'opcode': op_name,
                'opcode_raw': (opcode, flags),
                'addr_type': addr_type,
                'operand': operand,
                'address': addr_str,
                'comment': comment,
            }
            current_rung['instructions'].append(instr)
            total_instructions += 1
            if current_rung['instructions']:
                rungs.append(current_rung)
            current_rung = {'number': rung_count, 'instructions': []}
            break

        # STR RUNG (Sprossen-Start): opcode=0x1A, type=0x16(RNG)
        # Explicit rung marker - always starts a new rung
        if opcode == 0x1A and addr_type == 0x16:
            if current_rung['instructions']:
                rungs.append(current_rung)
            rung_count += 1
            current_rung = {'number': rung_count, 'instructions': [], 'has_marker': True}
            last_was_output = False
            total_instructions += 1
            pos += 8
            continue

        # AND RUNG (0x24, type=0x16): part of rung header, skip
        if opcode == 0x24 and addr_type == 0x16:
            total_instructions += 1
            pos += 8
            continue

        # END marker (addr_type=0x83): end of main ladder section
        # Do NOT stop - just record it as an instruction and continue
        if addr_type == 0x83:
            instr = {
                'offset': pos,
                'opcode': 'END',
                'opcode_raw': (opcode, flags),
                'addr_type': addr_type,
                'operand': operand,
                'address': '[END]',
                'comment': '',
            }
            current_rung['instructions'].append(instr)
            total_instructions += 1

            # Save current rung and start fresh after END
            if current_rung['instructions']:
                rungs.append(current_rung)
            rung_count += 1
            current_rung = {'number': rung_count, 'instructions': []}
            last_was_output = False
            pos += 8
            continue

        # Natural rung boundary detection:
        # If previous instruction was an output, and current is a contact/start
        # opcode with a real address type -> new rung.
        # Exception: LD V (0x8B) after OUT V (0xA7) is only a new rung if
        # the current rung has no contact instructions (pure math rungs).
        # Rungs with contacts (STR/AND/OR) that end with OUT V followed by
        # another LD V -> OUT V pair are continuations, not new rungs.
        is_rung_start = (last_was_output
                         and opcode in CONTACT_START_OPCODES
                         and addr_type in REAL_ADDR_TYPES)
        if is_rung_start and opcode == 0x8B and last_output_opcode == 0xA7:
            # LD V after OUT V: only suppress the split if the current rung
            # was started by an explicit STR_RNG marker (On SP1 rungs with
            # multiple LD V -> OUT V pairs in one rung).
            if current_rung.get('has_marker', False):
                is_rung_start = False  # Continuation of STR_RNG rung
        if is_rung_start:
            if current_rung['instructions']:
                rungs.append(current_rung)
            rung_count += 1
            current_rung = {'number': rung_count, 'instructions': []}
            last_was_output = False
            # Fall through to process this instruction normally

        # Resolve opcode name and output flag
        op_name, is_output = resolve_opcode(opcode, flags, addr_type, operand)

        # Adresse formatieren
        addr_str = format_ladder_addr(addr_type, operand, opcode)

        # Symbol-Lookup
        comment = sym_lookup.get(addr_str, '') if addr_str else ''

        instr = {
            'offset': pos,
            'opcode': op_name,
            'opcode_raw': (opcode, flags),
            'addr_type': addr_type,
            'operand': operand,
            'address': addr_str,
            'comment': comment,
        }
        current_rung['instructions'].append(instr)
        total_instructions += 1

        # Update last_was_output, but preserve it across parameter words
        # LD K (op=0x00, at=0x18) after output instructions are parameters
        # (e.g., TMR T0 is followed by LD K50 preset and LD K0 base)
        if opcode == PARAM_INSTRUCTION[0] and addr_type == PARAM_INSTRUCTION[1]:
            pass  # Keep last_was_output unchanged - this is a parameter word
        else:
            last_was_output = is_output
            if is_output:
                last_output_opcode = opcode
        pos += 8

    # Letzte Rung speichern
    if current_rung['instructions']:
        rungs.append(current_rung)

    return rungs, f"Ladder-Code ab Offset 0x{ladder_start:04X}, {rung_count} Sprossen, {total_instructions} Instruktionen"


# ============================================================================
# PRT-Parser: Projektbeschreibung
# ============================================================================

def parse_prt(decrypted_data):
    """Extrahiert die Projektbeschreibung aus der PRT-Datei."""
    # Text beginnt nach 8 Header-Bytes
    text_start = 8
    text_data = decrypted_data[text_start:]

    # Finde das Ende des Texts (Null-terminiert)
    null_pos = text_data.find(b'\x00')
    if null_pos >= 0:
        text_data = text_data[:null_pos]

    return text_data.decode('latin-1', errors='replace')


# ============================================================================
# LCD-Parser: Ladder-Code-Referenz (unverschlüsselt)
# ============================================================================

def parse_lcd(filepath):
    """Analysiert die LCD-Datei (Ladder-Referenzdaten)."""
    with open(filepath, 'rb') as f:
        data = f.read()

    info = {
        'size': len(data),
        'header': data[:6],
    }

    # LCD hat einen Header ähnlich wie ESD
    # Header Byte 0-1: Anzahl Einträge oder Typ
    if len(data) >= 2:
        info['entry_count'] = data[0]

    return info


# ============================================================================
# Ausgabe-Formatierung
# ============================================================================

def print_symbols(symbols, output_file=None):
    """Gibt die Symboltabelle formatiert aus."""
    lines = []
    lines.append("=" * 78)
    lines.append("SYMBOLTABELLE - DirectLogic DL405")
    lines.append("=" * 78)

    # Gruppiere nach Typ
    by_type = defaultdict(list)
    for sym in symbols:
        by_type[sym['type']].append(sym)

    type_labels = {
        'X': 'EINGÄNGE (Inputs)',
        'Y': 'AUSGÄNGE (Outputs)',
        'C': 'STEUERRELAIS (Control Relays)',
        'T': 'TIMER',
        'CT': 'ZÄHLER (Counters)',
        'S': 'STUFEN (Stages)',
        'SP': 'SPEZIALRELAIS',
        'V': 'DATENREGISTER (V-Memory)',
    }

    type_order = ['X', 'Y', 'C', 'T', 'CT', 'S', 'SP', 'V']

    for t in type_order:
        if t not in by_type:
            continue
        entries = by_type[t]
        label = type_labels.get(t, t)
        lines.append(f"\n--- {label} ({len(entries)} Einträge) ---")
        lines.append(f"{'Adresse':<12} {'Beschreibung'}")
        lines.append("-" * 60)
        for sym in entries:
            desc = sym['description'].replace('\n', ' / ')
            lines.append(f"{sym['address']:<12} {desc}")

    # Unbekannte Typen
    for t in sorted(by_type.keys()):
        if t in type_order:
            continue
        entries = by_type[t]
        lines.append(f"\n--- SONSTIGE Typ '{t}' ({len(entries)} Einträge) ---")
        for sym in entries:
            desc = sym['description'].replace('\n', ' / ')
            lines.append(f"{sym['address']:<12} {desc}")

    text = '\n'.join(lines)

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(text + '\n')

    return text


def print_ladder(rungs, symbols=None, output_file=None):
    """Gibt den Ladder-Code als Text-Darstellung aus."""
    lines = []
    lines.append("=" * 78)
    lines.append("LADDER-LOGIK PROGRAMM - DirectLogic DL430 (DL405)")
    lines.append("=" * 78)

    sym_lookup = {}
    if symbols:
        for sym in symbols:
            sym_lookup[sym['address']] = sym['description']

    for rung in rungs:
        lines.append(f"\n{'─' * 78}")
        lines.append(f"SPROSSE {rung['number']}")
        lines.append(f"{'─' * 78}")

        indent = "  "

        for instr in rung['instructions']:
            opcode = instr['opcode']
            addr = instr['address']
            comment = instr.get('comment', '') or sym_lookup.get(addr, '')
            if comment:
                comment = comment.replace('\n', ' / ').strip()

            comment_suffix = f"  (* {comment} *)" if comment else ""

            # --- Contact operations (NO = normally open) ---
            if opcode == 'STR':
                lines.append(f"{indent}──┤ {addr} ├──{comment_suffix}")

            elif opcode == 'STRN':
                lines.append(f"{indent}──┤/{addr} ├──{comment_suffix}")

            elif opcode == 'STREQ':
                lines.append(f"{indent}──┤ {addr} = ├──{comment_suffix}")

            elif opcode == 'AND':
                lines.append(f"{indent}  ──┤ {addr} ├──{comment_suffix}")

            elif opcode == 'ANDN':
                lines.append(f"{indent}  ──┤/{addr} ├──{comment_suffix}")

            elif opcode == 'OR':
                lines.append(f"{indent}─┬┤ {addr} ├┬─{comment_suffix}")

            elif opcode == 'ORN':
                lines.append(f"{indent}─┬┤/{addr} ├┬─{comment_suffix}")

            # --- Block operations ---
            elif opcode == 'ORSTR':
                lines.append(f"{indent}  ─┤ ODER-Block ├─")

            elif opcode == 'ANDSTR':
                lines.append(f"{indent}  ─┤ UND-Block ├─")

            # --- Comparison ---
            elif opcode == 'CMP':
                lines.append(f"{indent}  ──[CMP {addr}]──{comment_suffix}")

            # --- Output operations ---
            elif opcode == 'OUT':
                lines.append(f"{indent}    ──( {addr} )──{comment_suffix}")

            elif opcode == 'OUTD':
                lines.append(f"{indent}    ──(D {addr} )──{comment_suffix}")

            elif opcode == 'OUTX':
                lines.append(f"{indent}    ──(X {addr} )──{comment_suffix}")

            elif opcode == 'OUTN':
                lines.append(f"{indent}    ──(/{addr} )──{comment_suffix}")

            elif opcode == 'PD':
                lines.append(f"{indent}    ──(PD {addr} )──{comment_suffix}")

            elif opcode == 'SET':
                lines.append(f"{indent}    ──[SET {addr}]──{comment_suffix}")

            elif opcode == 'RST':
                lines.append(f"{indent}    ──[RST {addr}]──{comment_suffix}")

            # --- Timer/Counter ---
            elif opcode == 'TMR':
                lines.append(f"{indent}    ──[TMR {addr}]──{comment_suffix}")

            elif opcode == 'CNT':
                lines.append(f"{indent}    ──[CNT {addr}]──{comment_suffix}")

            # --- BCD conversion ---
            elif opcode == 'BCD':
                lines.append(f"{indent}  ──[BCD]──")

            # --- Math/Accumulator ---
            elif opcode == 'LD':
                lines.append(f"{indent}  ──[LD {addr}]──{comment_suffix}")

            elif opcode == 'MUL':
                lines.append(f"{indent}  ──[MUL {addr}]──{comment_suffix}")

            elif opcode == 'DIV':
                lines.append(f"{indent}  ──[DIV {addr}]──{comment_suffix}")

            elif opcode == 'SUBD':
                lines.append(f"{indent}  ──[SUBD {addr}]──{comment_suffix}")

            elif opcode == 'ADDD':
                lines.append(f"{indent}  ──[ADDD {addr}]──{comment_suffix}")

            elif opcode == 'ANDD':
                lines.append(f"{indent}  ──[ANDD {addr}]──{comment_suffix}")

            # --- Shift ---
            elif opcode == 'SHFL':
                lines.append(f"{indent}    ──[SHFL {addr}]──{comment_suffix}")

            elif opcode == 'SHFR':
                lines.append(f"{indent}    ──[SHFR {addr}]──{comment_suffix}")

            # --- Control ---
            elif opcode == 'JMP':
                lines.append(f"{indent}    ──[JMP {addr}]──{comment_suffix}")

            elif opcode == 'RET':
                lines.append(f"{indent}    ──[RET]──")

            elif opcode == 'END':
                lines.append(f"{indent}    ══[END]══")

            # --- Special/NOP ---
            elif opcode in ('NOP', 'SPECIAL'):
                raw_op, raw_fl = instr['opcode_raw']
                lines.append(f"{indent}  [{opcode} 0x{raw_op:02X} type=0x{instr['addr_type']:02X} op={instr['operand']}]")

            elif opcode.startswith('?'):
                # Unbekannter Opcode - raw ausgeben
                raw_op, raw_fl = instr['opcode_raw']
                lines.append(f"{indent}  ──[{opcode} fl=0x{raw_fl:02X} type=0x{instr['addr_type']:02X} op={instr['operand']}]──")

            else:
                # Fallback for any unmapped opcode
                if addr:
                    lines.append(f"{indent}  {opcode} {addr}{comment_suffix}")
                else:
                    lines.append(f"{indent}  {opcode}{comment_suffix}")

    text = '\n'.join(lines)

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(text + '\n')

    return text


def print_instruction_list(rungs, symbols=None, output_file=None):
    """Gibt den Ladder-Code als Instruktionsliste aus (IL-Format)."""
    lines = []
    lines.append("=" * 78)
    lines.append("INSTRUKTIONSLISTE (IL) - DirectLogic DL430 (DL405)")
    lines.append("=" * 78)

    sym_lookup = {}
    if symbols:
        for sym in symbols:
            sym_lookup[sym['address']] = sym['description']

    for rung in rungs:
        lines.append(f"\n// ===== Sprosse {rung['number']} =====")

        for instr in rung['instructions']:
            addr = instr['address']
            comment = instr.get('comment', '') or sym_lookup.get(addr, '')
            comment_oneline = comment.replace('\n', ' / ').strip() if comment else ''
            comment_str = f"  // {comment_oneline}" if comment_oneline else ""

            opcode = instr['opcode']
            raw_op, raw_fl = instr['opcode_raw']

            # For unknown opcodes, add raw bytes as additional info
            if opcode.startswith('?'):
                raw_info = f"[0x{raw_op:02X} fl=0x{raw_fl:02X} type=0x{instr['addr_type']:02X}]"
                if addr:
                    lines.append(f"  {opcode:<10s} {addr:<16s} {raw_info}{comment_str}")
                else:
                    lines.append(f"  {opcode:<10s} {'':16s} {raw_info}{comment_str}")
            elif addr:
                lines.append(f"  {opcode:<10s} {addr:<16s}{comment_str}")
            else:
                lines.append(f"  {opcode:<10s}{comment_str}")

    text = '\n'.join(lines)

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(text + '\n')

    return text


# ============================================================================
# IEC 61131-3 Structured Text Übersetzer
# ============================================================================

def _sym_comment(addr, sym_lookup):
    """Erzeugt einen ST-Kommentar mit Symbolname, falls vorhanden."""
    desc = sym_lookup.get(addr, '')
    if desc:
        desc = desc.replace('\n', ' / ').replace('(*', '(').replace('*)', ')').strip()
        return f" (* {desc} *)"
    return ''


def _is_ld_k(instructions, idx):
    """Prüft ob die Instruktion an idx ein LD K (Parameterwort) ist."""
    if idx >= len(instructions):
        return False
    instr = instructions[idx]
    return instr['opcode'] == 'LD' and instr['addr_type'] == 0x18


def _k_val(addr):
    """Formatiert einen K-Wert als ST-Hexliteral: K819 → 16#819."""
    if addr.startswith('K'):
        return f"16#{addr[1:]}"
    return addr


def _k_dec(addr):
    """Wandelt einen K-Adressstring in eine Dezimalzahl: K50 → 80."""
    if addr.startswith('K'):
        return int(addr[1:], 16)
    return 0


def translate_rung_to_st(rung, sym_lookup):
    """Übersetzt eine einzelne Sprosse in IEC 61131-3 Structured Text.

    Verwendet einen Boolean-Stack für Kontaktlogik und einen
    Akkumulator-Tracker für Math-Operationen.
    Alle Zeilen werden inline emittiert (kein separates acc_lines).

    Returns: Liste von ST-Zeilen
    """
    instructions = rung['instructions']
    lines = []
    bool_stack = []  # Stack für boolesche Ausdrücke
    acc_active = False  # Sind wir in einer Math-Kette?
    math_if_open = False  # Ist ein IF-Block für bedingte Math offen?
    indent = "    "  # Basis-Einrückung
    pending_stores = []  # Aufgeschobene OUT V + LD K Stores: [(addr, val, comment)]

    # Vorschau-Helfer: Nächster Opcode (ohne Parameterwörter)
    def next_real_op(from_idx):
        """Findet den nächsten Nicht-LD-K-Opcode ab from_idx."""
        j = from_idx
        while j < len(instructions):
            if not (instructions[j]['opcode'] == 'LD' and instructions[j]['addr_type'] == 0x18):
                return instructions[j]['opcode']
            j += 1
        return None

    def _open_math_if():
        """Öffnet einen IF-Block wenn Bedingungen im bool_stack vorhanden sind."""
        nonlocal math_if_open, indent
        if bool_stack and not math_if_open:
            condition = bool_stack[-1]
            if condition != 'TRUE':
                lines.append(f"    IF {condition} THEN")
                indent = "        "
                math_if_open = True

    def _close_math_if():
        """Schließt einen offenen IF-Block."""
        nonlocal math_if_open, indent
        if math_if_open:
            lines.append(f"    END_IF;")
            indent = "    "
            math_if_open = False

    def _flush_pending_stores():
        """Emittiert aufgeschobene OUT V Stores mit der aktuellen Bedingung.

        Dedupliziert Stores mit gleicher Adresse und Wert.
        """
        nonlocal pending_stores
        if not pending_stores:
            return
        condition = bool_stack[-1] if bool_stack else 'TRUE'
        seen = set()
        for s_addr, s_val, s_comment in pending_stores:
            key = (s_addr, s_val)
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"    IF {condition} THEN")
            lines.append(f"        {s_addr} := {s_val};{s_comment}")
            lines.append(f"    END_IF;")
        pending_stores = []

    def _next_is_block_op(from_idx):
        """Prüft ob nach from_idx ein ANDSTR oder ORSTR folgt (evtl. nach LD K)."""
        j = from_idx
        while j < len(instructions):
            nop = instructions[j]['opcode']
            if nop in ('ANDSTR', 'ORSTR'):
                return True
            # LD K Parameter überspringen
            if nop == 'LD' and instructions[j]['addr_type'] == 0x18:
                j += 1
                continue
            return False
        return False

    i = 0
    while i < len(instructions):
        instr = instructions[i]
        op = instr['opcode']
        addr = instr['address']
        comment = _sym_comment(addr, sym_lookup)

        # --- Rung-Header-Marker (STR_RNG, AND_RNG) überspringen ---
        if op in ('STR_RNG', 'AND_RNG', 'SPECIAL'):
            i += 1
            continue

        # NOP mit SP-Adresse = Hochgeschwindigkeitszähler (UDC) Spezialfunktion
        # Nutzt Stack-Einträge als Parameter und konsumiert folgende LD K-Werte
        if op == 'NOP':
            if instr['addr_type'] != 0x00 and addr:
                # Stack-Einträge als Parameter sammeln
                params = list(bool_stack)
                # Folgende LD K-Werte konsumieren
                k_vals = []
                j = i + 1
                while j < len(instructions) and _is_ld_k(instructions, j):
                    k_vals.append(instructions[j]['address'])
                    j += 1
                param_str = ', '.join(params) if params else ''
                k_str = ', '.join(k_vals) if k_vals else ''
                all_params = ', '.join(filter(None, [param_str, k_str]))
                lines.append(f"    (* UDC {addr}({all_params}) *){comment}")
                i = j  # LD K-Werte überspringen
                bool_stack.clear()
                continue
            i += 1
            continue

        # Kontakt-Instruktion beendet Math-Kette
        if op in ('STR', 'STRN', 'STREQ', 'AND', 'ANDN', 'OR', 'ORN') and acc_active:
            # Nur zurücksetzen wenn ein realer Adresstyp (Kontakt) vorliegt
            if instr['addr_type'] in REAL_ADDR_TYPES:
                _close_math_if()
                acc_active = False

        # ============================================================
        # Kontaktlogik → Boolesche Ausdrücke
        # ============================================================

        if op == 'STR' and not acc_active:
            # STR V + LD K = Vergleich V = K (alternate STREQ)
            if instr['addr_type'] == 0x11 and _is_ld_k(instructions, i + 1):
                cmp_val = instructions[i + 1]['address']
                bool_stack.append(f"({addr} = {cmp_val})")
                i += 2
                continue
            # STR V + LD V + CMP = Vergleich V < V (V-V-Vergleich, CMP als OR)
            if (instr['addr_type'] == 0x11
                    and i + 2 < len(instructions)
                    and instructions[i + 1]['opcode'] == 'LD'
                    and instructions[i + 1]['addr_type'] == 0x11
                    and instructions[i + 2]['opcode'] == 'CMP'):
                cmp_v2 = instructions[i + 1]['address']
                cmp_or = instructions[i + 2]['address']
                bool_stack.append(f"({addr} < {cmp_v2}) OR {cmp_or}")
                i += 3
                continue
            bool_stack.append(addr)
            i += 1
            continue

        if op == 'STRN' and not acc_active:
            # STRN V + LD K = Vergleich V <> K (Not Equal)
            if instr['addr_type'] == 0x11 and _is_ld_k(instructions, i + 1):
                cmp_val = instructions[i + 1]['address']
                bool_stack.append(f"({addr} <> {cmp_val})")
                i += 2
                continue
            # STRN V (opcode 0x1D/0x1F) mit LD K = V <> K
            if instr['opcode_raw'][0] in (0x1D, 0x1F) and _is_ld_k(instructions, i + 1):
                cmp_val = instructions[i + 1]['address']
                bool_stack.append(f"({addr} <> {cmp_val})")
                i += 2
                continue
            bool_stack.append(f"NOT {addr}")
            i += 1
            continue

        # STREQ: Vergleich V = K (konsumiert folgendes LD K)
        if op == 'STREQ':
            cmp_expr = addr
            if _is_ld_k(instructions, i + 1):
                cmp_expr = f"{addr} = {instructions[i + 1]['address']}"
                i += 1
            bool_stack.append(f"({cmp_expr})")
            i += 1
            continue

        if op == 'AND' and not acc_active:
            # AND V + LD K = AND (V = K) — Vergleich
            if instr['addr_type'] == 0x11 and _is_ld_k(instructions, i + 1):
                cmp_val = instructions[i + 1]['address']
                cmp_expr = f"({addr} = {cmp_val})"
                if bool_stack:
                    top = bool_stack.pop()
                    bool_stack.append(f"{top} AND {cmp_expr}")
                else:
                    bool_stack.append(cmp_expr)
                i += 2
                continue
            # AND V + LD V = V-V-Vergleich (V < V)
            if (instr['addr_type'] == 0x11
                    and i + 1 < len(instructions)
                    and instructions[i + 1]['opcode'] == 'LD'
                    and instructions[i + 1]['addr_type'] == 0x11):
                cmp_v2 = instructions[i + 1]['address']
                cmp_expr = f"({addr} < {cmp_v2})"
                if bool_stack:
                    top = bool_stack.pop()
                    bool_stack.append(f"{top} AND {cmp_expr}")
                else:
                    bool_stack.append(cmp_expr)
                i += 2
                continue
            if bool_stack:
                top = bool_stack.pop()
                bool_stack.append(f"{top} AND {addr}")
            else:
                bool_stack.append(addr)
            i += 1
            continue

        if op == 'ANDN' and not acc_active:
            # ANDN V + LD K = AND (V <> K)
            if instr['addr_type'] == 0x11 and _is_ld_k(instructions, i + 1):
                cmp_val = instructions[i + 1]['address']
                cmp_expr = f"({addr} <> {cmp_val})"
                if bool_stack:
                    top = bool_stack.pop()
                    bool_stack.append(f"{top} AND {cmp_expr}")
                else:
                    bool_stack.append(cmp_expr)
                i += 2
                continue
            if bool_stack:
                top = bool_stack.pop()
                bool_stack.append(f"{top} AND NOT {addr}")
            else:
                bool_stack.append(f"NOT {addr}")
            i += 1
            continue

        if op == 'OR' and not acc_active:
            # OR V + LD K = OR (V = K) — Vergleich
            if instr['addr_type'] == 0x11 and _is_ld_k(instructions, i + 1):
                cmp_val = instructions[i + 1]['address']
                cmp_expr = f"({addr} = {cmp_val})"
                if bool_stack:
                    top = bool_stack.pop()
                    bool_stack.append(f"{top} OR {cmp_expr}")
                else:
                    bool_stack.append(cmp_expr)
                i += 2
                continue
            if bool_stack:
                top = bool_stack.pop()
                bool_stack.append(f"{top} OR {addr}")
            else:
                bool_stack.append(addr)
            i += 1
            continue

        if op == 'ORN' and not acc_active:
            # ORN V + LD K = OR (V <> K)
            if instr['addr_type'] == 0x11 and _is_ld_k(instructions, i + 1):
                cmp_val = instructions[i + 1]['address']
                cmp_expr = f"({addr} <> {cmp_val})"
                if bool_stack:
                    top = bool_stack.pop()
                    bool_stack.append(f"{top} OR {cmp_expr}")
                else:
                    bool_stack.append(cmp_expr)
                i += 2
                continue
            if bool_stack:
                top = bool_stack.pop()
                bool_stack.append(f"{top} OR NOT {addr}")
            else:
                bool_stack.append(f"NOT {addr}")
            i += 1
            continue

        if op == 'ORSTR':
            if len(bool_stack) >= 2:
                b = bool_stack.pop()
                a = bool_stack.pop()
                bool_stack.append(f"({a}) OR ({b})")
            # Aufgeschobene Stores emittieren wenn keine weiteren Block-Ops folgen
            if pending_stores and not _next_is_block_op(i + 1):
                _flush_pending_stores()
            i += 1
            continue

        if op == 'ANDSTR':
            if len(bool_stack) >= 2:
                b = bool_stack.pop()
                a = bool_stack.pop()
                bool_stack.append(f"({a}) AND ({b})")
            # Aufgeschobene Stores emittieren wenn keine weiteren Block-Ops folgen
            if pending_stores and not _next_is_block_op(i + 1):
                _flush_pending_stores()
            i += 1
            continue

        # CMP (0x2F): Im Ladder ein paralleler Kontakt (OR).
        # Ohne folgendes LD K: einfacher OR-Kontakt.
        # Mit folgendem LD K: Vergleichskontakt (OR mit Bedingung).
        if op == 'CMP':
            if _is_ld_k(instructions, i + 1):
                cmp_expr = f"({addr} = {instructions[i + 1]['address']})"
                if bool_stack:
                    top = bool_stack.pop()
                    bool_stack.append(f"{top} OR {cmp_expr}")
                else:
                    bool_stack.append(cmp_expr)
                i += 2
                continue
            if bool_stack:
                top = bool_stack.pop()
                bool_stack.append(f"{top} OR {addr}")
            else:
                bool_stack.append(addr)
            i += 1
            continue

        # ============================================================
        # Ausgabe-Instruktionen
        # ============================================================
        condition = bool_stack[-1] if bool_stack else 'TRUE'

        # OUT Y/C (nicht V-Memory)
        if op == 'OUT' and instr['addr_type'] != 0x11:
            # OUT V für step chain (opcode 0x30): konsumiert folgendes LD K als Wert
            if instr['opcode_raw'][0] == 0x30:
                if _is_ld_k(instructions, i + 1):
                    val = instructions[i + 1]['address']
                    lines.append(f"    {addr} := {_k_val(val)};{comment}")
                    i += 2
                    continue
            lines.append(f"    {addr} := {condition};{comment}")
            i += 1
            continue

        if op == 'OUTN':
            lines.append(f"    {addr} := NOT ({condition});{comment}")
            i += 1
            continue

        if op == 'PD':
            lines.append(f"    {addr} := {condition} AND NOT {addr}_prev;{comment}")
            lines.append(f"    {addr}_prev := {condition};")
            i += 1
            continue

        if op == 'SET':
            lines.append(f"    IF {condition} THEN{comment}")
            lines.append(f"        {addr} := TRUE;")
            lines.append(f"    END_IF;")
            i += 1
            continue

        if op == 'RST':
            lines.append(f"    IF {condition} THEN{comment}")
            lines.append(f"        {addr} := FALSE;")
            lines.append(f"    END_IF;")
            i += 1
            continue

        # ============================================================
        # Timer (konsumiert 2 folgende LD K: Preset + Basis)
        # ============================================================
        if op == 'TMR':
            timer_name = addr
            preset = '0'
            base = '0'
            if _is_ld_k(instructions, i + 1):
                preset = instructions[i + 1]['address']
                i += 1
            if _is_ld_k(instructions, i + 1):
                base = instructions[i + 1]['address']
                i += 1
            preset_val = _k_dec(preset)
            base_map = {0: 0.01, 1: 0.1, 2: 1.0}
            base_val = _k_dec(base)
            time_sec = preset_val * base_map.get(base_val, 0.1)
            lines.append(f"    {timer_name}(IN := {condition}, PT := T#{time_sec}s);{_sym_comment(timer_name, sym_lookup)}")
            i += 1
            continue

        # ============================================================
        # Counter (konsumiert 2 folgende LD K: Preset + 2. Param)
        # ============================================================
        if op == 'CNT':
            cnt_name = addr
            # DL405 CNT: top stack = CU (Zähleingang), 2. Stack = R (Reset)
            cu_cond = condition
            r_cond = None
            if len(bool_stack) >= 2:
                cu_cond = bool_stack[-1]
                r_cond = bool_stack[-2]
            preset = '0'
            preset_is_var = False
            if _is_ld_k(instructions, i + 1):
                preset = instructions[i + 1]['address']
                i += 1
            elif (i + 1 < len(instructions) and instructions[i + 1]['opcode'] == 'LD'
                  and instructions[i + 1]['addr_type'] == 0x11):
                # Variable Vorgabe aus V-Memory
                preset = instructions[i + 1]['address']
                preset_is_var = True
                i += 1
            if _is_ld_k(instructions, i + 1):
                i += 1  # 2. Parameter überspringen
            preset_val = preset if preset_is_var else _k_dec(preset)
            params = f"CU := {cu_cond}"
            if r_cond:
                params += f", R := {r_cond}"
            params += f", PV := {preset_val}"
            lines.append(f"    {cnt_name}({params});{_sym_comment(cnt_name, sym_lookup)}")
            i += 1
            continue

        # ============================================================
        # Shift Register (konsumiert folgendes LD K: Länge)
        # ============================================================
        if op == 'SHFR':
            length = '0'
            if _is_ld_k(instructions, i + 1):
                length = instructions[i + 1]['address']
                i += 1
            lines.append(f"    SHFR({addr}, length := {_k_dec(length)}, DATA := {condition});{comment}")
            i += 1
            continue

        if op == 'SHFL':
            length = '0'
            if _is_ld_k(instructions, i + 1):
                length = instructions[i + 1]['address']
                i += 1
            lines.append(f"    SHFL({addr}, length := {_k_dec(length)}, DATA := {condition});{comment}")
            i += 1
            continue

        # ============================================================
        # Math/Akkumulator-Operationen (inline emittiert)
        # Bei bedingter Math: IF condition THEN ... END_IF;
        # ============================================================

        # LD V: Akkumulator laden
        if op == 'LD' and (instr['addr_type'] == 0x11 or instr['opcode_raw'][0] == 0x8B):
            acc_active = True
            _open_math_if()
            lines.append(f"{indent}acc := {addr};{comment}")
            i += 1
            continue

        # LD K in Math-Kontext: Unterscheidung ob neuer Akku-Wert oder Doppelwort-Highword
        # DL405 SUBD/ADDD/MUL/DIV sind Doppelwort-Ops und das folgende LD K ist
        # das High-Word des 32-Bit-Operanden. Wir überspringen K0 High-Words.
        if op == 'LD' and instr['addr_type'] == 0x18:
            if acc_active:
                # In einer Math-Kette: LD K0 nach Math-Op = High-Word → überspringen
                k_dec = _k_dec(addr)
                if k_dec == 0:
                    # High-Word K0 → überspringen (Doppelwort-Erweiterung)
                    i += 1
                    continue
                # Nicht-Null K-Wert: neuer Akku-Wert
                lines.append(f"{indent}acc := {_k_val(addr)};{comment}")
            else:
                # Außerhalb Math-Kontext: Akku starten
                acc_active = True
                _open_math_if()
                lines.append(f"{indent}acc := {_k_val(addr)};{comment}")
            i += 1
            continue

        # Math-Operationen auf Akkumulator
        if op in ('SUBD', 'MUL', 'DIV', 'ADDD', 'ANDD'):
            if not acc_active:
                acc_active = True
                _open_math_if()
            op_map = {'SUBD': '-', 'MUL': '*', 'DIV': '/', 'ADDD': '+', 'ANDD': 'AND'}
            lines.append(f"{indent}acc := acc {op_map[op]} {_k_val(addr)};{comment}")
            i += 1
            continue

        if op == 'BCD':
            if acc_active:
                lines.append(f"{indent}acc := BIN_TO_BCD(acc);")
            i += 1
            continue

        # OUT V / OUTD V / OUTX V: Akkumulator in V-Memory speichern
        if op in ('OUT', 'OUTD', 'OUTX') and instr['addr_type'] == 0x11:
            # Step-Chain Store (opcode 0x30): OUT V + LD K → bedingtes Speichern
            # DL405-Reihenfolge: OUT V, dann LD K als Speicherwert
            if instr['opcode_raw'][0] == 0x30:
                store_val = 'acc'
                if _is_ld_k(instructions, i + 1):
                    store_val = _k_val(instructions[i + 1]['address'])
                    i += 1
                # Prüfe ob danach ANDSTR/ORSTR kommt → Store puffern
                if _next_is_block_op(i + 1):
                    pending_stores.append((addr, store_val, comment))
                elif not math_if_open:
                    # Bei mehreren Stack-Einträgen alle kombinieren (Sprosse 81:
                    # Kontakte zwischen zwei OUT V 0x30 modifizieren unteren Eintrag)
                    store_cond = condition
                    if len(bool_stack) >= 2:
                        store_cond = " AND ".join(f"({e})" for e in bool_stack)
                    lines.append(f"    IF {store_cond} THEN")
                    lines.append(f"        {addr} := {store_val};{comment}")
                    lines.append(f"    END_IF;")
                else:
                    lines.append(f"{indent}{addr} := {store_val};{comment}")
            elif acc_active:
                lines.append(f"{indent}{addr} := acc;{comment}")
                _close_math_if()
            elif _is_ld_k(instructions, i + 1):
                # OUT V + LD K ohne aktiven Akkumulator:
                # Bedingtes Speichern eines K-Werts
                store_val = _k_val(instructions[i + 1]['address'])
                i += 1
                # Prüfe ob danach ANDSTR/ORSTR kommt → Store puffern
                # (Die Gesamtbedingung wird erst nach ANDSTR/ORSTR aufgebaut)
                if _next_is_block_op(i + 1):
                    pending_stores.append((addr, store_val, comment))
                else:
                    lines.append(f"    IF {condition} THEN")
                    lines.append(f"        {addr} := {store_val};{comment}")
                    lines.append(f"    END_IF;")
            else:
                lines.append(f"    {addr} := {condition};{comment}")
            i += 1
            continue

        # Catch-all für LD mit anderen Adresstypen
        if op == 'LD':
            if instr['addr_type'] == 0x11:
                acc_active = True
                _open_math_if()
                lines.append(f"{indent}acc := {addr};{comment}")
            i += 1
            continue

        # ============================================================
        # Steuerung
        # ============================================================
        if op == 'JMP':
            lines.append(f"    (* JMP {addr} *){comment}")
            i += 1
            continue

        if op == 'RET':
            lines.append(f"    RETURN;")
            i += 1
            continue

        if op == 'END':
            lines.append(f"    (* END *)")
            i += 1
            continue

        # ============================================================
        # LDTA - Load Timer Accumulator (opcode 0x6A, addr_type=0x00)
        # ============================================================
        if op == 'LDTA':
            acc_active = True
            _open_math_if()
            lines.append(f"{indent}acc := LDTA();{comment}")
            i += 1
            continue

        # ============================================================
        # Unbekannte Instruktion
        # ============================================================
        raw_op, raw_fl = instr['opcode_raw']
        lines.append(f"    (* {op} {addr} [0x{raw_op:02X}] *)")
        i += 1

    # Am Ende der Sprosse: aufgeschobene Stores und offenen IF-Block schließen
    _flush_pending_stores()
    _close_math_if()

    return lines


def translate_to_st(rungs, symbols, output_file=None, program_name=None):
    """Übersetzt alle Sprossen in IEC 61131-3 Structured Text.

    Args:
        rungs: Liste der geparsten Sprossen
        symbols: Liste der Symbole aus der ESD-Datei
        output_file: Optionaler Pfad für die ST-Ausgabedatei

    Returns: Der generierte ST-Code als String
    """
    sym_lookup = {}
    if symbols:
        for sym in symbols:
            sym_lookup[sym['address']] = sym['description']

    st_lines = []
    st_lines.append("(* ================================================================ *)")
    st_lines.append("(* IEC 61131-3 Structured Text                                      *)")
    st_lines.append("(* Übersetzt aus DirectLogic DL430 Ladder-Code                       *)")
    st_lines.append(f"(* Projekt: {(program_name or 'PLC_Program'):<57s}*)")
    st_lines.append("(* Generiert mit plc_parser.py                                       *)")
    st_lines.append("(* ================================================================ *)")
    st_lines.append("")
    st_lines.append(f"PROGRAM {program_name or 'PLC_Program'}")
    st_lines.append("")

    # --- Variablendeklarationen aus Symboltabelle ---
    st_lines.append("VAR")

    # Gruppiere Symbole nach Typ
    type_groups = defaultdict(list)
    if symbols:
        for sym in symbols:
            type_groups[sym['type']].append(sym)

    iec_type_map = {
        'X': ('BOOL', 'Eingänge'),
        'Y': ('BOOL', 'Ausgänge'),
        'C': ('BOOL', 'Steuerrelais'),
        'T': ('TON',  'Timer'),
        'CT': ('CTU', 'Zähler'),
        'S': ('BOOL', 'Stufen'),
        'SP': ('BOOL', 'Spezialrelais'),
        'V': ('DWORD', 'Datenregister'),
    }

    type_order = ['X', 'Y', 'C', 'T', 'CT', 'S', 'SP', 'V']
    for t in type_order:
        if t not in type_groups:
            continue
        iec_type, label = iec_type_map.get(t, ('ANY', t))
        st_lines.append(f"    (* {label} *)")
        for sym in type_groups[t]:
            desc = sym['description'].replace('\n', ' / ').replace('(*', '(').replace('*)', ')').strip()
            st_lines.append(f"    {sym['address']} : {iec_type}; (* {desc} *)")
        st_lines.append("")

    st_lines.append("END_VAR")
    st_lines.append("")

    # --- Sprossen übersetzen ---
    for rung in rungs:
        rung_num = rung['number']
        st_lines.append(f"    (* ===== Sprosse {rung_num} ===== *)")

        rung_lines = translate_rung_to_st(rung, sym_lookup)
        if rung_lines:
            st_lines.extend(rung_lines)
        else:
            st_lines.append(f"    (* leer *)")
        st_lines.append("")

    st_lines.append("END_PROGRAM")

    text = '\n'.join(st_lines)

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(text + '\n')

    return text



# ============================================================================
# Hauptprogramm
# ============================================================================

def main():
    # Verzeichnis bestimmen
    if len(sys.argv) > 1:
        base_dir = sys.argv[1]
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))

    # Datei-Präfix über Kommandozeile
    if len(sys.argv) > 2:
        prefix = sys.argv[2]
    else:
        print("Verwendung: plc_parser.py <verzeichnis> <präfix>")
        print("  Beispiel:  plc_parser.py /pfad/zum/projekt ANLAGE1")
        sys.exit(1)
    esd_file = os.path.join(base_dir, f'{prefix}.ESD')
    prj_file = os.path.join(base_dir, f'{prefix}.PRJ')
    vd_file = os.path.join(base_dir, f'{prefix}.VD')
    prt_file = os.path.join(base_dir, f'{prefix}.PRT')
    lcd_file = os.path.join(base_dir, f'{prefix}.LCD')
    inf_file = os.path.join(base_dir, f'{prefix}.INF')

    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║   DirectSOFT / DirectLogic DL405 PLC Projekt-Parser            ║")
    print(f"║   Projekt: {prefix:<53s}║")
    print("╚══════════════════════════════════════════════════════════════════╝")

    # ---- Projektinfo ----
    if os.path.exists(inf_file):
        print("\n" + "=" * 60)
        print("PROJEKTINFORMATION")
        print("=" * 60)
        with open(inf_file, 'r') as f:
            print(f.read())

    # ---- Keystream laden ----
    print("Lade Keystream aus VD-Datei...")
    try:
        keystream = load_keystream(vd_file)
        print(f"  Keystream: {len(keystream)} Bytes geladen")
        print(f"  Zyklus: {KEYSTREAM_CYCLE} Bytes (ab Offset {KEYSTREAM_UNIQUE_PREFIX})")
    except Exception as e:
        print(f"  FEHLER: {e}")
        print("  Verschlüsselte Dateien können nicht gelesen werden.")
        keystream = None

    # ---- Projektbeschreibung ----
    if keystream and os.path.exists(prt_file):
        try:
            prt_data = decrypt_file(prt_file, keystream)
            description = parse_prt(prt_data)
            print(f"\nProjektbeschreibung: {description}")
        except Exception as e:
            print(f"PRT-Datei Fehler: {e}")

    # ---- Symboltabelle ----
    symbols = []
    if os.path.exists(esd_file):
        print("\nParse Symboltabelle (ESD)...")
        symbols = parse_esd(esd_file)
        print(f"  {len(symbols)} Symbole gefunden")

        print_symbols(symbols)  # Nur für Dateispeicherung, nicht auf Konsole

        # Speichere als Datei
        sym_output = os.path.join(base_dir, 'symboltabelle.txt')
        print_symbols(symbols, output_file=sym_output)
        print(f"\n  -> Symboltabelle gespeichert: {sym_output}")

    # ---- Ladder-Code ----
    if keystream and os.path.exists(prj_file):
        print("\nParse Ladder-Code (PRJ)...")
        try:
            prj_data = decrypt_file(prj_file, keystream)
            rungs, info = parse_prj_ladder(prj_data, symbols)
            print(f"  {info}")
            print(f"  {len(rungs)} Sprossen extrahiert")

            # Instruktionsliste ausgeben (kurze Vorschau auf Konsole)
            il_text = print_instruction_list(rungs, symbols)
            il_lines = il_text.split('\n')
            # Zeige erste 60 Zeilen als Vorschau
            for line in il_lines[:60]:
                print(line)
            if len(il_lines) > 60:
                print(f"  ... ({len(il_lines) - 60} weitere Zeilen, siehe Datei)")

            # Ladder-Diagramm
            print_ladder(rungs, symbols)

            # Speichere als Dateien
            il_output = os.path.join(base_dir, 'instruktionsliste.txt')
            print_instruction_list(rungs, symbols, output_file=il_output)
            print(f"\n  -> Instruktionsliste gespeichert: {il_output}")

            ladder_output = os.path.join(base_dir, 'ladder_diagramm.txt')
            print_ladder(rungs, symbols, output_file=ladder_output)
            print(f"  -> Ladder-Diagramm gespeichert: {ladder_output}")

            # Structured Text erzeugen
            st_output = os.path.join(base_dir, 'programm.st')
            st_text = translate_to_st(rungs, symbols, output_file=st_output, program_name=prefix)
            st_line_count = len(st_text.split('\n'))
            print(f"  -> Structured Text gespeichert: {st_output} ({st_line_count} Zeilen)")

        except Exception as e:
            print(f"  FEHLER: {e}")
            import traceback
            traceback.print_exc()

    # ---- Zusammenfassung ----
    print("\n" + "=" * 60)
    print("ZUSAMMENFASSUNG")
    print("=" * 60)
    print(f"  PLC-Typ:        DirectLogic DL-430 (DL405-Familie)")
    print(f"  Symbole:        {len(symbols)}")
    if keystream:
        print(f"  Verschlüsselung: XOR-Keystream (50-Byte-Zyklus, entschlüsselt)")
    print(f"  Dateien:")
    for fname in sorted(os.listdir(base_dir)):
        fpath = os.path.join(base_dir, fname)
        if os.path.isfile(fpath) and fname.startswith(prefix + '.'):
            fsize = os.path.getsize(fpath)
            print(f"    {fname:<12s} {fsize:>8,d} Bytes")


if __name__ == '__main__':
    main()
