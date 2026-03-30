# DirectSOFT / DirectLogic DL405 PLC Parser

**(c) 2026 retavi GmbH — Lizenz: GNU General Public License v3**

> **Hinweis:** Keine Garantie für korrekte Programmübersetzung. Jede Konversion muss manuell überprüft werden! Nutzung auf eigene Gefahr.

*→ English version below*

---

## Beschreibung

Parser für binäre Projektdateien der **DirectSOFT**-Programmiersoftware für die **DirectLogic DL405-Familie** (DL430, DL440, DL450).

Liest die binären Projektdateien, entschlüsselt XOR-verschlüsselte Daten und erzeugt folgende Ausgaben:

- **Symboltabelle** (`symboltabelle.txt`)
- **Instruktionsliste** (`instruktionsliste.txt`)
- **Ladder-Diagramm** (`ladder_diagramm.txt`) — ASCII-Darstellung
- **IEC 61131-3 Structured Text** (`programm.st`)

---

## Verwendung

```bash
python3 plc_parser.py <verzeichnis> <präfix>
```

**Parameter:**

| Parameter     | Beschreibung                                                        |
|---------------|---------------------------------------------------------------------|
| `verzeichnis` | Pfad zum Ordner mit den DirectSOFT-Projektdateien                  |
| `präfix`      | Datei-Präfix des Projekts (z.B. `ANLAGE1`, `TEST`)                 |

**Beispiel:**

```bash
python3 plc_parser.py /pfad/zum/projekt ANLAGE1
```

Erwartet im angegebenen Verzeichnis die Dateien `ANLAGE1.ESD`, `ANLAGE1.PRJ`, `ANLAGE1.VD` usw.

---

## Unterstützte Dateiformate

| Endung | Beschreibung                              | Verschlüsselt |
|--------|-------------------------------------------|:-------------:|
| `.ESD` | Symboltabelle (Element/Symbol Description)| Nein          |
| `.PRJ` | Ladder-Code (Hauptprojektdatei)           | Ja            |
| `.VD`  | V-Register / Keystream-Quelle             | Ja            |
| `.LDO` | Ladder-Objektcode                         | Ja            |
| `.LDA` | Ladder-Adresszuweisungen                  | Ja            |
| `.PRT` | Projektbeschreibung                       | Ja            |
| `.LCD` | Ladder-Referenzdaten                      | Nein          |
| `.INF` | Projektinfo (INI-Format)                  | Nein          |
| `.TLS` | Tool-Einstellungen                        | Ja            |

---

## Verschlüsselung

Alle verschlüsselten Dateien verwenden XOR mit einem Keystream aus der `.VD`-Datei.
Der Keystream besteht aus 7 individuellen Anfangsbytes, gefolgt von einem 50-Byte-Zyklus.

---

## Voraussetzungen

- Python 3.6+
- Keine externen Abhängigkeiten (nur Standardbibliothek)

---
---

# DirectSOFT / DirectLogic DL405 PLC Parser

**(c) 2026 retavi GmbH — License: GNU General Public License v3**

> **Warning:** No guarantee of correct program translation. Every conversion must be checked manually! Use at your own risk.

---

## Description

Parser for binary project files created by **DirectSOFT** programming software for the **DirectLogic DL405 family** of PLCs (DL430, DL440, DL450).

Reads the binary project files, decrypts XOR-encrypted data, and generates the following outputs:

- **Symbol table** (`symboltabelle.txt`)
- **Instruction list** (`instruktionsliste.txt`)
- **Ladder diagram** (`ladder_diagramm.txt`) — ASCII representation
- **IEC 61131-3 Structured Text** (`programm.st`)

---

## Usage

```bash
python3 plc_parser.py <directory> <prefix>
```

**Parameters:**

| Parameter   | Description                                                      |
|-------------|------------------------------------------------------------------|
| `directory` | Path to the folder containing the DirectSOFT project files      |
| `prefix`    | Project file prefix (e.g. `ANLAGE1`, `TEST`)                    |

**Example:**

```bash
python3 plc_parser.py /path/to/project ANLAGE1
```

This expects the files `ANLAGE1.ESD`, `ANLAGE1.PRJ`, `ANLAGE1.VD`, etc. in the specified directory.

---

## Supported File Formats

| Extension | Description                               | Encrypted |
|-----------|-------------------------------------------|:---------:|
| `.ESD`    | Symbol table (Element/Symbol Description) | No        |
| `.PRJ`    | Ladder code (main project file)           | Yes       |
| `.VD`     | V-Register data / keystream source        | Yes       |
| `.LDO`    | Ladder object code                        | Yes       |
| `.LDA`    | Ladder address assignments                | Yes       |
| `.PRT`    | Project description text                  | Yes       |
| `.LCD`    | Ladder reference data                     | No        |
| `.INF`    | Project info / metadata (INI format)      | No        |
| `.TLS`    | Tool settings                             | Yes       |

---

## Encryption

All encrypted files use **XOR encryption** with a keystream derived from the `.VD` file.
The keystream consists of 7 unique initial bytes followed by a repeating 50-byte cycle.

---

## Requirements

- Python 3.6+
- No external dependencies (standard library only)
