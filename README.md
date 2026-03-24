# DirectSOFT / DirectLogic DL405 PLC Parser
(c) 2026 retavi GmbH

Lizenz: GNU GENERAL PUBLIC LICENSE v3
Keine Garantie für korrekte Übersetzung von Programmen. Jede Konversion muss manuell überprüft werden!
Nutzung auf eigene Gefahr.

///////////////////////////////////////

License: GNU GENERAL PUBLIC LICENSE v3
No guarantee of correct program translation. Every conversion must be checked manually!
Use at your own risk.

///////////////////////////////////////

Parser für DirectSOFT-Projektdateien der DirectLogic DL405-Familie (DL430, DL440, DL450).

Liest die binären Projektdateien, entschlüsselt XOR-verschlüsselte Daten und erzeugt:
- **Symboltabelle** (`symboltabelle.txt`)
- **Instruktionsliste** (`instruktionsliste.txt`)
- **Ladder-Diagramm** (`ladder_diagramm.txt`) — ASCII-Darstellung
- **IEC 61131-3 Structured Text** (`programm.st`)

## Verwendung

```bash
python3 plc_parser.py <verzeichnis> <präfix>
```

**Parameter:**
| Parameter | Beschreibung |
|-----------|-------------|
| `verzeichnis` | Pfad zum Ordner mit den DirectSOFT-Projektdateien |
| `präfix` | Datei-Präfix des Projekts (z.B. `ANLAGE1`, `TEST`) |

**Beispiel:**
```bash
python3 plc_parser.py /pfad/zum/projekt ANLAGE1
```

Dies erwartet im angegebenen Verzeichnis die Dateien `ANLAGE1.ESD`, `ANLAGE1.PRJ`, `ANLAGE1.VD` usw.

## Unterstützte Dateiformate

| Endung | Beschreibung | Verschlüsselt |
|--------|-------------|:---:|
| `.ESD` | Symboltabelle (Element/Symbol Description) | Nein |
| `.PRJ` | Ladder-Code (Hauptprojektdatei) | Ja |
| `.VD` | V-Register / Keystream-Quelle | Ja |
| `.LDO` | Ladder-Objektcode | Ja |
| `.LDA` | Ladder-Adresszuweisungen | Ja |
| `.PRT` | Projektbeschreibung | Ja |
| `.LCD` | Ladder-Referenzdaten | Nein |
| `.INF` | Projektinfo (INI-Format) | Nein |
| `.TLS` | Tool-Einstellungen | Ja |

## Verschlüsselung

Alle verschlüsselten Dateien verwenden XOR mit einem Keystream aus der `.VD`-Datei.
Der Keystream hat 7 individuelle Anfangsbytes, danach einen 50-Byte-Zyklus.

## Voraussetzungen

- Python 3.6+
- Keine externen Abhängigkeiten (nur Standardbibliothek)
