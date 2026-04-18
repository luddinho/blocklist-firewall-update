# blocklist-firewall-update

Sprache: 🇩🇪 Deutsch | [🇬🇧 English](README.md)

### Überblick
Dieses Projekt enthaelt ein Shell-Skript, das IP-Blocklisten von mehreren Bedrohungsquellen herunterlaedt und lokale Firewall-Sperren aktualisiert.

Unterstuetzte Quellen (Schwerpunkt: SSH- und Web-Login-Angriffe):
- **blocklist.de** – SSH, Brute-Force, Mail, Web u.v.m.
- **AbuseIPDB** – gemeldete missbreauchliche IPs (API-Key erforderlich)
- **DShield** – Top-angreifende /24-Netzwerke (kein Key noetig)
- **FireHOL** – aggregierte, kuratierte IP-Sets (kein Key noetig)
- **ThreatFox** – C2- und Malware-IOC-IPs von abuse.ch (kein Key noetig)

Das Skript:
- Liest eine Konfigurationsdatei, um aktive Quellen zu bestimmen
- Laedt Feeds herunter und prueft IPv4-Adressen und CIDR-Bloecke
- Schreibt Eintraege in ein ipset (`hash:net`) ueber ein temporaeres Set mit atomarem Swap
- Nutzt eine iptables-Chain, die Traffic von gelisteten Quell-IPs verwirft
- Gibt eine kurze Zusammenfassung aus (hinzugefuegt/entfernt/netto)

Hauptdateien:
- `blocklist-firewall-update.sh` – Hauptskript
- `blocklist-firewall-update.conf` – Konfigurationsdatei

### Voraussetzungen
Folgende Programme muessen verfuegbar sein:
- curl
- ipset
- iptables

Zusaetzlich:
- Linux-System mit iptables/ipset-Unterstuetzung
- Root-Rechte fuer Firewall-Aenderungen

### Konfiguration
Die Konfiguration erfolgt ueber `blocklist-firewall-update.conf`. Eine Vorlagendatei `blocklist-firewall-update.conf.example` ist enthalten. Kopieren Sie diese um eine Konfiguration zu erstellen:

```sh
cp blocklist-firewall-update.conf.example blocklist-firewall-update.conf
# Nach Bedarf anpassen
```

Das Skript sucht die Datei in dieser Reihenfolge:
1. Pfad aus der Umgebungsvariablen `CONFIG_FILE`
2. Gleiches Verzeichnis wie das Skript (`blocklist-firewall-update.sh`)
3. `/etc/blocklist-firewall-update.conf`

Alle Einstellungen koennen auch als Umgebungsvariablen gesetzt werden. Werte in der Konfigurationsdatei ueberschreiben die eingebauten Standardwerte des Skripts.

Wichtige Optionen:

| Variable | Standard | Beschreibung |
|---|---|---|
| `BLOCKLIST_CHAIN_NAME` | `BLOCKLIST_INPUT` | Name der iptables-Chain |
| `ENABLE_BLOCKLIST_DE` | `yes` | blocklist.de aktivieren |
| `BLOCKLIST_DE_TYPES` | `ssh,bruteforcelogin` | Kommagetrennte blocklist.de-Typen |
| `ENABLE_ABUSEIPDB` | `no` | AbuseIPDB aktivieren |
| `ABUSEIPDB_API_KEY` | _(leer)_ | AbuseIPDB-API-Key (erforderlich wenn aktiviert) |
| `ABUSEIPDB_CONFIDENCE_MINIMUM` | `90` | Minimaler Konfidenzwert (1–100) |
| `ENABLE_DSHIELD` | `no` | DShield aktivieren |
| `ENABLE_FIREHOL` | `no` | FireHOL aktivieren |
| `FIREHOL_SETS` | `firehol_level1 firehol_level2` | Leerzeichen-getrennte FireHOL-Set-Namen |
| `ENABLE_THREATFOX` | `no` | ThreatFox aktivieren |
| `THREATFOX_DAYS` | `7` | IOCs der letzten N Tage abrufen (1–7) |

Jede aktive Quelle erhaelt ein **eigenes ipset** mit einem festen Namen:

| Quelle | ipset-Name |
|---|---|
| blocklist.de | `blocklist_de` |
| AbuseIPDB | `abuseipdb_com` |
| DShield | `dshield_org` |
| FireHOL (je Set) | gleich dem Set-Namen, z.B. `firehol_level1` |
| ThreatFox | `threatfox_abuse_ch` |

Die iptables-Chain erhaelt pro aktivem ipset eine eigene `match-set … src -j DROP`-Regel.

Mit der mitgelieferten `blocklist-firewall-update.conf` sind alle Quellen ausser AbuseIPDB standardmaessig aktiviert.

Erlaubte Werte fuer `BLOCKLIST_DE_TYPES`: `all`, `ssh`, `mail`, `apache`, `imap`, `ftp`, `sip`, `bots`, `strongips`, `ircbot`, `bruteforcelogin`

FireHOL-Sets mit Fokus auf Login-Angriffe: `firehol_level1`, `firehol_level2`, `sshpranker`
(Alle Sets: https://iplists.firehol.org/)

### Funktionsweise
1. `blocklist-firewall-update.conf` laden (falls vorhanden).
2. Fuer jede aktive Quelle den Feed herunterladen und Eintraege in eine quelleigene Rohdatei schreiben.
3. Fuer jede Quelle: nur gueltige IPv4-Adressen und CIDR-Bloecke behalten, deduplizieren und in ein eigenes `hash:net`-ipset laden (temporaeres Set, atomarer Swap). Statistiken je Set werden protokolliert.
4. Bestehende `hash:ip`-Sets werden automatisch auf `hash:net` migriert (einmalig).
5. Die iptables-Chain leeren und pro aktivem ipset eine `match-set … src -j DROP`-Regel einfuegen.
6. Sicherstellen, dass die Chain in `INPUT` eingehangen ist.
7. Zusammenfassung mit Chain-Name und allen aktiven ipsets ausgeben.

### Nutzung
Konfigurationsdatei beim ersten Mal einrichten:

```sh
cp blocklist-firewall-update.conf.example blocklist-firewall-update.conf
# blocklist-firewall-update.conf nach Bedarf anpassen
```

Skript ausfuehren:

```sh
sudo sh ./blocklist-firewall-update.sh
```

Dry-Run mit Befehlszeilenparameter:

```sh
sudo sh ./blocklist-firewall-update.sh -n
# oder
sudo sh ./blocklist-firewall-update.sh --dry-run
```

Eigenen Konfigurationspfad angeben:

```sh
sudo CONFIG_FILE=/etc/blocklist-firewall-update.conf sh ./blocklist-firewall-update.sh
```

Einzelne Einstellungen per Umgebungsvariable ueberschreiben:

```sh
sudo ENABLE_DSHIELD=yes ENABLE_FIREHOL=no sh ./blocklist-firewall-update.sh
```

Eigener Chain-Name:

### Cron-Beispiel
Alle 10 Minuten ausfuehren:

```cron
*/10 * * * * /bin/sh /pfad/zu/blocklist-firewall-update.sh >> /pfad/zu/log/blocklist-update.log 2>&1
```

### Hinweise
- IPv4-Adressen und CIDR-Bloecke werden akzeptiert; IPv6 wird nicht unterstuetzt.
- Der ipset-Typ ist `hash:net` (unterstuetzt einzelne IPs und CIDR-Bereiche). Bestehende `hash:ip`-Sets werden beim ersten Lauf automatisch migriert.
- Die Chain wird bei jedem Lauf geleert und mit einer ipset-DROP-Regel neu aufgebaut.
- Andere Firewall-Regeln werden nicht direkt veraendert, aber die Reihenfolge in `INPUT` ist wichtig.
- Im Dry-Run-Modus werden Befehle nur ausgegeben.
- AbuseIPDB benoetigt einen kostenfreien API-Key von https://www.abuseipdb.com/register
- Schlaegt ein Quell-Download fehl, wird er uebersprungen und andere Quellen laufen normal weiter.

### Fehlerbehebung

- `curl not found`: curl installieren.
- `ipset not found`: ipset-Paket installieren.
- `iptables not found`: iptables-Paket installieren.
- Keine Wirkung auf Traffic:
  - pruefen, ob die Chain in `INPUT` eingehangen ist
  - pruefen, ob Set-Name und Chain-Regel zusammenpassen
  - Regeln mit `iptables -S` und Set-Inhalt mit `ipset list <set>` kontrollieren

#### Beispiel: iptables-Chain inspizieren

```sh
sudo iptables -L BLOCKLIST_INPUT -n -v
```

Beispielausgabe:

```
Chain BLOCKLIST_INPUT (1 references)
 pkts bytes target     prot opt in     out     source               destination
    4   240 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set blocklist_de src
    1    60 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set dshield_org src
    2   120 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set firehol_level1 src
```

#### Beispiel: Inhalt eines Sets anzeigen

```sh
sudo ipset list blocklist_de
sudo ipset list dshield_org
sudo ipset list firehol_level1
```

#### Beispiel: Nicht mehr verwendetes Set entfernen

```sh
sudo ipset destroy blocklist_combined
```
