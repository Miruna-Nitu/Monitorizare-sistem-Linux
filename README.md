# Monitorizare-sistem-Linux

Aplicatie Python de monitorizare avansata a resurselor si starii sistemului Linux, cu interfata grafica (PyQt6), rulare in fundal ca serviciu systemd, alerte, logare si raportare.


## Functionalitati

* Monitorizare permanenta a:

  * CPU utilizat (%)
  * Memorie utilizata (%)
  * Spatiu utilizat pe fiecare partitie montata
  * Rata de citire/scriere pe disk (Disk I/O)
  * Trafic de retea (bytes sent/received)
* Top 3 procese dupa:

  * Utilizare CPU
  * Utilizare Memorie
  * I/O pe disc
  * Numar conexiuni retea active
* Monitorizare fisiere critice:

  * `/etc/passwd`, `/etc/hosts`, `/etc/shadow`
  * Detectare modificari (prin hash SHA256)
* Monitorizare porturi de retea deschise (`ss -tulnp`)
* Monitorizare pachete instalate recent (`/var/log/dpkg.log`)
* Monitorizare procese root
* Detectare cronjob-uri pentru fiecare utilizator
* Monitorizare aplicatie specifica (ex: `sshd`)
* Salvare metrici in `CSV`, `JSON`, `log` si `alerts.log`
* Interfata GUI organizata in 3 tab-uri: Resurse, Procese, Securitate

## Structura proiectului

```bash
Monitorizare-sistem-Linux/
├── Monitor.py                # Script principal CLI (rulat ca serviciu)
├── gui_monitor.py            # Interfata grafica PyQt6
├── monitor.service           # Fisier serviciu systemd
├── start_monitor_service.sh  # Script automat instalare si pornire serviciu
├── logs/                     # Folder loguri generate automat
│   ├── system.csv
│   ├── top_processes.csv
│   ├── alerts.log
│   └── hashes.json
└── README.md
```

