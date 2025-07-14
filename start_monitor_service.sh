#!/bin/bash

SERVICE_NAME="monitor.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"
LOCAL_SERVICE_FILE="./monitor.service"
SCRIPT_PATH="/home/miruna/Desktop/git/Monitorizare-sistem-Linux/Monitor.py"

# Verifică dacă fișierul de servicii există
if [ ! -f "$LOCAL_SERVICE_FILE" ]; then
    echo "Fișierul $LOCAL_SERVICE_FILE nu există. Asigură-te că rulezi scriptul din directorul unde se află."
    exit 1
fi

# Copiază fișierul .service
echo "Copiere fișier serviciu în /etc/systemd/system/"
sudo cp "$LOCAL_SERVICE_FILE" "$SERVICE_PATH"

# Reîncarcă systemd pentru a recunoaște noul serviciu
echo "Reîncărcare systemd..."
sudo systemctl daemon-reload

# Activează serviciul la boot
echo "Activare serviciu..."
sudo systemctl enable monitor.service

# Pornește serviciul
echo "Pornire serviciu..."
sudo systemctl start monitor.service

# Afișează statusul
echo "Status serviciu:"
sudo systemctl status monitor.service

# Afișează ultimele 10 loguri
echo "Ultimele loguri din journalctl:"
sudo journalctl -u monitor.service -n 10 --no-pager

