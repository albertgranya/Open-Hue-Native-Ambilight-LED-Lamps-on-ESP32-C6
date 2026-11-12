#!/usr/bin/env python
"""sniffer_channel_scan.py - busca en quins canals 802.15.4 hi ha una xarxa (PAN / ext PAN) amb el sniffer
snifferzigbeewifi (finestra Wi-Fi + MQTT). Per a cada canal: reinicia el sniffer (fitxer .cmd de serial_log.py),
publica el canal per MQTT durant la finestra, espera que esnifi i compta trames de la PAN buscada.

Us: python tools/sniffer_channel_scan.py logs/sniffer.txt 0x1A2B 15 20 25
"""
import io
import re
import subprocess
import sys
import time

PY = sys.executable
LOG, PAN = sys.argv[1], sys.argv[2].upper().replace('0X', '0x')
CHANNELS = [int(c) for c in sys.argv[3:]] or [15, 20, 25]
TOPIC = 'esphome/zigbeelogger/cmd/channel'


def nlines():
    return len(io.open(LOG, encoding='utf-8', errors='replace').read().splitlines())


for ch in CHANNELS:
    n0 = nlines()
    io.open(LOG + '.cmd', 'w').write('reset\n')
    t0 = time.time()
    # el sniffer connecta entre 10 i 25 s despres d'arrencar; la finestra dura 30 s des de la connexio
    pub = subprocess.Popen([PY, 'tools/mqtt_cmd.py', TOPIC, str(ch), '--repeat', '25', '--every', '2'],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    started = None
    while time.time() - t0 < 130:
        time.sleep(3)
        new = io.open(LOG, encoding='utf-8', errors='replace').read().splitlines()[n0:]
        for l in new:
            m = re.search(r'SNIFFER EN MARXA: canal (\d+)', l)
            if m:
                started = (int(m.group(1)), l[:12])
        if started:
            break
    pub.wait()
    if not started:
        print('canal %d: el sniffer no ha arrencat en 130 s' % ch, flush=True)
        continue
    time.sleep(40)
    new = io.open(LOG, encoding='utf-8', errors='replace').read().splitlines()[n0:]
    k = [i for i, l in enumerate(new) if 'SNIFFER EN MARXA' in l][-1]
    seg = new[k:]
    hue = [l for l in seg if ('dstPAN=%s' % PAN) in l or ('srcPAN=%s' % PAN) in l]
    pans = {}
    for l in seg:
        for m in re.finditer(r'(?:dst|src)PAN=(0x[0-9A-F]+)', l):
            pans[m.group(1)] = pans.get(m.group(1), 0) + 1
    print('canal %d (sniffer en marxa %s, canal real %d): %d trames de %s | PANs vistes %s' %
          (ch, started[1], started[0], len(hue), PAN, pans), flush=True)
    if hue:
        print('  TROBADA al canal %d' % ch, flush=True)
        break
