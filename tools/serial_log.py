#!/usr/bin/env python
"""serial_log.py - captura un port serie a un fitxer amb hora, sense codis ANSI, amb reconnexio automatica
(els ESP32-C6 amb USB-Serial-JTAG desapareixen ~1 s a cada reset) i un fitxer de control per fer reset
per DTR/RTS o aturar la captura.

Us:      python tools/serial_log.py COM5 logs/cactus.txt [--baud 115200]
Control: fitxer <sortida>.cmd amb una paraula:  reset  |  quit
         (p.ex.  echo reset > logs/cactus.txt.cmd )
"""
import argparse
import os
import re
import time

import serial

ANSI = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]')


def stamp():
    t = time.time()
    return time.strftime('%H:%M:%S', time.localtime(t)) + '.%03d' % int((t % 1) * 1000)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('port')
    ap.add_argument('out')
    ap.add_argument('--baud', type=int, default=115200)
    a = ap.parse_args()
    cmdfile = a.out + '.cmd'
    out = open(a.out, 'a', encoding='utf-8', buffering=1)

    def w(line):
        out.write(stamp() + ' ' + line + '\n')

    w('=== captura %s @ %d -> %s (pid %d) ===' % (a.port, a.baud, a.out, os.getpid()))
    ser = None
    buf = b''
    was_open = False
    while True:
        if os.path.exists(cmdfile):
            try:
                cmd = open(cmdfile).read().strip().lower()
            except OSError:
                cmd = ''
            try:
                os.remove(cmdfile)
            except OSError:
                pass
            if cmd == 'quit':
                w('=== quit ===')
                break
            if cmd == 'reset':
                if ser is not None and ser.is_open:
                    try:
                        # Auto-reset de l'USB-Serial-JTAG del C6 (provat 2026-10-11, Windows): reobrir el port amb
                        # (DTR=1,RTS=1), passar a (0,1) = EN baix i despres a (0,0). Des de (0,0) a (0,1) no reinicia,
                        # i passar per (1,0) deixa el xip en mode DOWNLOAD (boot:0x14).
                        ser.close()
                        s = serial.Serial()
                        s.port = a.port
                        s.baudrate = a.baud
                        s.timeout = 0.2
                        s.dtr = True
                        s.rts = True
                        s.open()
                        time.sleep(0.3)
                        s.dtr = False
                        time.sleep(0.3)
                        s.rts = False
                        ser = s
                        buf = b''
                        w('=== RESET per DTR/RTS enviat ===')
                    except Exception as e:  # noqa: BLE001
                        w('=== RESET ha fallat: %r ===' % (e,))
                else:
                    w('=== RESET demanat pero el port no esta obert ===')
        if ser is None:
            try:
                s = serial.Serial()
                s.port = a.port
                s.baudrate = a.baud
                s.timeout = 0.2
                s.dtr = False
                s.rts = False
                s.open()
                ser = s
                buf = b''
                w('=== port reobert ===' if was_open else '=== port obert ===')
                was_open = True
            except Exception:  # noqa: BLE001
                time.sleep(0.5)
                continue
        try:
            data = ser.read(ser.in_waiting or 1)
        except Exception as e:  # noqa: BLE001
            w('=== port perdut (%s), reintentant ===' % (e.__class__.__name__,))
            try:
                ser.close()
            except Exception:  # noqa: BLE001
                pass
            ser = None
            continue
        if not data:
            continue
        buf += data
        while b'\n' in buf:
            line, buf = buf.split(b'\n', 1)
            txt = ANSI.sub('', line.decode('utf-8', 'replace')).rstrip('\r')
            if txt.strip():
                w(txt)
    out.close()


if __name__ == '__main__':
    main()
