#!/usr/bin/env python
"""mqtt_cmd.py - publica una comanda pel broker MQTT local (src/secrets.yaml: mqttbrokerlocal / mqttusername /
mqttpassword). El payload pot venir d'un fitxer (--file) per no deixar claus a la linia de comandes ni als logs.

Us:  python tools/mqtt_cmd.py esphome/zigbeelogger/cmd/sniff 1
     python tools/mqtt_cmd.py esphome/zigbeelogger/cmd/nwk_key --file key.txt --repeat 20 --every 2
"""
import argparse
import os
import time

import paho.mqtt.client as mqtt
import yaml

SECRETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src', 'secrets.yaml')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('topic')
    ap.add_argument('payload', nargs='?', default='')
    ap.add_argument('--file')
    ap.add_argument('--repeat', type=int, default=1)
    ap.add_argument('--every', type=float, default=2.0)
    ap.add_argument('--retain', action='store_true')
    a = ap.parse_args()
    payload = open(a.file, encoding='utf-8').read().strip() if a.file else a.payload
    sec = yaml.safe_load(open(SECRETS, encoding='utf-8'))
    host = str(sec['mqttbrokerlocal'])
    port = 1883
    if ':' in host:
        host, port = host.rsplit(':', 1)
        port = int(port)
    c = mqtt.Client(client_id='mqtt_cmd_%d' % int(time.time()))
    c.username_pw_set(str(sec['mqttusername']), str(sec['mqttpassword']))
    c.connect(host, port, 30)
    c.loop_start()
    sent = 0
    for i in range(a.repeat):
        r = c.publish(a.topic, payload, qos=1, retain=a.retain)
        r.wait_for_publish(5)
        sent += 1 if r.is_published() else 0
        if i + 1 < a.repeat:
            time.sleep(a.every)
    c.loop_stop()
    c.disconnect()
    print('publicat %d/%d a %s (%d bytes de payload)' % (sent, a.repeat, a.topic, len(payload)))


if __name__ == '__main__':
    main()
