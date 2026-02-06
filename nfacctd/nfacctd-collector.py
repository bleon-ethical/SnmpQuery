# coding=utf-8
#!/usr/bin/python -tt

"""

SnmpQuery - Network Discovery and Monitoring Tool
Copyright (C) 2025 Agustin Garcia Maiztegui

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

nfacctd-collector.py - Netflow Collector using nfacctd. Maintains a raw flows table
"""


from datetime import datetime
import time
import os
import subprocess
import sqlite3
import pathlib
import threading
import traceback
import signal
import logging


RAMDISK_DB = "/ramdisk/nfacctd.db"
BASE_DIR = pathlib.Path(__file__).resolve().parent
nfacctdCONF = BASE_DIR / "nfacctd.conf"
intervalo_buffer_tabla_flows = 0.5
tiempoRetencion = 1860 # Seconds. Time to keep the data.
# ---------------------------------------------------------------------------------------------------------------------
stop_event = threading.Event()
def handle_sigterm(signum, frame):
    logging.info("Received termination signal")
    stop_event.set()
signal.signal(signal.SIGTERM, handle_sigterm)
signal.signal(signal.SIGINT, handle_sigterm)
# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


def crearDB(ramDB):
    cur = ramDB.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS flows (
        stamp TEXT,
        srcIP TEXT,
        dstIP TEXT,
        srcPort TEXT,
        dstPort TEXT,
        protocol TEXT,
        packets TEXT,
        bytes TEXT
    )
    """)
    
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sumarizados (
        stamp TEXT,
        srcIP TEXT,
        dstIP TEXT,
        srcPort TEXT,
        dstPort TEXT,
        protocol TEXT,
        packets TEXT,
        bytes TEXT,
        tiempo TEXT
    )
    """)
  
# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------

def CollectorPipe():
    ramDB = sqlite3.connect(RAMDISK_DB, isolation_level=None)
    cur = ramDB.cursor()
    flow_state = {}  # key → (last_bytes, last_packets, last_seen)
    insert_buffer = []
    last_db_flush = time.time()
    try:
        proc = subprocess.Popen(
            ["nfacctd", "-f", nfacctdCONF],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        for line in proc.stdout:
            now = time.time()
            if stop_event.is_set():
                logging.info("Stop event set, terminating CollectorPipe")
                proc.terminate()
                break
            line = line.strip()
            if line.startswith("INFO") or line.startswith("WARN"):
                continue
            
            # Skip header lines
            if "SRC_IP" in line or "DST_IP" in line:
                continue
            parts = line.split()
            if len(parts) < 7:
                continue
            
            try:
                src = parts[0]
                dst = parts[1]
                sport = parts[2]
                dport = parts[3]
                proto = parts[4]
                packets_ = parts[5]
                bytes_ = parts[6]
                
                bytes_val = int(bytes_)
                packets_val = int(packets_)
            except (ValueError, IndexError):
                continue  # skip malformed lines
            
            if bytes_val > 0 or packets_val > 0:
                insert_buffer.append((
                    str(now),
                    src, dst, sport, dport, proto,
                    str(packets_val),
                    str(bytes_val)
                ))
            
            # --- flush buffer ---
            if( ( (now - last_db_flush) >= intervalo_buffer_tabla_flows ) and ( insert_buffer ) ):
                try:
                    cur.execute("BEGIN IMMEDIATE")
                    cur.executemany(
                        "INSERT INTO flows VALUES (?,?,?,?,?,?,?,?)",
                        insert_buffer
                    )
                    insert_buffer.clear()
                    # PRUNING:
                    floatStampCorte = time.time() - tiempoRetencion
                    cur.execute("""
                        DELETE FROM flows WHERE CAST(stamp AS REAL) < ?
                        """, (floatStampCorte,))
                    ramDB.commit()
                    insert_buffer.clear()
                    
                except Exception as e:
                    ramDB.rollback()
                    logging.error(f"DB flush error: {e}")
                    print("error!")
                    traceback.print_exc()
                last_db_flush = now
    except Exception as e:
        logging.error(f"CollectorPipe error: {e}")
        print(e)
        traceback.print_exc()
        print(datos)
        
      
# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


if __name__ == "__main__":
    print("starting!")
    ramDB = sqlite3.connect(RAMDISK_DB, isolation_level=None)
    crearDB(ramDB)
    print("database OK")
    
    thr_CollectorPipe = None
    thr_CollectorPipe = threading.Thread(target=CollectorPipe)
    thr_CollectorPipe.start()
    
    while not stop_event.is_set():
        time.sleep(1.005)
    print("FIN.")
    