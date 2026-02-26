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

"""


import time
import multiprocessing
import sqlite3
import traceback
import funciones
import ipaddress
import signal
import logging
import threading
import warnings
warnings.filterwarnings("ignore", category=SyntaxWarning)

# ---------------------------------------------------------------------------------------------------------------------
stop_event = threading.Event()
def handle_sigterm(signum, frame):
    logging.info("Received termination signal")
    stop_event.set()
signal.signal(signal.SIGTERM, handle_sigterm)
signal.signal(signal.SIGINT, handle_sigterm)
# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------


def netflowUpdater(stop_event):
    lastNetflow = 0.0
    netflowRefresh = 1.0
    tiempoRetencion = 300 # tiempo en segundos a retener en las tablas 
    fallas = 0
    # We iterate each row to check if both Source and Destination belong to
    #  the Network of interest (set in the .ini file). If they do, we will
    #  ignore them. The rest get identified and inserted into the tables.
    lastNetflow = time.time()
    # Main Database
    diskDB = sqlite3.connect("/ramdisk/snmpqserver.db", isolation_level=None)
    diskDB.execute("PRAGMA journal_mode=WAL;")
    diskDB.execute("PRAGMA synchronous=NORMAL;")
    # Processed info Database (non-Root)
    netflowDB = sqlite3.connect("/ramdisk/netflow.db", isolation_level=None)
    netflowDB.execute("PRAGMA journal_mode = DELETE;")
    netflowDB.execute("PRAGMA synchronous = NORMAL;")
    netflowDB.execute("PRAGMA temp_store = MEMORY;")
    netflowCur = netflowDB.cursor()
    # Database (RAW Data)
    flowDB = sqlite3.connect("/ramdisk/nfacctd.db", isolation_level=None)
    flowCur = flowDB.cursor()
    crearTablasNetflow(netflowDB)
    iteraciones = 0
    while not stop_event.is_set():
        if(fallas > 10):
            stop_event.set()
            continue
        try:
            # We attempt to import the database periodically.
            ahora = time.time()
            if( (ahora - lastNetflow) > netflowRefresh ):
                # 1. We get network address and maskbits from the siteData table:
                laNetworkAddr = funciones.leerDBenSQL(diskDB,"NETWORK")
                losMaskBits = funciones.leerDBenSQL(diskDB,"MASKBITS")
                rawRows = []
                curatedPublicDS = []
                curatedPublicUS = []
                curatedPrivateDS = []
                curatedPrivateUS = []
                # 1. We get the most recent stamp from the local curated tables.
                # 2. During the update, we will focus on flows that followed.
                masReciente = 0.0
                for row in netflowCur.execute("""
                    SELECT MAX(CAST(stamp AS REAL))
                    FROM netflowPrivateUS
                    ORDER BY CAST(stamp AS REAL) DESC
                    """):
                    unStamp1 = row[0]
                for row in netflowCur.execute("""
                    SELECT MAX(CAST(stamp AS REAL))
                    FROM netflowPublicUS
                    ORDER BY CAST(stamp AS REAL) DESC
                    """):
                    unStamp2 = row[0]
                for row in netflowCur.execute("""
                    SELECT MAX(CAST(stamp AS REAL))
                    FROM netflowPrivateDS
                    ORDER BY CAST(stamp AS REAL) DESC
                    """):
                    unStamp3 = row[0]
                if(masReciente is None):
                    masReciente = 0.0
                for row in netflowCur.execute("""
                    SELECT MAX(CAST(stamp AS REAL))
                    FROM netflowPublicDS
                    ORDER BY CAST(stamp AS REAL) DESC
                    """):
                    unStamp4 = row[0]
                    
                if(unStamp1 is not None):
                    if(unStamp1 > masReciente):
                        masReciente = unStamp1
                if(unStamp2 is not None):
                    if(unStamp2 > masReciente):
                        masReciente = unStamp2
                if(unStamp3 is not None):
                    if(unStamp3 > masReciente):
                        masReciente = unStamp3
                if(unStamp4 is not None):
                    if(unStamp4 > masReciente):
                        masReciente = unStamp4
                # We only bring flows that we don't have already.
                for row in flowCur.execute("""
                    SELECT *
                    FROM flows
                    WHERE CAST(stamp AS REAL) > ?
                    ORDER BY CAST(stamp AS REAL) DESC
                    """, (masReciente,)):
                    rawRows.append(row)
                for cadaRaw in rawRows:
                    try:
                        validado = validateSrcDst( cadaRaw[1], cadaRaw[2], laNetworkAddr, losMaskBits)
                    except ipaddress.AddressValueError:
                        # Puede ser IPv4 o IPv6. o texto.
                        validado = False
                    if( validado ):
                        # Valid flow. Not between same network of interest.
                        # We need to check for each case:
                        #
                        # A. srcIP is __PRIVATE, dstIP is laNETWORK -> netflowPrivateDS
                        # B. srcIP is laNETWORK, dstIP is __PRIVADA -> netflowPrivateUS
                        # C. srcIP is PUBLIC,    dstIP is laNETWORK -> netflowPublicDS
                        # D. srcIP is laNETWORK, dstIP is PUBLIC    -> netflowPublicUS
                        #
                        elSrcIP = cadaRaw[1]
                        elDstIP = cadaRaw[2]
                        # esRedLocal checks if a given IP belongs to the netflow-monitored scope.
                        if( esRedLocal(elSrcIP, laNetworkAddr, losMaskBits) ):
                            # laNETWORK is srcIP, UPSTREAM.
                            if( ipaddress.ip_address(elDstIP).is_private ):
                                # TABLE: netflowPrivateUS (uploading/sending to a private net)
                                curatedPrivateUS.append(cadaRaw)
                            else:
                                # TABLE: netflowPublicUS (uploading/sendint to internet)
                                curatedPublicUS.append(cadaRaw)
                        if( esRedLocal(elDstIP, laNetworkAddr, losMaskBits) ):
                            # laNETWORK is dstIP, DOWNSTREAM.
                            if( ipaddress.ip_address(elSrcIP).is_private ):
                                # TABLE: netflowPrivateDS (downloading from a private net)
                                curatedPrivateDS.append(cadaRaw)
                            else:
                                # TABLE: netflowPublicDS (downloading from internet)
                                curatedPublicDS.append(cadaRaw)
                # Let's define where to make the cut:
                corte = time.time() - tiempoRetencion
                netflowCur.execute("BEGIN IMMEDIATE")
                netflowCur.execute("DELETE FROM netflowPrivateUS WHERE CAST(stamp AS REAL) < ?",(corte,))
                netflowCur.execute("DELETE FROM netflowPublicUS WHERE CAST(stamp AS REAL) < ?",(corte,))
                netflowCur.execute("DELETE FROM netflowPrivateDS WHERE CAST(stamp AS REAL) < ?",(corte,))
                netflowCur.execute("DELETE FROM netflowPublicDS WHERE CAST(stamp AS REAL) < ?",(corte,))
                iteraciones = iteraciones + 1
                netflowCur.executemany("INSERT INTO netflowPrivateUS VALUES (?,?,?,?,?,?,?,?)", curatedPrivateUS)
                netflowCur.executemany("INSERT INTO netflowPublicUS VALUES (?,?,?,?,?,?,?,?)", curatedPublicUS)
                netflowCur.executemany("INSERT INTO netflowPrivateDS VALUES (?,?,?,?,?,?,?,?)", curatedPrivateDS)
                netflowCur.executemany("INSERT INTO netflowPublicDS VALUES (?,?,?,?,?,?,?,?)", curatedPublicDS)
                # Incremental vacuum (run every ~10 iterations, not every time)
                if(iteraciones > 10):
                    netflowCur.execute("PRAGMA incremental_vacuum")
                netflowDB.commit()
                lastNetflow = time.time()
                fallas = 0
        except Exception as e:
            print(e)
            traceback.print_exc()
            fallas = fallas + 1
    

# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------

def validateSrcDst(string_ipA, string_ipB, network, maskbits):
    # If ipA AND ipB BOTH belong to the network, return FALSE.
    ipA = ipaddress.IPv4Address(string_ipA)
    ipB = ipaddress.IPv4Address(string_ipB)
    network = ipaddress.IPv4Network(network+"/"+maskbits, strict=False)
    if( (ipA in network) and (ipB in network) ):
        return False
    else:
        return True

def esRedLocal(string_ip, network, maskbits):
    ipA = ipaddress.IPv4Address(string_ip)
    network = ipaddress.IPv4Network(network+"/"+maskbits, strict=False)
    if( ipA in network ):
        return True
    else:
        return False

def crearTablasNetflow(diskDB):
    diskCur = diskDB.cursor()
    diskCur.execute("""
        CREATE TABLE IF NOT EXISTS netflowPrivateDS (
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
    diskCur.execute("""
        CREATE TABLE IF NOT EXISTS netflowPrivateUS (
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
    diskCur.execute("""
        CREATE TABLE IF NOT EXISTS netflowPublicDS (
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
    diskCur.execute("""
        CREATE TABLE IF NOT EXISTS netflowPublicUS (
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




# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------------------------



if __name__ == "__main__":
    stop_event = multiprocessing.Event()
    try:
        process_netflow = multiprocessing.Process(target=netflowUpdater, args=(stop_event,),)
        process_netflow.start()
        while not stop_event.is_set():
            time.sleep(1.005)
    except KeyboardInterrupt:
        print("Keyboard Interrupt: Stopping...")
        stop_event.set()
stop_event.set()
process_netflow.join()
print("Stopped.")