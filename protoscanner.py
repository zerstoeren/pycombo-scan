#!/usr/bin/env python

import smbc
import sys
import os
import argparse
import io
import json
import time
import netaddr
import threading
from socket import *
from pydicom import *
from pynetdicom3 import AE

def dicomscan(server, port, results_file):
    print "Attempting DICOM scan on " + '%s' % server + '\n'
    ts = time.time()
    try:
# Application Entity Title is a DICOM specific field usually required to be known for successful DICOM communication with C-Commands.  The SCU_SOP_UID help to eliminate the need to know
# that information.  Each C-Command seems to have it's own specific SCU_SOP_UID and the one below is for C-Echo.  Note that if the SCU_SOP_UID does not exist then an AET authentication
# error message is received which still confirms that it is a DICOM device.
#
# Additional research shows that many DICOM vendors like to put web wrapping/UI applications over DICOM in which case a different error message (generally PDU 0x0048) will be provided
# which is also known to be a DICOM error response for web wrapped DICOM engines.  This is also acknowledgement of a valid DICOM device and we know that it was a web wrapped device.
        ae = AE(scu_sop_class=['1.2.840.10008.1.1'])
        peerassoc = ae.associate(server, port)
        dicom_entry = peerassoc.send_c_echo()
        peerassoc.release()
        if '%s' % dicom_entry is not None:
            if results_file is not None:
                with print_lock:
                    with open(results_file, 'a+') as outfile:
                        dicom_data = 'host: ' + '%s' % server + '\n' + 'is_dicom: true\ndicom_info:' + '%s' % dicom_entry + '\ndicom_port: ' + '%s' % port + '\ntimestamp: ' + '%s' % ts + '\n\n'
                        outfile.write(dicom_data)
            else:
                with print_lock:
                    print ("[+] " + '%s' % server + ": " + '%s' % dicom_entry + '\n')
        else:
            pass 
    except:
        try:   
# Web wrapped DICOM devices will also be sent here and generally receive a Connection Timeout or Connection Refused message so we handle that in here with errorcode Exceptions so that
# we can keep scanning the IP range.
#
# If we do not get a DICOM success message above, we send it here to try to identify what it is if we can.
            connector = socket(AF_INET, SOCK_STREAM)
            connector.settimeout(1)
            connector.connect(('%s' % server, port))
            connector.send('Friendly Portscanner\r\n')
            dicom_entry = connector.recv(2048)
            connector.close()
            if results_file is not None:
                with print_lock:
                    with open(results_file, 'a+') as outfile:
                       dicom_data = 'host: ' + '%s' % server + '\n' + 'is_dicom: false\ndicom_info:' + '%s' % dicom_entry + '\ndicom_port: ' + '%s' % port + '\ntimestamp: ' + '%s' % ts + '\n\n'
                       outfile.write(dicom_data)
            else:
                with print_lock:
                    print ("[-] " + '%s' % server + ": " + '%s' % dicom_entry + '\n')
                    pass
        except Exception, errorcode:
            if errorcode[0] == "timed out":
                print server + ": connection " + errorcode[0] + "\n"
                pass
            elif errorcode[0] == "connection refused":
                print server + ": connection " + errorcode[0] + "\n"
                pass
            else:
                pass            

def smbscan(server, results_file):
    smb_obj = []
    ctx = smbc.Context()
    ts = time.time()
    print "attempting SMB scan for " + server + '\n'    
# attempt to pull shares
    try:
        entry = ctx.opendir('smb://' + server).getdents()
#        for entry in entries:
        if entry is not None:
# if SMB communication is detected, try to banner grab to 445 via port connect
            connector = socket(AF_INET, SOCK_STREAM)
            connector.settimeout(1)
            try:
                connector.connect(('%s' % server, 445))
                connector.send('Friendly Portscanner\r\n')
                smbbg = connector.recv(2048)
                connector.close()
# if I remember correctly, SMB + 445 equals a possible DoublePulsar target and WannaCry target remembering that $IPC can be connected to if open
                if results_file is not None:
                    with print_lock:
                        with open(results_file, 'a+') as outfile:
                            smb_data = 'host: ' + '%s' % server + '\n' + 'is_smb: true\nopen_share:' + '%s' % entry + '\n' + 'banner: ' + '%s' % smbbg + 'is_dupulsar: true\nbg_port: 445\ntimestamp: ' + '%s' % ts + '\n'
                            outfile.write(smb_data)
                else:
                    with print_lock:
                        print ("[+] " + '%s' % server + ": " + '%s' % entry + ", Banner Grab: " + '%s' % smbbg + ' Possible DPulsar Target = True')
            except:
                if results_file is not None:
                    with print_lock:
                        with open(results_file, 'a+') as outfile:
                            smb_data = 'host: ' + '%s' % server + '\n' + 'is_smb: true\nopen_share:' + '%s' % entry + '\n' + 'banner: closed\nis_dpulsar: false\nbg_port: 445\ntimestamp: ' + '%s' % ts + '\n'
                            outfile.write(smb_data)
                else:
                   with print_lock:
                        print ("[+] " + '%s' % server + ": " + '%s' % entry + ", Port 445: closed, Possible DPulsar Target = False")
        else:
            pass
    except:
          pass

def thread_check(server, results_file):
    global semaphore

    try:
        if smbargs.proto == 'SMB':
            smbscan(server, results_file)
        else:
            dicomscan(server, port, results_file)
    except Exception as e:
        with print_lock:
           print "I ended up here \n"
           print "[ERROR] [%s] - %s" % (server, e)
    finally:
        semaphore.release()

if __name__ == "__main__":    
    smbparser = argparse.ArgumentParser(description="SMB Scanner")
    smbparser.add_argument("-netrange", type=str, required=False, help="CIDR Block")
    smbparser.add_argument("-ip", type=str, required=False, help="IP address to scan")
    smbparser.add_argument("-proto", type=str, required=True, help="DICOM or SMB")
    smbparser.add_argument("-port", type=int, required=False, help="Only required when not running SMB")
    smbparser.add_argument("-results_file", type=str, required=False, help="Results File")
    smbparser.add_argument("-packet_rate", default=1, type=int, required=False, help="Packet rate")
    smbargs = smbparser.parse_args()
  
    semaphore = threading.BoundedSemaphore(value=smbargs.packet_rate)
    print_lock = threading.Lock()
 
    if smbargs.ip is not None:
        if smbargs.proto == 'SMB':
            smbscan(smbargs.ip, smbargs.results_file)
        else:
            dicomscan(smbargs.ip, smbargs.port, smbargs.results_file)

    elif smbargs.netrange is not None:
       if smbargs.proto == 'SMB':
           for ip in netaddr.IPNetwork(smbargs.netrange).iter_hosts():
               smbscan(str(ip), smbargs.results_file)
       else:
           for ip in netaddr.IPNetwork(smbargs.netrange).iter_hosts():
               dicomscan(str(ip), smbargs.port, smbargs.results_file) 

    elif not smbargs.packet_rate and smbargs.netrange:
       for ip in netaddr.IPNetwork(smbargs.netrange).iter_hosts():
           semaphore.acquire()
           smbthread = threading.Thread(target=thread_check, args=(str(ip), smbargs.results_file))
           smbthread.start()
           smbthread.join()
    else: 
        print "Please provide with either -ip or -netrange.  Or ./smbscanner.py -h for help.." 
        exit
