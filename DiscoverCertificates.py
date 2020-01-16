# Imports
import io
import os
from tkinter import *
import time
import ssl
from fnmatch import fnmatch
from socket import *
from http.server import HTTPServer, BaseHTTPRequestHandler
import ctypes
from ctypes import wintypes
import fire

# Local variables
root = "\\"

# Path of folder where it's save the certificates
file_path_certificates = "./CertificatesToImport"
file_path_details = "./CertificatesToImport/Details"

# Variables and classes needed on the function listSharedFolders
# netapi32.dll is a module that contains the Windows NET API used by applications to access a Microsoft network
netapi32 = ctypes.WinDLL('netapi32')

STYPE_DISKTREE = 0x00000000
STYPE_PRINTQ = 0x00000001
STYPE_DEVICE = 0x00000002
STYPE_IPC = 0x00000003
STYPE_MASK = 0x000000FF
STYPE_TEMPORARY = 0x40000000
STYPE_SPECIAL = 0x80000000

MAX_PREFERRED_LENGTH = 0xFFFFFFFF
ERROR_MORE_DATA = 0x00EA


class NET_API_BUFFER(ctypes.Structure):
    pass


class SHARE_INFO(NET_API_BUFFER):
    pass


class SHARE_INFO_1(SHARE_INFO):
    _fields_ = (('shi1_netname', wintypes.LPWSTR),
                ('shi1_type', wintypes.DWORD),
                ('shi1_remark', wintypes.LPWSTR))


LPNET_API_BUFFER = ctypes.POINTER(NET_API_BUFFER)


class LPSHARE_INFO(LPNET_API_BUFFER):
    _type_ = SHARE_INFO


class LPSHARE_INFO_1(LPSHARE_INFO):
    _type_ = SHARE_INFO_1


LPLPSHARE_INFO = ctypes.POINTER(LPSHARE_INFO)

if not hasattr(wintypes, 'LPBYTE'):  # 2.x
    wintypes.LPBYTE = ctypes.POINTER(wintypes.BYTE)

if not hasattr(wintypes, 'LPDWORD'):  # 2.x
    wintypes.LPDWORD = ctypes.POINTER(wintypes.DWORD)

netapi32.NetShareEnum.argtypes = (
    wintypes.LPWSTR,  # _In_    servername
    wintypes.DWORD,  # _In_    level
    LPLPSHARE_INFO,  # _Out_   bufptr
    wintypes.DWORD,  # _In_    prefmaxlen
    wintypes.LPDWORD,  # _Out_   entriesread
    wintypes.LPDWORD,  # _Out_   totalentries
    wintypes.LPDWORD)  # _Inout_ resume_handle

netapi32.NetApiBufferFree.argtypes = (
    LPNET_API_BUFFER,)  # _In_ Buffer


# Function to find folders shared from PC's, return folders shared
def listSharedFolders(serverName):
    pshare_info = LPSHARE_INFO_1()
    entries_read = wintypes.DWORD()
    total_entries = wintypes.DWORD()
    resume_handle = wintypes.DWORD()
    shares = []
    try:
        while True:
            result = netapi32.NetShareEnum(serverName,
                                           1,
                                           ctypes.byref(pshare_info),
                                           MAX_PREFERRED_LENGTH,
                                           ctypes.byref(entries_read),
                                           ctypes.byref(total_entries),
                                           ctypes.byref(resume_handle))
            if result and result != ERROR_MORE_DATA:
                raise ctypes.WinError(result)
            try:
                for i in range(entries_read.value):
                    info = pshare_info[i]
                    if info.shi1_type & STYPE_MASK == STYPE_DISKTREE:
                        shares.append(info.shi1_netname)
            finally:
                free_result = netapi32.NetApiBufferFree(pshare_info)
                if free_result:
                    raise ctypes.WinError(free_result)
            if result != ERROR_MORE_DATA:
                break
    except PermissionError:
        print("Host UP but without access")
    return shares


# Function to return the date and time actual
def createFolders():
    try:
        os.stat(file_path_certificates)
        os.stat(file_path_details)
    except:
        os.mkdir(file_path_certificates)
        os.mkdir(file_path_details)


# Function to return actual date and time
def dateAndTime():
    timeNow = time.strftime("%H:%M:%S")
    dateNow = (time.strftime("%d/%m/%Y"))
    return timeNow + dateNow


# Function to clear local files
def clearLocalFiles(filename):
    # Open the file with the param 'w' to rewrite with nothing
    open(filename, 'w').close()


# Function to find certificates in local machines
def findLocalCertificates():
    completeName = os.path.join(file_path_details, "detailsLocalCertificates.txt")
    with io.open(completeName, "a", encoding="utf-8") as f:
        f.write(dateAndTime() + '\n')
        f.close()
    for path, subdirs, files in os.walk(root):
        for name in files:
            if name.endswith((".p12", ".crt", ".pfx", ".cer", ".jks", "jceks")):
                with io.open(completeName, "a", encoding="utf-8") as f:
                    # Concatenation of path and name and write this the file
                    f.write(os.path.join(path, name) + '\n')
                    f.close()


# HOST/IP -> Unique ports, Common ports, Multiple ports, Shared Folders
# Function to find a specific certificate for one ip and respective port
def findCertificateHostUniquePort(ip, port):
    try:
        # Save in variable "toFile" the certificate
        toFile = ssl.get_server_certificate((ip, port))
        # To save the certificate with name and port of the specific certificate
        nameFile = ip + port + ".crt"
        # Join the folder with the name of certificate
        completeNameCert = os.path.join(file_path_certificates, nameFile)
        # Open to "w" write
        f = open(completeNameCert, "w")
        # Write in the file
        f.write(toFile)
        f.close()
        completeName = os.path.join(file_path_details, "detailsCertificateHostUniquePort.txt")
        with io.open(completeName, "a", encoding="utf-8") as f:
            f.write(completeNameCert)
            f.close()
    except TimeoutError:
        print("TimeoutError, Host unavailable")
    except ConnectionRefusedError:
        print("Connection refused, Host available but dont connect")


# Function to find certificates in machine that knows ip and ond only in the common ports
def findCertificatesHostCommonPorts(ip):
    ports = [22, 25, 443, 465, 993, 994, 995]
    for port in ports:
        try:
            print(ip, port)
            # Save in variable "toFile" the certificate
            toFile = ssl.get_server_certificate((ip, port))
            # To save the certificate with name and port of the specific certificate
            nameFile = ip + str(port) + ".crt"
            # Join the folder with the name of certificate
            completeNameCert = os.path.join(file_path_certificates, nameFile)
            # Open to "w" write
            f = open(completeNameCert, "w")
            # Write in the file
            f.write(toFile)
            f.close()
            completeName = os.path.join(file_path_details, "detailsCertificatesHostCommonPorts.txt")
            with io.open(completeName, "a", encoding="utf-8") as f:
                f.write(completeNameCert)
                f.close()
        except TimeoutError:
            print("TimeoutError, Host unavailable")
        except ConnectionRefusedError:
            print("Connection refused, Host available but dont connect")


# Function to find certificates in machine that knows ip and ond the ports that pass in argument
def findCertificatesHostMultiplePorts(ip, ports):
    ports = ports.rsplit(",")
    for port in ports:
        try:
            print(ip, port)
            # Save in variable "toFile" the certificate
            toFile = ssl.get_server_certificate((ip, port))
            # To save the certificate with name and port of the specific certificate
            nameFile = ip + str(port) + ".crt"
            # Join the folder with the name of certificate
            completeNameCert = os.path.join(file_path_certificates, nameFile)
            # Open to "w" write
            f = open(completeNameCert, "w")
            # Write in the file
            f.write(toFile)
            f.close()
            completeName = os.path.join(file_path_details, "detailsCertificatesHostMultiplePorts.txt")
            with io.open(completeName, "a", encoding="utf-8") as f:
                f.write(completeNameCert)
                f.close()
        except TimeoutError:
            print("TimeoutError, Host unavailable")
        except ConnectionRefusedError:
            print("Connection refused, Host available but dont connect")


# Function to find all certificates for determinate ip
def findCertificateHostAllPorts(ip):
    # For with the ports that the function run
    for ports in range(1, 655351):
        try:
            print(ip, ports)
            # Save in variable "toFile" the certificate
            toFile = ssl.get_server_certificate((ip, ports))
            # To save the certificate with name and port of the specific certificate
            nameFile = ip + str(ports) + ".crt"
            # Join the folder with the name of certificate
            completeNameCert = os.path.join(file_path_certificates, nameFile)
            # Open to "w" write
            f = open(completeNameCert, "w")
            # Write in the file
            f.write(toFile)
            f.close()
            completeName = os.path.join(file_path_details, "detailsCertificateHostAllPorts.txt")
            with io.open(completeName, "a", encoding="utf-8") as f:
                f.write(dateAndTime() + "\n")
                f.write(completeNameCert + "\n")
                f.close()
        except TimeoutError:
            print("TimeoutError, Host unavailable")
        except ConnectionRefusedError:
            print("Connection refused, Host available but dont connect")


# List certificates in the shared folders found on the function ListSharedFolders from one IP
def listCertificatesHostSharedFolders(IP):
    completeName = os.path.join(file_path_details, "detailsCertificatesHostSharedFolders")
    with io.open(completeName + ".txt", "a", encoding="utf-8") as f:
        f.write(dateAndTime() + '\n')
        f.close()
        try:
            share = listSharedFolders(IP)
            try:
                for idx, val in enumerate(share):
                    for root, dirs, files in os.walk(r"\\" + IP + "\\" + val):
                        for name in files:
                            if name.endswith((".crt")):
                                copyfile(os.path.join(r"\\" + IP, val, root, name),
                                         file_path_certificates + "/" + str(IP + val + name))
                            if name.endswith((".p12", ".pfx", ".cer", ".jks", "jceks")):
                                with io.open(completeName + ".txt", "a", encoding="utf-8") as f:
                                    print(os.path.join(r"\\" + IP, val, root, name))
                                    out = os.path.join(r"\\" + IP, val, root, name + "\n")
                                    f.write(out)
                                    f.close()
            except PermissionError:
                print("Folder *" + val + "* without access")
        except FileNotFoundError:
            print("FileNotFoundError, Host unavailable: " + IP)
        except PermissionError:
            print("Folder *" + val + "* without access")


# Ip Range -> Unique ports, Common ports, Multiple ports, Shared Folders
# Function to find certificates in range of ip's in a specific port
def findCertificatesRangeUniquePorts(iniIP, endIP, port):
    # Split IP
    ipcompleteINI = iniIP.rsplit(".")
    ipcompleteEND = endIP.rsplit(".")
    ip = ipcompleteINI[0] + "." + ipcompleteINI[1] + "." + ipcompleteINI[2] + "."
    for rangeIP in range(int(ipcompleteINI[3]), int(ipcompleteEND[3])):
        # try save the certificate for determinate ip and port
        try:
            ipTotal = ip + str(rangeIP)
            print(ipTotal + ":" + str(port))
            toFile = ssl.get_server_certificate((ipTotal, str(port)))
            name_of_file = ipTotal + str(port) + ".crt"
            completeName = os.path.join(file_path_certificates, name_of_file)
            f = open(completeName, "w")
            f.write(toFile)
            f.close()
            completeNameDetails = os.path.join(file_path_details, "detailsCertificatesRangeUniquePorts.txt")
            with io.open(completeNameDetails, "a", encoding="utf-8") as f:
                f.write(dateAndTime() + "\n")
                f.write(completeName + "\n")
                f.close()
        except TimeoutError:
            print("TimeoutError, Host unavailable")
        except ConnectionRefusedError:
            print("Connection refused, Host available but dont connect")


# Function to find cerificates in a ip range for common ports
def findCertificatesInIPrangeCommonPorts(iniIP, endIP):
    ports = [22, 25, 443, 465, 993, 994, 995]
    # Split the IP
    ipcompleteINI = iniIP.rsplit(".")
    ipcompleteEND = endIP.rsplit(".")
    ip = ipcompleteINI[0] + "." + ipcompleteINI[1] + "." + ipcompleteINI[2] + "."
    # For with the ports that the function run
    for port in ports:
        # For with the IP's that the function run
        for rangeIP in range(int(ipcompleteINI[3]), int(ipcompleteEND[3])):
            # try save the certificate for determinate ip and port
            try:
                ipTotal = ip + str(rangeIP)
                print(ipTotal + ":" + str(port))
                toFile = ssl.get_server_certificate((ipTotal, str(port)))
                name_of_file = ipTotal + str(port) + ".crt"
                completeName = os.path.join(file_path_certificates, name_of_file)
                f = open(completeName, "w")
                f.write(toFile)
                f.close()
                completeNameDetails = os.path.join(file_path_details, "detailsCertificatesInIPrangeCommonPorts.txt")
                with io.open(completeNameDetails, "a", encoding="utf-8") as f:
                    f.write(dateAndTime() + "\n")
                    f.write(completeName + "\n")
                    f.close()
            except TimeoutError:
                print("TimeoutError, Host unavailable")
            except ConnectionRefusedError:
                print("Connection refused, Host available but don't connect")


# Function to find cerificates in a ip range for multiple ports
def findCertificatesInIPrangeMultiplePorts(iniIP, endIP, ports):
    ports = ports.rsplit(",")
    # Split the IP
    ipcompleteINI = iniIP.rsplit(".")
    ipcompleteEND = endIP.rsplit(".")
    ip = ipcompleteINI[0] + "." + ipcompleteINI[1] + "." + ipcompleteINI[2] + "."
    # For with the ports that the function run
    for port in ports:
        # For with the IP's that the function run
        for rangeIP in range(int(ipcompleteINI[3]), int(ipcompleteEND[3])):
            # try save the certificate for determinate ip and port
            try:
                ipTotal = ip + str(rangeIP)
                print(ipTotal + ":" + str(port))
                toFile = ssl.get_server_certificate((ipTotal, str(port)))
                name_of_file = ipTotal + str(port) + ".crt"
                completeName = os.path.join(file_path_certificates, name_of_file)
                f = open(completeName, "w")
                f.write(toFile)
                f.close()
                completeNameDetails = os.path.join(file_path_details, "detailsCertificatesInIPrangeMultiplePorts.txt")
                with io.open(completeNameDetails, "a", encoding="utf-8") as f:
                    f.write(dateAndTime() + "\n")
                    f.write(completeName + "\n")
                    f.close()
            except TimeoutError:
                print("TimeoutError, Host unavailable")
            except ConnectionRefusedError:
                print("Connection refused, Host available but don't connect")


# Function to find cerificates in a ip range for the all ports
def findCertificatesInIPrangeAllPorts(iniIP, endIP):
    # Split the IP
    ipcompleteINI = iniIP.rsplit(".")
    ipcompleteEND = endIP.rsplit(".")
    ip = ipcompleteINI[0] + "." + ipcompleteINI[1] + "." + ipcompleteINI[2] + "."
    # For with the ports that the function run
    for port in range(1, 655351):
        # For with the IP's that the function run
        for rangeIP in range(int(ipcompleteINI[3]), int(ipcompleteEND[3])):
            # try save the certificate for determinate ip and port
            try:
                ipTotal = ip + str(rangeIP)
                print(ipTotal + ":" + str(port))
                toFile = ssl.get_server_certificate((ipTotal, str(port)))
                name_of_file = ipTotal + str(port) + ".crt"
                completeName = os.path.join(file_path_certificates, name_of_file)
                f = open(completeName, "w")
                f.write(toFile)
                f.close()
                completeNameDetails = os.path.join(file_path_details, "detailsCertificatesInIPrangeAllPorts.txt")
                with io.open(completeNameDetails, "a", encoding="utf-8") as f:
                    f.write(dateAndTime() + "\n")
                    f.write(completeName + "\n")
                    f.close()
            except TimeoutError:
                print("TimeoutError, Host unavailable")
            except ConnectionRefusedError:
                print("Connection refused, Host available but don't connect")


# List certificates in the shared folders found on the function ListSharedFolders from on IP range
def listCertificatesIPRangeSharedFolders(iniIP, endIP):
    ipcompleteINI = iniIP.rsplit(".")
    ipcompleteEND = endIP.rsplit(".")
    ip = ipcompleteINI[0] + "." + ipcompleteINI[1] + "." + ipcompleteINI[2] + "."
    completeName = os.path.join(file_path_details, "detailsCertificatesIPRangeSharedFolders")
    with io.open(completeName + ".txt", "a", encoding="utf-8") as f:
        f.write(dateAndTime() + '\n')
        f.close()
        for rangeIP in range(int(ipcompleteINI[3]), int(ipcompleteEND[3])):
            ipTotal = ip + str(rangeIP)
            try:
                share = listSharedFolders(ipTotal);
                for idx, val in enumerate(share):
                    for root, dirs, files in os.walk(r"\\" + ipTotal + "\\" + val):
                        for name in files:
                            if name.endswith((".crt")):
                                copyfile(os.path.join(r"\\" + ipTotal, val, root, name),
                                         file_path_certificates + "/" + str(ipTotal + val + name))
                            if name.endswith((".p12", ".pfx", ".cer", ".jks", "jceks")):
                                with io.open(completeName + ".txt", "a", encoding="utf-8") as f:
                                    print(os.path.join(r"\\" + ipTotal, val, root, name))
                                    out = os.path.join(r"\\" + ipTotal, val, root, name + "\n")
                                    f.write(out)
                                    f.close()
            except PermissionError:
                print("Folder *" + val + "* without access")
            except FileNotFoundError:
                print("FileNotFoundError, Host unavailable: " + ipTotal)
            except PermissionError:
                print("Folder *" + val + "* without access")


# Multiple networks -> Unique ports, Common ports, Multiple ports, Shared Folders

# Function to find all certificates in multiple networks in specific port
def findCertificatesMultipleNetworksUniquePort(networks, port):
    networks = networks.rsplit(",")
    for ip in networks:
        # For with the IP's that the function run
        for rangeIP in range(1, 255 + 1):
            # try save the certificate for determinate ip and port
            try:
                ipTotal = ip + str(rangeIP)
                print(ipTotal + ":" + str(port))
                toFile = ssl.get_server_certificate((ipTotal, str(port)))
                name_of_file = ipTotal + str(port) + ".crt"
                completeNameCert = os.path.join(file_path_certificates, name_of_file)
                f = open(completeNameCert, "w")
                f.write(toFile)
                f.close()
                completeName = os.path.join(file_path_details, "detailsCertificatesMultipleNetworksUniquePort.txt")
                with io.open(completeName, "a", encoding="utf-8") as f:
                    f.write(dateAndTime() + "\n")
                    f.write(completeNameCert + "\n")
                    f.close()
            except ConnectionRefusedError:
                print("Connection refused, Host available but dont connect")
            except TimeoutError:
                print("TimeoutError, Host unavailable")


# Function to find all certificates in multiple networks on common ports
def findCertificatesMultipleNetworksCommonPorts(networks):
    networks = networks.rsplit(",")
    ports = [22, 25, 443, 465, 993, 994, 995]
    for ip in networks:
        for port in ports:
            # For with the IP's that the function run
            for rangeIP in range(1, 255 + 1):
                # try save the certificate for determinate ip and port
                try:
                    ipTotal = ip + str(rangeIP)
                    print(ipTotal + ":" + str(port))
                    toFile = ssl.get_server_certificate((ipTotal, str(port)))
                    name_of_file = ipTotal + str(port) + ".crt"
                    completeNameCert = os.path.join(file_path_certificates, name_of_file)
                    f = open(completeNameCert, "w")
                    f.write(toFile)
                    f.close()
                    completeName = os.path.join(file_path_details, "detailsCertificatesMultipleNetworksCommonPorts.txt")
                    with io.open(completeName, "a", encoding="utf-8") as f:
                        f.write(dateAndTime() + "\n")
                        f.write(completeNameCert + "\n")
                        f.close()
                except ConnectionRefusedError:
                    print("Connection refused, Host available but dont connect")
                except TimeoutError:
                    print("TimeoutError, Host unavailable")


# Function to find all certificates in multiple networks on multiple ports
def findCertificatesMultipleNetworksMultiplePorts(networks, ports):
    networks = networks.rsplit(",")
    ports = ports.split(",")
    for ip in networks:
        for port in ports:
            # For with the IP's that the function run
            for rangeIP in range(1, 255 + 1):
                # try save the certificate for determinate ip and port
                try:
                    ipTotal = ip + str(rangeIP)
                    print(ipTotal + ":" + str(port))
                    toFile = ssl.get_server_certificate((ipTotal, str(port)))
                    name_of_file = ipTotal + str(port) + ".crt"
                    completeNameCert = os.path.join(file_path_certificates, name_of_file)
                    f = open(completeNameCert, "w")
                    f.write(toFile)
                    f.close()
                    completeName = os.path.join(file_path_details,
                                                "detailsCertificatesMultipleNetworksMultiplePorts.txt")
                    with io.open(completeName, "a", encoding="utf-8") as f:
                        f.write(dateAndTime() + "\n")
                        f.write(completeNameCert + "\n")
                        f.close()
                except ConnectionRefusedError:
                    print("Connection refused, Host available but dont connect")
                except TimeoutError:
                    print("TimeoutError, Host unavailable")


# Function to find all certificates in multiple networks in all ports
def findCertificatesMultipleNetworksAllPorts(networks):
    networks = networks.rsplit(",")
    for ip in networks:
        for port in range(1, 655351):
            # For with the IP's that the function run
            for rangeIP in range(1, 255 + 1):
                # try save the certificate for determinate ip and port
                try:
                    ipTotal = ip + str(rangeIP)
                    print(ipTotal + ":" + str(port))
                    toFile = ssl.get_server_certificate((ipTotal, str(port)))
                    name_of_file = ipTotal + str(port) + ".crt"
                    completeNameCert = os.path.join(file_path_certificates, name_of_file)
                    f = open(completeNameCert, "w")
                    f.write(toFile)
                    f.close()
                    completeName = os.path.join(file_path_details, "detailsCertificatesMultipleNetworksAllPorts.txt")
                    with io.open(completeName, "a", encoding="utf-8") as f:
                        f.write(dateAndTime() + "\n")
                        f.write(completeNameCert + "\n")
                        f.close()
                except ConnectionRefusedError:
                    print("Connection refused, Host available but dont connect")
                except TimeoutError:
                    print("TimeoutError, Host unavailable")


# List certificates in the shared folders found on the function ListSharedFolders from on IP range
def listCertificatesMultipleNetworksSharedFolders(networks):
    networks = networks.rsplit(",")
    completeName = os.path.join(file_path_details, "detailsCertificatesMultipleNetworksSharedFolders")
    with io.open(completeName + ".txt", "a", encoding="utf-8") as f:
        f.write(dateAndTime() + '\n')
        f.close()
        for ip in networks:
            for rangeIP in range(1, 255 + 1):
                ipTotal = ip + str(rangeIP)
                try:
                    share = listSharedFolders(ipTotal);
                    for idx, val in enumerate(share):
                        for root, dirs, files in os.walk(r"\\" + ipTotal + "\\" + val):
                            for name in files:
                                if name.endswith((".crt")):
                                    copyfile(os.path.join(r"\\" + ipTotal, val, root, name),
                                             file_path_certificates + "/" + str(ipTotal + val + name))
                                if name.endswith((".p12", ".pfx", ".cer", ".jks", "jceks")):
                                    with io.open(completeName + ".txt", "a", encoding="utf-8") as f:
                                        print(os.path.join(r"\\" + ipTotal, val, root, name))
                                        out = os.path.join(r"\\" + ipTotal, val, root, name + "\n")
                                        f.write(out)
                                        f.close()
                except PermissionError:
                    print("Folder *" + val + "* without access")
                except FileNotFoundError:
                    print("FileNotFoundError, Host unavailable: " + ipTotal)
                except PermissionError:
                    print("Folder *" + val + "* without access")


# Program starts, as code is run
if __name__ == '__main__':
    createFolders()
    fire.Fire()
# PROGRAM FINISHES
