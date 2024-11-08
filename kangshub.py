# -*- coding: utf-8 -*-
"""
#Updated and better than kangshub2.py which was uploaded accidentally!!!
Usage:
> python kangaroo.py -p {LOCATION OF FILE CONTAINING PUBLICKEYS} -keyspace {STARTING RANGE:ENDING RANGE} -R/r {FOR RANDOM MODE OF KEYS GENERATION} //OR// -S/s {FOR SEQUENTIAL GENERATION} -ncore {FOR NUMBER OF CPU THREADS} -t/T {Interval time in seconds for range reset}
@Retyped-by: shubsaini08
@Credit-goes-to: ICELAND {-he's the one-}
"""

import bit
import ctypes
import platform
import sys
import os
import argparse
import signal
import time
import psutil
from coincurve import PublicKey
from secrets import SystemRandom

# Argument parser setup
parser = argparse.ArgumentParser(description='This tool uses Kangaroo algorithm for searching 1 pubkey in the specified range with multiple CPUs')
parser.version = '--shubv1--kangShub--'
parser.add_argument("-p", "--pubkey", help="Path to a file containing public keys in hex format, one per line", required=True)
parser.add_argument("-keyspace", help="Keyspace range (hex) to search from min:max", action='store')
parser.add_argument("-ncore", help="Number of CPU threads to use. default = Total-1", action='store')
parser.add_argument("-n", help="Total range search per loop. default=72057594037927935", action='store')
parser.add_argument("-r", help="Random mode", action="store_true")
parser.add_argument("-s", help="Sequential mode", action="store_true")
parser.add_argument("-t", help="Time interval for resetting range (seconds)", type=int, default=120)
args = parser.parse_args()

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

# Keyspace setup
ss = args.keyspace if args.keyspace else '1:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140'
a, b = [int(x, 16) for x in ss.split(':')]
increment = int(args.n) if args.n else 72057594037927935
flag_random = args.r
ncore = int(args.ncore) if args.ncore else os.cpu_count() - 1

# Load CPU-specific DLLs or shared libraries for Kangaroo algorithm
if platform.system().lower().startswith('win'):
    pathdll = os.path.realpath('Kangaroo_CPU.dll')
    ice = ctypes.CDLL(pathdll)
elif platform.system().lower().startswith('lin'):
    pathdll = os.path.realpath('Kangaroo_CPU.so')
    ice = ctypes.CDLL(pathdll)
else:
    print("[-] Unsupported Platform for ctypes DLL method. Only Windows and Linux are supported.")
    sys.exit()

ice.run_cpu_kangaroo.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p
]
ice.init_kangaroo_lib()

def run_cpu_kangaroo(start_range_int, end_range_int, dp, ncpu, mx, upub_bytes):
    st_hex = hex(start_range_int)[2:].encode('utf8')
    en_hex = hex(end_range_int)[2:].encode('utf8')
    res = (b'\x00') * 32
    ice.run_cpu_kangaroo(st_hex, en_hex, dp, ncpu, mx, res, upub_bytes)
    return res

def pub2upub(pub_hex):
    x = int(pub_hex[2:66], 16)
    if len(pub_hex) >= 70:
        y = int(pub_hex[66:], 16)
    else:
        curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        y_square = (pow(x, 3, curve_order) + 7) % curve_order
        y = pow(y_square, (curve_order + 1) // 4, curve_order)
        if y % 2 != 0:
            y = curve_order - y
    upub_bytes = b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
    return upub_bytes

def load_public_keys(filepath):
    try:
        with open(filepath, "r") as f:
            keys = {line.strip() for line in f if line.strip()}
        print(f"[+] Working on number of Pubkey: {len(keys)}")
        return keys
    except FileNotFoundError:
        print(f"[-] File not found: {filepath}")
        sys.exit()

def random_or_sequential(a, b, last, flag_random):
    if flag_random:
        return SystemRandom().randrange(a, b + 1)
    return last + 1 if last <= b else a

range_st = random_or_sequential(a, b, a, flag_random)
range_en = range_st + increment

batch_start = time.time()
print(f"[+] Starting Kangaroo Algorithm........Please Wait........   >  Version :: [{parser.version}]  <")
print("[+] Search Mode: Range search Continuous in the given range")

# Load keys
pub_keys = load_public_keys(args.pubkey) if os.path.isfile(args.pubkey) else {args.pubkey}
start_time = time.time()
key_count = 0
found_keys = 0

for pub in pub_keys:
    upub = pub2upub(pub)
    print(f"[+] Starting search for Pubkey: {upub.hex()}")

    while True:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        elapsed_time = time.time() - start_time
        ram_usage = psutil.virtual_memory().percent

        print(f"[+] Using [Number of CPU Threads: {ncore}] [DP size: 10] [MaxStep: 2]")
        print("====================================================================================================================")
        print(f"[+] Scanning Range :: [{hex(range_st)} :: {hex(range_en)}]")
        print("====================================================================================================================")

        pvk_found = run_cpu_kangaroo(range_st, range_en, 10, ncore, 2, upub)
        key_count += 1
        key_speed = key_count / (elapsed_time + 1e-8)

        print(f"++ [{key_speed:.2f} Keys/s][found {key_count}][Elapsed {int(elapsed_time)}s][RAM {ram_usage}%]", end='\r')

        if int(pvk_found.hex(), 16) != 0:
            print("\n===================================================== KEYFOUND ========================================================")
            print(f"Kangaroo FOUND PrivateKey :   0x{pvk_found.hex()}")
            print("==============================================StaY--BLesSeD============================================================")
            print(f"++ Kangaroo FOUND Pubkey :   {pub}")
            print("==============================================--THANK-YOU-FOR-USING--==================================================")
            with open("KEYFOUNDKEYFOUND.txt", "a") as f:
              f.write(f"PrivateKey: 0x{pvk_found.hex()} | PublicKey: {pub}\n")
            found_keys += 1

        if args.t and time.time() - batch_start >= args.t:
            range_st = random_or_sequential(a, b, range_st, flag_random)
            range_en = range_st + increment
            print("[+] RANGE IS RESET TO NEW STARTING RANGE WITHIN GIVEN RANGE")
            batch_start = time.time()

print(f"[+] Program Finished. Found {found_keys} keys. Exiting.")
