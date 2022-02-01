import os
import sys
if not os.geteuid() == 0:
    sys.exit("\nOnly root can run this script\n")

from helper import generateMac
interface = input("Interface to use (will not be checked): ")



