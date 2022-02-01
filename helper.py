import random

def generateMac():
    return("%02x:%02x:%02x:%02x:%02x:%02x" % (random.randint(0, 255),
                                random.randint(0, 255),
                                random.randint(0, 255),
                                random.randint(0, 255),
                                random.randint(0, 255),
                                random.randint(0, 255)))
