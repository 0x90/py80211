import time

class ess:
    """
    extended service area object
    """
    def __init__(self):
        self.fts = time.time()      # first time object is seen
        self.lts = None             # last time object is seen, update on every acccess
        self.name = "ess"           # object type
        self.points = []            # list of bssids that belong to ess

class accessPoint:
    """
    Access point object
    """
    def __init__(self, bssid):
        # set first time seen
        self.fts = time.time()      # first time object is seen
        self.lts = None             # last time object is seen, update on every acccess
        self.name = "accessPoint"   # object type
        self.connectedclients = []  # list of connected clients
        self.essid = ""             # broadcasted essid
        self.bssid = bssid          # bssid of ap
        self.hidden = False         # denote if essid is hidden
        self.encryption = "Unknown" # show encryption level
        self.auth = "Unknown"       # show authentication settings
        self.channel = None         # ap's channel
        self.ssidList = []          # rolling list of seen ssid's for this ap
    
    def numClients(self):
        """
        return number of connected clients
        as an int
        """
        return len(self.connectedclients)
    
    def updateEssid(self, essid, iternum=3):
        """
        help prevent mangled ssids from being set
        require us to see it at least 3 times before we update
        as new ssids come in old ones get phased out
        essid = essid in hex
        iternum = int num of ssids to compair agasint
        """
        counter = 0
        if len(self.ssidList) < iternum:
            # havent seen 3 beacons yet, set first essid we see
            self.essid = essid
        for ssid in self.ssidList:
            if essid != ssid:
                # something didnt match stop checking
                break
            if essid == ssid and counter == iternum:
                # all 3 matched, update
                self.essid = essid
            counter += 1
        # remove first record and append new one to back
        if len(self.ssidList) != 0:
            self.ssidList.pop(0)
        self.ssidList.append(essid)
            
class client:
    """
    Client object
    """
    def __init__(self, mac):
        """
        mac = client mac address in hex
        """
        self.fts = time.time()        # first time object is seen
        self.lts = None               # last time object is seen, update on every access 
        self.name = "client"          # object type
        self.mac = mac                # client mac address
        self.probes = []              # list of probe requests client broadcast
        self.assoicated = False       # list if client is associated to an ap
        self.bssid = "Not Assoicated" # Bssid of assoicated ap
        self.wired = False            # not a wired client by default
    
    def updateProbes(self, probe):
        """
        update probes list and keep it unique
        """
        try:
            self.probes.index(probe)
        except ValueError:
            self.probes.append(probe)
            
    def numProbes(self):
        """
        return number of probe requests
        as an int
        """
        return len(self.probes)
