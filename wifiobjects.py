import time


class accessPoint:
    """
    Access point object
    """
    def __init__(self):
        # set first time seen
        self.fts = time.time()      # firs time object is seen
        self.lts = None             # last time object is seen, update on every acccess
        self.name = "accessPoint"   # object type
        self.connectedclients = []  # list of connected clients
        self.essid = ""             # broadcasted essid
        self.bssid = ""             # bssid of ap
        self.hidden = False         # denote if essid is hidden
        self.encryption = "Unknown" # show encryption level
        self.auth = "Unknown"       # show authentication settings
        self.channel = None         # ap's channel

    def numClients(self):
        """
        return number of connected clients
        as an int
        """
        return len(self.connectedclients)


class client:
    """
    Client object
    """
    def __init__(self):
        self.fts = time.time()     # first time object is seen
        self.lts = None            # last time object is seen, update on every access 
        self.name = "client"       # object type
        self.mac = None            # client mac address
        self.probes = []           # list of probe requests client broadcast
        self.assoicated = False    # list of client is associated to an ap
        self.bssid = None          # Bssid of assoicated ap

    def numProbes(self):
        """
        return number of probe requests
        as an int
        """
        return len(self.probes)
