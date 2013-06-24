import threading
import time
import sys
import os
import fcntl
import struct
from select import select
import pcap
# custom imports
import Parse80211
import PyLorcon2
from wifiobjects import *

#debug imports
import pdb
import sys

class iface80211:
    """
    handle 80211 interfacs
    """
    def __init__(self):
        self.TUNSETIFF = 0x400454ca
        self.TUNSETOWNER = self.TUNSETIFF + 2
        self.IFF_TUN = 0x0001
        self.IFF_TAP = 0x0002
        self.IFF_NO_PI = 0x1000


    def checkTun(self, path):
        """
        check for tuntap support
        """
        # doesnt work
        #return os.path.isfile(path)
        return True

    def openTun(self):
        """
        open up a tuntap interface
        path is /dev/net/tun in TAP (ether) mode
        returns false if failed
        """
        path = "/dev/net/tun"
        if self.checkTun(path) is not False:
            self.tun = os.open(path, os.O_RDWR)
            # ifr = struct.pack("16sH", "tun%d", self.IFF_TAP | self.IFF_NO_PI)
            ifr = struct.pack("16sH", "tun%d", self.IFF_TAP)
            ifs = fcntl.ioctl(self.tun, self.TUNSETIFF, ifr)
            #fcntl.ioctl(self.tun, self.TUNSETOWNER, 1000)
            # return interface name
            ifname = ifs[:16].strip("\x00")
            # commented out...  for now!
            print "Interface %s created. Configure it and use it" % ifname
            # put interface up
            os.system("ifconfig %s up" %(ifname))
            # return interface name
            try:
                self.lp = pcap.pcapObject()
                self.lp.open_live(ifname, 1526, 0 ,100)
            except AttributeError:
                print "You have the wrong pypcap installed"
                print "Use https://github.com/signed0/pylibpcap.git"
            return ifname
        else:
            return False
    
    def inject(self, packet):
        """
        send bytes to pylorcon interface
        """
        if self.moniface is not None:
            self.moniface['ctx'].send_bytes(packet)

    
    def readTun(self):
        """
        read a packet from tun interface
        """
        packet = select([self.tun],[],[])[0]
        if self.tun in packet:
            return os.read(self.tun, 1526)
    
    def sniffTun(self):
        """
        read a packet from tun interface
        """
        return self.lp.next()

    def writeTun(self, packet):
        """
        write a packet to tun interface
        """
        os.write(self.tun, packet)

    def openMon(self, interface):
        """
        open a monitor mode interface and create a vap
        interface = string 
        currently assumes all cards are to be opened in monitor mode
        """
        # open the card up and gain a a context to them
        # create a dict with interface name and context
        try:
            self.moniface = {"ctx":PyLorcon2.Context(interface)}
        except PyLorcon2.Lorcon2Exception,e:
            print "%s is the %s interface there?" %(e, interface)
            sys.exit(-1)
        # place cards in injection/monitor mode
        self.moniface["ctx"].open_injmon()
        self.moniface["name"] = self.moniface["ctx"].get_vap()
        #self.air = self.Airview(self.moniface)
        #self.air.start()

    def getMonmode(self):
        """
        retruns mon interface object
        """
        return self.moniface

    def exit(self):
        """
        Close card context
        """
        self.moniface["ctx"].close()

class ChannelHop(threading.Thread):
    """
    Control a card and cause it to hop channels
    Only one card per instance
    """
    def __init__(self,interface):
        """
        set the channel hopping sequence
        expects lorcon injmon() context
        """
        threading.Thread.__init__(self)
        threading.Thread.daemon = True
        self.iface = interface
        self.HOPpause = False
        # dwell for 3 time slices on 1 6 11
        # default is 3/10 of a second
        # got the lists from kismet config file
        # thanks dragorn!
        self.channellist = [1,6,11,14,2,7,3,8,4,9,5,10,
            36,40,44,48,52,56,60,64,149,153,157,161,165]
        self.hopList = []
        self.current = 0
        self.checkChannels()

    def checkChannels(self):
        """
        card drivesr suck, determine what channels 
        a card supports before we start hopping
        """
        # try setting 802.11ab channels first
        # this may not work depending on 5ghz dfs
        # reverse so we start with 5ghz channels first
        for ch in self.channellist:
            try:
                self.iface.set_channel(ch)
            except PyLorcon2.Lorcon2Exception:
                continue
            self.hopList.append(ch)
    
    def pause(self):
        """
        Pause the channel hopping
        """
        self.HOPpause = True

    def unpause(self):
        """
        Unpause the channel hopping
        """
        self.HOPpause = False
    
    def setchannel(self, channel):
        """
        Set a single channel
        expects channel to be an int
        returns -1 if channel isnt supported
        #should raise an exception if this is the case
        """
        if channel in self.hopList:
            self.iface.set_channel(channel)
            return 0
        else:
            return -1

    def hop(self, dwell=.5):
        """
        Hop channels
        """
        while True:
            for ch in self.hopList:
                # hopping is paused though loop still runs
                if self.HOPpause is True:
                    continue
                try:
                    self.iface.set_channel(ch)
                except PyLorcon2.Lorcon2Exception:
                    continue
                self.current = ch
                if ch in [1,6,11]:
                    # dwell for 4/10 of a second
                    # we want to sit on 1 6 and 11 a bit longer
                    time.sleep(dwell)
                else:
                    time.sleep(.3)
    
    def run(self):
        """
        start the channel hopper
        """
        self.hop()

class Airview(threading.Thread):
    """
    Grab a snapshot of the air
    whos connected to who
    whats looking for what
    # note right now expecting to deal with only one card
    # will need to refactor code to deal with more then one in the future
    # dong this for time right now
    """
    def __init__(self, interface, mon=False):
        """
        Open up a packet parser for a given interface and create monitor mode interface
        Thread the instance
        interface = interface as string
        if mon = True then interface = to the dicitionary object from iface80211
        """
        self.stop = False
        self.hopper = ""
        threading.Thread.__init__(self)
        threading.Thread.daemon = True
        #create monitor mode interface
        if mon is False:
            self.intf = iface80211()
            self.intf.openMon(interface)
            monif = self.intf.getMonmode()
        else:
            monif = interface
        # get interface name for use with pylibpcap
        self.iface = monif["name"]
        # get context for dealing with channel hopper
        self.ctx = monif["ctx"]
        # open up a parser
        self.rd = Parse80211.Parse80211(self.iface)
        
        #### New code ####
        # dict object to store client objects in 
        # format is {mac_address:object}
        self.clientObjects = {}
        # dict object to store ap objects in
        # format is {bssid:object}
        self.apObjects = {}
        #dict object to store ess objects
        # format is {essid:object}
        self.essObjects = {}


    @staticmethod
    def pformatMac(hexbytes):
        """
        Take in hex bytes and pretty format them 
        to the screen in the xx:xx:xx:xx:xx:xx format
        """
        mac = []
        if hexbytes is not None:
            for byte in hexbytes:
                mac.append(byte.encode('hex'))
            return ':'.join(mac).upper()
        else:
            return hexbytes

    def processData(self, frame):
        """
        Update self.clients var based on ds bits
        """
        bssid = frame["bssid"]
        src = frame["src"]
        dst = frame["dst"]
        ds = frame["ds"]
        assoicated = False
        wired = None
        # actual client mac
        clientmac = None
        # NOTE need to figure how to mark a client
        # no longer assoicated
        clientrssi = None
        aprssi = None
        if ds == 0:
            # broadcast/adhoc/managmentFrames
            assoicated = True
            if frame["type"] == 0 and frame["stype"] == 4:
                # probe packet
                assoicated = False
            wired = False
            clientmac = src
            aprssi = frame["rssi"]

        elif ds == 1:
            # station to ap
            assoicated = True
            wired = False
            clientmac = src
            clientrssi = frame["rssi"]

        elif ds == 2:
            # ap to station
            clientmac = dst
            assoicated = True
            aprssi = frame["rssi"]
            # check for wired broadcasts
            if self.rd.isBcast(dst) is True:
                # were working with a wired broadcast
                wired = True
                # reset client mac to correct src addr
                clientmac = src
            else:
                wired = False
        elif ds == 3:
            # wds, were ignoring this for now
            return
        client_obj = None
        # create client mac if it doesnt exist
        if clientmac not in self.clientObjects.keys(): 
            self.clientObjects[clientmac] = client(clientmac)
        client_obj = self.clientObjects[clientmac]
        if clientrssi is not None:
            client_obj.rssi = clientrssi
        client_obj.updateWired(wired)
        client_obj.assoicated = assoicated
        #update last time seen
        client_obj.lts = time.time()
        if assoicated is True:
            """
            may get client before we see ap, 
            check to see if we have ap object yet
            if we do add reference link
            """
            if bssid in self.apObjects.keys():
                client_obj.apObject = self.apObjects[bssid]
            client_obj.updateBssid(bssid)
            # remove client from old bssid if moved to new bssid
            if client_obj.lastBssid != bssid:
                if bssid in self.apObjects.keys():
                    self.apObjects[bssid].delClients(clientmac)
        else:
            client_obj.updateBssid("Not Assoicated")
        #update access points with connected clients
        # create ap objects based on bssids seen from clients
        # make sure we dont do broadcast addresses
        if self.rd.isBcast(bssid) is False:
            if bssid not in self.apObjects.keys():
                # create new object
                self.apObjects[bssid] = accessPoint(bssid)
            # update list of clients connected to an AP
            ap_object = self.apObjects[bssid]
            ap_object.addClients(clientmac)
            if aprssi is not None:
                ap_object.rssi = aprssi

    def parse(self):
        """
        Grab a packet, call the parser then update
        The airview state vars
        """
        while self.stop is False:
            self.channel = self.hopper.current
            frame = self.rd.parseFrame(
                        self.rd.getFrame())
            
            # beacon frames
            if frame == None:
                # we cant parse the frame
                continue
            if frame == -1:
                # frame is mangled
                continue
            
            if frame["type"] == 0 and frame["stype"] == 8:
                # beacon packet
                ap_object = None
                bssid = frame["bssid"]
                essid = frame["essid"]
                # grab the AP object or create it if it doesnt exist
                if bssid not in self.apObjects.keys():
                    # create new object
                    self.apObjects[bssid] = accessPoint(bssid)
                ap_object = self.apObjects[bssid]
                # populate rssi
                ap_object.rssi = frame["rssi"]
                # update essid
                ap_object.updateEssid(essid)
                # update ap encryption
                ap_object.encryption = frame["encryption"]
                ap_object.auth = frame["auth"]
                ap_object.cipher = frame["cipher"]
                # update channel
                ap_object.channel = frame["channel"]
                # update ap_last time seen
                ap_object.lts = time.time()
                # update the ess
                #NOTE this is broken, need to populate ess from ap's
                if ap_object.essid in self.essObjects.keys():
                    if bssid not in self.essObjects[essid].points:
                        self.essObjects[essid].points.append(bssid)
            
            elif frame["type"] == 2 and frame["stype"] in range(0, 17):
                # applying to all data packets, subtype 0 - 16
                self.processData(frame)
            
            elif frame["type"] == 0 and frame["stype"] in [4]:
                # probes parsing
                # update client list
                self.processData(frame)
                # process probe for essid
                src = frame["src"]
                essid = frame["essid"]
                if src not in self.clientObjects.keys(): 
                    self.clientObjects[clientmac] = client(src)
                client_obj = self.clientObjects[src]
                client_obj.rssi = frame['rssi']
                client_obj.updateProbes(essid)
                if client_obj.bssid is None:
                    client_obj.updateBssid("Not Assoicated")
                client_obj.managedFrame = True
                client_obj.lts = time.time()

            elif frame["type"] == 0 and frame["stype"] in [10,12]:
                # deauth/disassoicate
                src = frame["src"]
                dst = frame["dst"]
                bssid = frame["bssid"]
                for addy in [src, dst]:
                    if addy in self.clientObjects.keys():
                        client_obj = self.clientObjects[addy]
                        client_obj.rssi = frame["rssi"]
                        client_obj.assoicated = False
                        client_obj.updateBssid("Not Assoicated")
                        client_obj.managedFrame = True
                        client_obj.lts = time.time()
                        if bssid in self.apObjects.keys():
                            self.apObjects[bssid].delClients(addy)

    def run(self):
        """
        start the parser
        """
        # need to start channel hopping here
        self.hopper = ChannelHop(self.ctx)
        self.hopper.start()
        self.parse()
    
    def kill(self):
        """
        stop the parser
        """
        self.stop = True
        self.intf.exit()

