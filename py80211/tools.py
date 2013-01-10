import threading
import time
import sys
import os
import fcntl
import struct
# custom imports
from py80211 import parsers
import PyLorcon2

class Interface(object):
    """
    handle 80211 interfacs
    """
    def __init__(self):
        self.tun = ""
        self.moniface = ""
        self.TUNSETIFF = 0x400454ca
        self.TUNSETOWNER = self.TUNSETIFF + 2
        self.IFF_TUN = 0x0001
        self.IFF_TAP = 0x0002
        self.IFF_NO_PI = 0x1000

    def check_tun(self, path):
        """
        check for tuntap support
        """
        # doesnt work
        #return os.path.isfile(path)
        return True

    def open_tun(self):
        """
        open up a tuntap interface
        path is /dev/net/tun in TAP (ether) mode
        returns false if failed
        """
        path = "/dev/net/tun"
        if self.check_tun(path) is not False:
            self.tun = os.open(path, os.O_RDWR)
            ifr = struct.pack("16sH", "tun%d", self.IFF_TAP | self.IFF_NO_PI)
            ifs = fcntl.ioctl(self.tun, self.TUNSETIFF, ifr)
            #fcntl.ioctl(self.tun, self.TUNSETOWNER, 1000)
            # return interface name
            ifname = ifs[:16].strip("\x00")
            # commented out...  for now!
            print "Interface %s created. Configure it and use it" % ifname
            # put interface up
            os.system("ifconfig %s up" %(ifname))
            # return interface name
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
        return os.read(self.tun, 1526)

    def writeTun(self, packet):
        """
        write a packet to tun interface
        """
        os.write(self.tun, packet)

    def monitor(self, interface):
        """
        open a monitor mode interface and create a vap
        interface = string
        currently assumes all cards are to be opened in monitor mode
        """
        # open the card up and gain a a context to them
        # create a dict with interface name and context
        try:
            self.moniface = {
                "ctx" : PyLorcon2.Context(interface)
                }
        except PyLorcon2.Lorcon2Exception, exception:
            print "%s is the %s interface there?" % (exception, interface)
            sys.exit(-1)
        # place cards in injection/monitor mode
        self.moniface["ctx"].open_injmon()
        self.moniface["name"] = self.moniface["ctx"].get_vap()

    @property
    def monitor_interface(self):
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
    def __init__(self, interface, channels=False):
        """
        set the channel hopping sequence
        expects lorcon injmon() context
        """
        self.lock = 0
        threading.Thread.__init__(self)
        threading.Thread.daemon = True
        self.iface = interface
        self.pause = False
        # dwell for 3 time slices on 1 6 11
        # default is 3/10 of a second
        # got the lists from kismet config file
        # thanks dragorn!
        self.channellist = channels
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
        self.pause = True

    def unpause(self):
        """
        Unpause the channel hopping
        """
        self.pause = False

    def setchannel(self, channel):
        """
        Set a single channel
        expects channel to be an int
        returns -1 if channel isnt supported
        #should raise an exception if this is the case
        """
        while self.lock == 1:
            print "!!!!!!!!!!!!!!Waiting for lock...!!!!!!!!!!!!"
            time.sleep(2)
        if channel in self.hopList:
            self.iface.set_channel(channel)
            return 0
        else:
            return -1

    def hop(self, dwell=.4):
        """
        Hop channels
        """
        while True:
            # hopping is paused though loop still runs
            if self.pause == True | self.lock == 1:
                continue
            for ch in self.hopList:
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
                    time.sleep(.2)

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
    def __init__(self, interface_, mon=False,
        channels = [1,6,11,14,2,7,3,8,4,9,5,10,
            36,40,44,48,52,56,60,64,149,153,157,161,165]):
        """
            Open up a packet parser for a given interface and create monitor mode interface
            Thread the instance
            interface = interface as string
            if mon = True then interface = to the dicitionary object from the interface
        """
        self.channels=channels
        self.stop = False
        self.hopper = ""
        threading.Thread.__init__(self)
        threading.Thread.daemon = True
        #create monitor mode interface
        if not mon:
            self.interface = Interface()
            self.interface.monitor(interface_)
            monif = self.interface.monitor_interface
        else:
            monif = interface_
        # get interface name for use with pylibpcap
        self.iface = monif["name"]
        # get context for dealing with channel hopper
        self.ctx = monif["ctx"]
        # open up a parser
        self.rd = parsers.Common(self.iface)
        # key = bssid, value = essid
        self.bss = {}
        # load up latest beacon packet for an AP
        self.apData = {}
        # note fake AP's can end up in here.. need to solve this
        # key = essid, value [bssid, bssid]
        self.ess = {}
        # this may not work for WDS, though ignoring wds for now
        # key = mac, value=assoication
        # probes from a given client
        self.clientProbes = {}
        # info on clients
        self.client_list=ClientList(self.iface)
        #the above works fine, but let's get more efficient
        self.view = {}
        # ap = key{essid},value{bssid,clients}
        # clients = key{mac},value{probelist[]}
        # dict to store last 5 essids seen for a bssid
        #key = bssid value=[ssid,ssid....]
        self.vSSID = {}
        # client to ap relationship
        self.capr = {}

    @staticmethod
    def pformatMac(hexbytes):
        """
        Take in hex bytes and pretty format them
        to the screen in the xx:xx:xx:xx:xx:xx format
        """
        mac = []
        for byte in hexbytes:
            mac.append(byte.encode('hex'))
        return ':'.join(mac)

    def verifySSID(self, bssid, uessid):
        """
        its possible to get a mangled ssid
        this allows us to check last 5 seen
        to see if they are mangled or its been changed
        bssid = bssid in hex of ap in question
        uessid = essid in hex to verify
        if all 5 dont match return False, else return True
        """
        for essid in self.vSSID[bssid]:
            if uessid != essid:
                # blank it out
                self.vSSID[bssid] = []
                return False
        return True

    @property
    def clients(self):
        return self.client_list.clients

    @property
    def clients_extra(self):
        return self.client_list.clients_extra

    def parse(self):
        """
        Grab a packet, call the parser then update
        The airview state vars
        """
        while self.stop is False:
            #TODO: we may need to set semaphore here?
            self.hopper.lock = 1
            self.channel = self.hopper.current
            frame = self.rd.parseFrame( self.rd.getFrame() )
            self.hopper.lock = 0
            #release semaphore here -- we have what we came for
            # beacon frames
            if frame == None:
                # we cant parse the frame
                continue
            if frame == -1:
                # frame is mangled
                continue
            if frame["type"] == 0 and frame["stype"] == 8:
                # beacon packet
                bssid = frame["bssid"]
                essid = frame["essid"]
                # update bss list, we dont check for keys
                # as it allows the essid for a given bssid to be updated
                self.bss[bssid] = essid
                # update ess list
                if essid in self.ess.keys():
                    self.ess[essid].append(bssid)
                else:
                    self.ess[essid]=[bssid]
                #update all info about ap
                self.apData[bssid] = frame
                if bssid in self.vSSID.keys():
                    ssidList = self.vSSID[bssid]
                    if len(ssidList) > 3:
                        # remove first item
                        ssidList.pop(0)
                        # append new one to back
                        ssidList.append(essid)
                        self.vSSID[bssid] = ssidList
                    else:
                        self.vSSID[bssid].append(essid)
                else:
                    self.vSSID[bssid] = [essid]
                continue
            elif frame["type"] == 2 and frame["stype"] in range(0,16):
                #applying to all data packets
                self.client_list.add(frame)
            if frame["type"] == 0 and frame["stype"] in [4]:
                # update client list
                self.client_list.add(frame)
                # process probe for essid
                src = frame["src"]
                essid = frame["essid"]
                if frame["src"] in self.clientProbes.keys():
                    if essid != '':
                        self.clientProbes[src][essid] = ""
                else:
                    # use dict behaivor to remove duplicates
                    if essid != '':
                        self.clientProbes[src] = {essid:""}
            # update client ap relationships
            self.getCapr()

    def getCapr(self, wiredc=False):
        """
        Parse clients list to build current list
        of bssids and their clients
        set wiredc to True to include wired devices discovered by broadcast
        """
        for client in self.clients.keys():
            # include or exclude wired devices
            if wiredc is False:
              if client in self.clients_extra.keys():
                if self.clients_extra[client]['wired'] is False:
                    # skip the wired devices
                    continue
            bssid = self.clients[client]
            if bssid != "Not Associated":
                if bssid not in self.capr.keys():
                    self.capr[bssid] = [client]
                else:
                    if client not in self.capr[bssid]:
                        self.capr[bssid].append(client)

    def getProbes(self, cmac):
        """
        return a list of probe requests
        for a given client
        """
        if cmac in self.clientProbes.keys():
            return self.clientProbes[cmac].keys()
        else:
            return None

    def run(self):
        """
        start the parser
        """
        # need to start channel hopping here
        self.hopper = ChannelHop(self.ctx, self.channels)
        self.hopper.start()
        self.parse()

    def kill(self):
        """
        stop the parser
        """
        self.stop = True
        self.interface.exit()

class ClientList(object):
    def __init__(self, iface):
        self.clients = {}
        self.clients_extra = {}
        self.rd = parsers.Common(iface)

    def add(self, frame):
        """
            Update self.clients var based on ds bits
        """
        bssid = frame["bssid"]
        src = frame["src"]
        dst = frame["dst"]
        ds = frame["ds"]
        if ds == 0:
            # broadcast/adhoc
            self.clients[src] = "Not Associated"
            if src in self.clients_extra.keys():
                self.clients_extra[src]['wired'] = False
            else:
                self.clients_extra[src] = {'wired':False}
        elif ds == 1:
            # station to ap
            self.clients[src] = bssid
            if src in self.clients_extra.keys():
                self.clients_extra[src]['wired'] = False
            else:
                self.clients_extra[src] = {'wired':False}
            return
        elif ds == 2:
            # ap to station
            # check for wired broadcasts
            if self.rd.isBcast(dst) is True:
                #were doing with a wired broadcast
                #make sure we show its connected to an ap
                self.clients[src] = bssid
                if src in self.clients_extra.keys():
                    # dont set a wireless client to wired
                    if self.clients_extra[src]['wired'] is not False:
                        self.clients_extra[src]['wired'] = True
                else:
                    self.clients_extra[src] = {'wired':True}
            # deal with ipv6 mutlicast
            elif self.rd.isBcast(dst) is True:
                #were doing with a wired broadcast
                #make sure we show its connected to an ap
                self.clients[src] = bssid
                if src in self.clients_extra.keys():
                    # dont set a wireless client to wired
                    if self.clients_extra[src]['wired'] is not False:
                        self.clients_extra[src]['wired'] = True
                else:
                    self.clients_extra[src] = {'wired':True}
            else:
                self.clients[dst] = bssid
                if src in self.clients_extra.keys():
                    self.clients_extra[src]['wired'] = False
                else:
                    self.clients_extra[src] = {'wired':False}
            return
        elif ds == 3:
            # wds, were ignoring this for now
            return
        else:
            return
