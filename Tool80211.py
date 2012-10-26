import threading
import time
# custom imports
import Parse80211
import PyLorcon2

#debug imports
import pdb
import sys
import os

class Toolkit80211:
    """
    Group of class's for working with 80211
    """
    def __init__(self,interface):
        """
        interface = string 
        currently assumes all cards are to be opened in monitor mode
        """
        # open the card up and gain a a context to them
        # create a dict with interface name and context
        self.moniface = {"ctx":PyLorcon2.Context(interface)}
        # place cards in injection/monitor mode
        self.moniface["ctx"].open_injmon()
        self.moniface["name"] = self.moniface["ctx"].get_vap()

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
            self.pause = False
            # dwell for 3 time slices on 1 6 11
            # default is 3/10 of a second
            # got the lists from kismet config file
            # thanks dragorn!
            self.channellist = [1,6,11,14,2,7,3,8,4,9,5,10,36,40,44,48,52,56,60,64,149,153,157,161,165]
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
            #should raise an expection if this is the case
            """
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
                if self.pause == True:
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
        def __init__(self, interface):
            """
            Open up a packet parser for a given interface
            Thread the instance
            """
            threading.Thread.__init__(self)
            threading.Thread.daemon = True
            # get interface name for use with pylibpcap
            self.iface = interface["name"]
            # get context for dealing with channel hopper
            self.ctx = interface["ctx"]
            # open up a parser
            self.rd = Parse80211.Parse80211(self.iface)
            # key = bssid, value = essid
            self.bss = {}
            # load up latest beacon packet for an AP
            self.apData = {}
            # note fake AP's can end up in here.. need to solve this
            # key = essid, value [bssid, bssid]
            self.ess = {}
            # this may not work for WDS, though ignoring wds for now
            # key = mac, value=assoication
            self.clients = {}
            # data about a given client
            self.clientData = {}
        
        def updateClient(self, frame):
            """
            Update self.clients var based on ds bits
            """
            bssid = frame["bssid"]
            src = frame["src"]
            dst = frame["dst"]
            ds = frame["ds"]
            if ds == 0:
                # broadcast/adhoc
                self.clients[src] = "Not Assoicated"
            elif ds == 1:
                # station to ap
                self.clients[src] = dst
                return
            elif ds == 2:
                # ap to station
                # check for wired broadcasts
                if dst == '\xff\xff\xff\xff\xff\xff':
                    #were doing with a wired broadcast
                    #make sure we showe its connected to an ap
                    self.clients[src] = bssid
                else:
                    self.clients[dst] = src
                return
            elif ds == 3:
                # wds, were ignoring this for now
                return
            else:
                return

        def parse(self):
            """
            Grab a packet, call the parser then update
            The airview state vars
            """
            while True:
                self.channel = self.hopper.current
                frame = self.rd.parseFrame(
                            self.rd.getFrame())
                # beacon frames
                if frame == None:
                    continue
                if frame["key"] == "\x80":
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
                    continue
                # data frames
                elif frame["key"] in ["\x08", "\xC8","\x50"]:
                    self.updateClient(frame)
                elif frame["key"] in ["\x50"]:
                    self.clientData['src'] = frame

        def run(self):
            """
            start the parser
            """
            # need to start channel hopping here
            self.hopper = Toolkit80211.ChannelHop(self.ctx)
            self.hopper.start()
            self.parse()
    
    class RandomBits:
        """
        Class to hold all the random functions 
        to do one off things
        """
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

if __name__ == "__main__":
    try:
        x = Toolkit80211(sys.argv[1])
        #will only work with one
        y = x.Airview(x.moniface)
        y.start()
        ppmac = Toolkit80211.RandomBits.pformatMac
        while True:
            time.sleep(2)
            os.system("clear")
            lbss = y.bss
            print "Channel %i" %(y.channel)
            print "Access point"
            for bssid in lbss.keys():
                apbssid = ppmac(bssid)
                print "%s %s" %(apbssid, lbss[bssid])
            print "\nClients"
            lclient = y.clients
            for client in lclient.keys():
                pclient = ppmac(client)
                plclient = lclient[client]
                if plclient != "Not Assoicated":
                    plclient = ppmac(plclient)
                print "%s %s" %(pclient, plclient) 
    except KeyboardInterrupt:
        print "\nbye"
        sys.exit(0)
