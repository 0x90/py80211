import pcap
import sys
import struct
import pdb


class IeTag80211:
    """
    Parsing 802.11 frame information elements
    """
    def __init__(self):
        """
        build parser for IE tags
        """
        self.tagdata = {"unparsed":[]}  # dict to return parsed tags
        self.parser = {
            "\x00": self.ssid,  # ssid IE tag parser
            "\x01": self.rates,  # data rates tag parser
            "\x03": self.channel,  # channel tag parser
            "\x30": self.rsn,  # rsn tag parser
            "\x32": self.exrates  # extended rates tag parser
                      }

    def parseIE(self, rbytes):
        """
        takes string of raw bytes splits them into tags
        passes those tags to the correct parser
        retruns parsed tags as a dict, key is tag number
        rbytes = string of bytes to parse
        """
        self.tagdata = {"unparsed":[]}  # dict to return parsed tags
        offsets = {}
        while len(rbytes) > 0:
            try:
                fbyte = rbytes[0]
                # add two to account for size byte and tag num byte
                blen = ord(rbytes[1]) + 2  # byte len of ie tag
                if fbyte in self.parser.keys():
                    self.parser[fbyte](rbytes[0:blen])
                else:
                    # we have no parser for the ie tag
                    self.tagdata["unparsed"].append(rbytes[0:blen])
                rbytes = rbytes[blen:]  # add two to offset tag number and get to new one
            except IndexError:
                # mangled packets
                return -1
       
    def exrates(self, rbytes):
        """
        parses extended supported rates
        exrates IE tag number is 0x32
        retruns exrates in a list
        """
        exrates = []
        for exrate in tuple(rbytes[2:]):
            exrates.append(ord(exrate))
        self.tagdata["exrates"] = exrates

    def channel(self, rbytes):
        """
        parses channel
        channel IE tag number is 0x03
        returns channel as int
        last byte is channel
        """
        self.tagdata["channel"] = ord(rbytes[2])

    def ssid(self, rbytes):
        """
        parses ssid IE tag
        ssid IE tag number is 0x00
        returns the ssid as a string
        """
        # how do we handle hidden ssids?
        self.tagdata["ssid"] = unicode(rbytes[2:], errors='replace')

    def rates(self, rbytes):
        """
        parses rates from ie tag
        rates IE tag number is 0x01
        returns rates as in a list
        """
        rates = []
        for rate in tuple(rbytes[2:]):
            rates.append(ord(rate))
        self.tagdata["rates"] = rates

    def rsn(self, rbytes):
        """
        parses robust security network ie tag
        rsn ie tag number is 0x30
        returns rsn info in nested dict
        gtkcs is group temportal cipher suite
        akm is auth key managment, ie either wpa, psk ....
        ptkcs is pairwise temportal cipher suite
        """
        rsn = {}
        ptkcs = []
        akm = []
        # need to extend this
        cipherS = {
            1 : "WEP-40/64",
            2 : "TKIP",
            3 : "RESERVED",
            4 : "CCMP",
            5 : "WEP-104/128"
            }
        authKey = {
            1 : "802.1x or PMK",
            2 : "PSK",
            }
        try:
            version = struct.unpack('h', rbytes[2:4])[0]
            rsn["gtkcsOUI"] = rbytes[4:7]
            # GTK Bytes Parsing
            gtkcsTypeI = ord(rbytes[7])
            if gtkcsTypeI in cipherS.keys():
                gtkcsType = cipherS[gtkcsTypeI]
            else:
                gtkcsType = gtkcsTypeI
            rsn["gtkcsType"] = gtkcsType
            # PTK Bytes Parsing
            # len of ptk types supported
            ptkcsTypeL = struct.unpack('h', rbytes[8:10])[0]
            counter = ptkcsTypeL
            cbyte = 10 #current byte
            while counter >= ptkcsTypeL:
                ptkcsTypeOUI = rbytes[cbyte:cbyte+3]
                ptkcsTypeI = ord(rbytes[cbyte+3])
                if ptkcsTypeI in cipherS.keys():
                    ptkcsType = cipherS[ptkcsTypeI]
                else:
                    ptkcsType = ptkcsTypeI
                cbyte += 4 # end up on next byte to parse
                ptkcs.append({"ptkcsOUI":ptkcsTypeOUI,
                              "ptkcsType":ptkcsType})
                counter -= 1

            akmTypeL = struct.unpack('h', rbytes[cbyte:cbyte+2])[0]
            cbyte += 2
            counter = akmTypeL
            #this might break need testing
            while counter >= akmTypeL:
                akmTypeOUI = rbytes[cbyte:cbyte+3]
                akmTypeI = ord(rbytes[cbyte+3])
                if akmTypeI in authKey.keys():
                    akmType = authKey[akmTypeI]
                else:
                    akmType = akmTypeI
                cbyte += 4 # end up on next byte to parse
                akm.append({"akmOUI":akmTypeOUI,
                              "akmType":akmType})
                counter -= 1
            # 8 bits are switches for various features
            capabil = rbytes[cbyte:cbyte+2]
            cbyte += 3 # end up on PMKID list
            rsn["pmkidcount"] = rbytes[cbyte:cbyte +2]
            rsn["pmkidlist"] = rbytes[cbyte+3:]
            rsn["ptkcs"] = ptkcs
            rsn["akm"] = akm
            rsn["capabil"] = capabil
            self.tagdata["rsn"] = rsn
        except IndexError:
            # mangled packets
            return -1

class Parse80211:
    """
    Class file for parsing
    several common 802.11 frames
    """
    def __init__(self, dev):
        """
        open up the libpcap interface
        open up the device to sniff from
        dev = device name as a string
        """
        self.IE = IeTag80211()
        # bytes are in little endian hex
        # doing this based off bytes is wrong... it works mostly however subtype is in bits not bytes and this may break in the future, should run bitwise on the byte
        self.parser = {
            "\x00": self.placedef,   # assoication request 
            "\x10": self.placedef,   # assoication responce
            "\x20": self.placedef,   # reassoication request
            "\x30": self.placedef,   # reassoication response
            "\x40": self.probeReq,   # probe request
            "\x50": self.probeResp,  # probe response
            "\x80": self.beacon,     # Beacon
            "\x90": self.placedef,   # ATIM
            "\xA0": self.placedef,   # disassoication
            "\xB0": self.placedef,   # Authenticaiton
            "\xC0": self.placedef,   # Deauthentication
            "\xC8": self.qos,        # qos
            "\x08": self.data,       # data
        }
        self.lp = pcap.pcapObject()
        # check what these numbers mean
        self.lp.open_live(dev, 1600, 0 ,100)
        if self.lp.datalink() == 127:
            self.rth = True
        else:
            self.rth = False
    
    def placedef(self, data):
        print data[18].encode('hex')
        print "No parser for subtype\n"

    def getFrame(self):
        """
        return a frame from libpcap
        """
        return self.lp.next()

    def parseFrame(self, frame):
        """
        Determine the type of frame and
        choose the right parser
        """
        if frame != None:
            data = frame[1]
            if self.rth:
                rt = struct.unpack('h', data[2:4])[0]
            else:
                rt = 0
        else:
            return None
        # determine frame subtype
        # subtype should be one off radio tap headers
        subtype = data[rt:rt +1]
        if subtype in self.parser.keys():
            #strip the radio tap header
            return self.parser[subtype](data[rt:])
        else:
            # we dont have a parser for the packet
            return None
    
    def data(self, data):
        """
        parse the src,dst,bssid from a data frame
        subtype = \x08 data hex byte
        wireshark shows subtype as \x20
        """
        # do a bit bitwise & to check which of the last 2 bits are set
        dsbits = ord(data[1]) & 3
        dst = data[4:10]  # destination addr 6 bytes
        bssid = data[10:16]  # bssid addr 6 bytes
        src = data[16:22]  # source addr 6 bytes
        return {"key":"\x08", "src":src, "dst":dst, "bssid":bssid, "ds":dsbits}

    def qos(self, data):
        """
        parse the src,dst,bssid from a qos frame
        subtype = \xC8
        """
        # fix bug in case we dont get radio tap headers
        dsbits = ord(data[1]) & 3
        dst = data[4:10]  # destination addr 6 bytes
        src = data[10:16]  # source addr 6 bytes
        bssid = data[16:22]  # bssid addr 6 bytes
        return {"key":"\xC8", "src":src, "dst":dst, "bssid":bssid, "ds":dsbits}

    def probeResp(self, data):
        """
        Parse out probe response
        return a dict of with keys of
        src, dst, bssid, probe request
        """
        dsbits = ord(data[1]) & 3
        dst = data[4:10]  # destination addr 6 bytes
        src = data[10:16]  # source addr 6 bytes
        bssid = data[16:22]  # bssid addr 6 bytes
        # parse the IE tags
        # possible bug, no fixed 12 byte paramaters before ie tags?
        # these seem to have it...
        self.IE.parseIE(data[36:])
        if "ssid" not in self.IE.tagdata.keys():
            essid = ""
        else:
            essid = self.IE.tagdata["ssid"]
        if "channel" not in self.IE.tagdata.keys():
            channel = ""
        else:
            channel = self.IE.tagdata["channel"]
        return {"key":"\x50", "bssid":bssid, "essid":essid, "src":src, 
            "dst":dst, "channel":channel, "extended":self.IE.tagdata, "ds":dsbits}
    
    def probeReq(self, data):
        """
        Parse out probe requests
        return a dict of with keys of
        src, dst, bssid, probe request
        """
        # fix bug in case we dont get radio tap headers
        dsbits = ord(data[1]) & 3
        dst = data[4:10]  # destination addr 6 bytes
        src = data[10:16]  # source addr 6 bytes
        bssid = data[16:22]  # bssid addr 6 bytes
        # parse the IE tags
        # possible bug, no fixed 12 byte paramaters before ie tags?
        self.IE.parseIE(data[24:])
        if "ssid" not in self.IE.tagdata.keys():
            essid = ""
        else:
            essid = self.IE.tagdata["ssid"]
        if "channel" not in self.IE.tagdata.keys():
            channel = ""
        else:
            channel = self.IE.tagdata["channel"]
        return {"key":"\x40", "bssid":bssid, "essid":essid, "src":src, 
            "dst":dst, "channel":channel, "extended":self.IE.tagdata, "ds":dsbits}
    
    def beacon(self, data):
        """
        Parse out beacon packets
        return a dict with the keys of
        src, dst, bssid, essid, channel ....
        going to need to add more
        """
        # fix bug in case we dont get radio tap headers
        dst = data[4:10]  # destination addr 6 bytes
        src = data[10:16]  # source addr 6 bytes
        bssid = data[16:22]  # bssid addr 6 bytes
        # parse the IE tags
        # assuming we have 12 byte paramaters
        self.IE.parseIE(data[36:])
        if "ssid" not in self.IE.tagdata.keys():
            essid = ""
        else:
            essid = self.IE.tagdata["ssid"]
        if "channel" not in self.IE.tagdata.keys():
            channel = ""
        else:
            channel = self.IE.tagdata["channel"]
        return {"key":"\x80", "bssid":bssid, "essid":essid, "src":src, "dst":dst, "channel":channel, "extended":self.IE.tagdata}

if __name__ == "__main__":
    x = Parse80211(sys.argv[1])
    while True:
        frame = x.parseFrame(x.getFrame())
        #if frame != None:
        #    if frame["key"] == "\x20":
        #        print frame
        print x.parseFrame(x.getFrame())
