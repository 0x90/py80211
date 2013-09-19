__author__ = "TheX1le, Crypt0s, radiotap parsing orginally by Scott Raynel in the radiotap.py project"

import pcap
import sys
import struct

class InformationElements(object):
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
            "\x32": self.exrates,  # extended rates tag parser
            "\xDD": self.vendor221, # 221 vendor tag parser
                      }
    def vendor221(self, rbytes):
        """
        Parse the wpa IE tag 221 aka \xDD
        returns wpa info in nested dict
        gtkcs is group temportal cipher suite
        akm is auth key managment, ie either wpa, psk ....
        ptkcs is pairwise temportal cipher suite
        """
        wpa = {}
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
            # remove IE tag, len and Microsoft OUI
            packetLen = ord(rbytes[1])
            vendor_OUI = rbytes[2:5]
            vendor_OUI_type = ord(rbytes[5])
            if vendor_OUI == "\x00\x50\xf2":
                if vendor_OUI_type == 1:
                    # WPA Element Parsing
                    version = struct.unpack('h', rbytes[6:8])[0]
                    wpa["gtkcsOUI"] = rbytes[8:11]
                    # GTK Bytes Parsing
                    gtkcsTypeI = ord(rbytes[11])
                    if gtkcsTypeI in cipherS.keys():
                        gtkcsType = cipherS[gtkcsTypeI]
                    else:
                        gtkcsType = gtkcsTypeI
                    wpa["gtkcsType"] = gtkcsType
                    # PTK Bytes Parsing
                    # len of ptk types supported
                    ptkcsTypeL = struct.unpack('h', rbytes[12:14])[0]
                    counter = ptkcsTypeL
                    cbyte = 14 #current byte
                    while counter != 0:
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
                    counter = akmTypeL
                    # skip past the akm len
                    cbyte = cbyte + 2
                    while counter != 0:
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
                    wpa["ptkcs"] = ptkcs
                    wpa["akm"] = akm
                    self.tagdata["wpa"] = wpa
                if vendor_OUI_type == 4:
                    wpsState = "Unknown"
                    # WPA Element Parsing
                    # Verson data element type
                    det = struct.unpack('h', rbytes[6:8])[0]
                    # data element length
                    delen = struct.unpack('h', rbytes[8:10])[0]
                    # wps version
                    version = ord(rbytes[10])
                    # WPS data element type
                    wdet = struct.unpack('h', rbytes[11:13])[0]
                    # WPS data element length
                    wdelen = struct.unpack('h', rbytes[13:15])[0]
                    # wps state
                    if ord(rbytes[15]) is 2:
                        # wps is configured
                        wpsState = "configured"
                    self.tagdata["wps"] = {"state": wpsState}
        except IndexError:
            # mangled packets
            return -1

    def parseIE(self, rbytes):
        """
        takes string of raw bytes splits them into tags
        passes those tags to the correct parser
        retruns parsed tags as a dict, key is tag number
        rbytes = string of bytes to parse
        """
        self.tagdata = {"unparsed":[]}  # dict to return parsed tags
        # offsets = {} # TODO
        while len(rbytes) > 0:
            try:
                fbyte = rbytes[0]
                # add two to account for size byte and tag num byte
                blen = ord(rbytes[1]) + 2  # byte len of ie tag
                if fbyte in self.parser.keys():
                    prebytes = rbytes[0:blen]
                    if blen == len(prebytes):
                        self.parser[fbyte](prebytes)
                    else:
                        # mangled packets
                        return -1
                else:
                    # we have no parser for the ie tag
                    self.tagdata["unparsed"].append(rbytes[0:blen])
                rbytes = rbytes[blen:]
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
            while counter != 0:
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
            while counter != 0:
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

class Common(object):
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
        # this gets set to True if were seeing mangled packets
        self.mangled = False
        # number of mangled packets seen
        self.mangledcount = 0
        # create ie tag parser
        self.IE = InformationElements()
        self.parser = {0:{  # managment frames
            0: self.placedef,   # assoication request
            1: self.placedef,   # assoication response
            2: self.placedef,   # reassoication request
            3: self.placedef,   # reaassoication response
            4: self.probeReq,   # probe request
            5: self.probeResp,  # probe response
            8: self.beacon,     # beacon
            9: self.placedef,   # ATIM
            10: self.deauthDisass,  # disassoication
            11: self.placedef,  # authentication
            12: self.deauthDisass,  # deauthentication
            }, 1:{},  # control frames
            2:{  # data frames
             0: self.fdata,  # data
             1: self.fdata,  # data + CF-ack
             2: self.fdata,  # data + CF-poll
             3: self.fdata,  # data + CF-ack+CF-poll
             5: self.fdata,  # CF-ack
             6: self.fdata,  # CF-poll
             7: self.fdata,  # CF-ack+CF-poll
             8: self.fdata,  # QoS Data
             9: self.fdata,  # QoS Data + CF-ack
             10: self.fdata,  # QoS Data + CF-poll
             11: self.fdata,  # QoS Data + CF-ack+CF-poll
             12: self.fdata,  # QoS Null
             14: self.fdata,  # QoS + CF-poll (no data)
             15: self.fdata,  # QoS + CF-ack (no data)
             }}

        self.packetBcast = {
            "oldbcast": '\x00\x00\x00\x00\x00\x00',  # old broadcast address
            "l2": '\xff\xff\xff\xff\xff\xff',     # layer 2 mac broadcast
            "ipv6m": '\x33\x33\x00\x00\x00\x16',  # ipv6 multicast
            "stp": '\x01\x80\xc2\x00\x00\x00',    # Spanning Tree multicast 802.1D
            "cdp": '\x01\x00\x0c\xcc\xcc\xcc',    # CDP/VTP mutlicast address
            "cstp": '\x01\x00\x0C\xCC\xCC\xCD',   # Cisco shared STP Address
            "stpp": '\x01\x80\xc2\x00\x00\x08',   # Spanning Tree multicast 802.1AD
            "oam": '\x01\x80\xC2\x00\x00\x02',    # oam protocol 802.3ah
            "ipv4m": '\x01\x00\x5e\x7F\x00\xCD',  # ipv4 multicast
            "ota" : '\x01\x0b\x85\x00\x00\x00',    # Over the air provisioning multicast
            "v6Neigh" : '\x33\x33\xff\x00\x00\x00' # ipv6 neighborhood discovery
        }
        self.openLiveSniff(dev)

    def openLiveSniff(self, dev):
        """
        open up a libpcap object
        return object and radio tap boolen
        """
        packet = None
        try:
            self.lp = pcap.pcapObject()
        except AttributeError:
            print "You have the wrong pypcap installed"
            print "Use https://github.com/signed0/pylibpcap.git"
        snap_lenght = 1600 # Size to get, this might truncate packages
        promisc_flag = 0 # 0 to not put the interface in promisc mode
        timeout = 100 # Timout in ms
        self.lp.open_live(dev, snap_lenght, promisc_flag, timeout)
        if self.lp.datalink() == 127:
            self.rth = True
            # snag a packet to look at header, this should always be a
            # packet that wasnt injected so should have a rt header
            while packet is None:
                frame = self.getFrame()
                if frame is not None:
                    packet = frame[1]
            # set known header size
            self.headsize = struct.unpack('h', packet[2:4])[0]
        else:
            self.rth = False
        return

    def isBcast(self, mac):
        """
        returns boolen if mac is a broadcast/multicast mac
        """
        for bcastType in ['ipv6m', 'ipv4m', 'v6Neigh']:
            if mac[:3] == self.packetBcast[bcastType][:3]:
                return True
        if mac in self.packetBcast.values():
            return True
        else:
            return False

    def placedef(self, data):
        pass
        #print data[self.rt].encode('hex')
        #print "No parser for subtype\n"

    def getFrame(self):
        """
        return a frame from libpcap
        """
        return self.lp.next()

    def parseRtap(self, rtap):
        """
        radio tap parser taken from http://code.google.com/p/python-radiotap/source/browse/trunk/radiotap.py
        orginal author, c) 2007 Scott Raynel <scottraynel@gmail.com>
        Minor changes by TheX1le
        """
        # All Radiotap fields are in little-endian byte-order.
        # We use our own alignment rules, hence '<'.
        data = {}
        fields = []
        rformat = "<"
        RTAP_TSFT = 0
        RTAP_FLAGS = 1
        RTAP_RATE = 2
        RTAP_CHANNEL = 3
        RTAP_FHSS = 4
        RTAP_DBM_ANTSIGNAL = 5
        RTAP_DBM_ANTNOISE = 6
        RTAP_LOCK_QUALITY = 7
        RTAP_TX_ATTENUATION = 8
        RTAP_DB_TX_ATTENUATION = 9
        RTAP_DBM_TX_POWER = 10
        RTAP_ANTENNA = 11
        RTAP_DB_ANTSIGNAL = 12
        RTAP_DB_ANTNOISE = 13
        RTAP_RX_FLAGS = 14
        RTAP_TX_FLAGS = 15
        RTAP_RTS_RETRIES = 16
        RTAP_DATA_RETRIES = 17
        RTAP_EXT = 31 # Denotes extended "present" fields.

        self._PREAMBLE_FORMAT = "<BxHI"
        self._PREAMBLE_SIZE = struct.calcsize(self._PREAMBLE_FORMAT)
        try:
            (v,l,p) = self._unpack_preamble(rtap)
        except Exception:
            return -1
        # Skip extended bitmasks
        pp = p
        skip = 0
        while pp & 1 << RTAP_EXT:
                pp = buf[self._PREAMBLE_SIZE + skip]
                skip += 1

        # Generate a rformat string to be passed to unpack
        # To do this, we look at each of the radiotap fields
        # we know about in order. We have to make sure that
        # we keep all fields aligned to the field's natural
        # boundary. E.g. 16 bit fields must be on a 16-bit boundary.

        if p & 1 << RTAP_TSFT:
                rformat += "Q"
                fields.append(RTAP_TSFT)
        if p & 1 << RTAP_FLAGS:
                rformat += "B"
                fields.append(RTAP_FLAGS)
        if p & 1 << RTAP_RATE:
                rformat += "B"
                fields.append(RTAP_RATE)
        if p & 1 << RTAP_CHANNEL:
                # Align to 16 bit boundary:
                rformat += self._field_align(2, rformat)
                rformat += "I"
                fields.append(RTAP_CHANNEL)
        if p & 1 << RTAP_FHSS:
                rformat += "H"
                fields.append(RTAP_FHSS)
        if p & 1 << RTAP_DBM_ANTSIGNAL:
                rformat += "b"
                fields.append(RTAP_DBM_ANTSIGNAL)
        if p & 1 << RTAP_DBM_ANTNOISE:
                rformat += "b"
                fields.append(RTAP_DBM_ANTNOISE)
        if p & 1 << RTAP_LOCK_QUALITY:
                rformat += self._field_align(2, rformat)
                rformat += "H"
                fields.append(RTAP_LOCK_QUALITY)
        if p & 1 << RTAP_TX_ATTENUATION:
                rformat += self._field_align(2, rformat)
                rformat += "H"
                fields.append(RTAP_TX_ATTENUATION)
        if p & 1 << RTAP_DBM_TX_POWER:
                rformat += "b"
                fields.append(RTAP_DBM_TX_POWER)
        if p & 1 << RTAP_ANTENNA:
                rformat += "B"
                fields.append(RTAP_ANTENNA)
        if p & 1 << RTAP_DB_ANTSIGNAL:
                rformat += "B"
                fields.append(RTAP_DB_ANTSIGNAL)
        if p & 1 << RTAP_DB_ANTNOISE:
                rformat += "B"
                fields.append(RTAP_DB_ANTNOISE)
        if p & 1 << RTAP_RX_FLAGS:
                rformat += self._field_align(2, rformat)
                rformat += "H"
                fields.append(RTAP_RX_FLAGS)
        if p & 1 << RTAP_TX_FLAGS:
                rformat += self._field_align(2, rformat)
                rformat += "H"
                fields.append(RTAP_TX_FLAGS)
        if p & 1 << RTAP_RTS_RETRIES:
                rformat += "B"
                fields.append(RTAP_RTS_RETRIES)
        if p & 1 << RTAP_DATA_RETRIES:
                rformat += "B"
                fields.append(RTAP_DATA_RETRIES)

        end = self._PREAMBLE_SIZE + skip + struct.calcsize(rformat)
        unpacked = struct.unpack(rformat, rtap[self._PREAMBLE_SIZE + skip:end])

        for i in range(len(unpacked)):
                data[fields[i]] = unpacked[i]
        return data

    def _unpack_preamble(self, buf):
        if len(buf) < self._PREAMBLE_SIZE:
                raise Exception("Truncated at Radiotap preamble.")
        (v,l,p) = struct.unpack(self._PREAMBLE_FORMAT, buf[:self._PREAMBLE_SIZE])
        if v != 0:
                raise Exception("Radiotap version not handled")
        return (v,l,p)

    def _field_align(self, fbytes, string):
        """ Returns a number of 'x' characters to ensure that
            the next character fits on a 'bytes' boundary.
        """
        n = struct.calcsize(string) % fbytes
        if n == 0:
                return ""
        return 'x' * (fbytes - n)

    def parseFrame(self, frame):
        """
        Determine the type of frame and
        choose the right parser
        """
        # set the wep bit for the packet
        self.wepbit = False
        if frame is not None:
            data = frame[1]
            if data is None:
                return None
            if self.rth:
                self.rt = struct.unpack('h', data[2:4])[0]
                # check to see if packet really has a radio tap header
                # lorcon injected packets wont
                if self.rt != self.headsize:
                    self.rt = 0
            else:
                self.rt = 0
        else:
            return None
        # parse radio tap if not 0
        try:
            rtapData = self.parseRtap(data[:self.rt])
        except Exception:
            # bad rtap header, pass for now
            pass
        # determine frame subtype
        ptype = ord(data[self.rt])
        # wipe out all bits we dont need
        ftype = (ptype >> 2) & 3
        stype = ptype >> 4
        # protected data bit aka the WEP bit
        flags = ord(data[self.rt + 1])
        if (flags & 64):
            self.wepbit = True
        if ftype in self.parser.keys():
            if stype in self.parser[ftype].keys():
                # will return -1 if packet is mangled
                # none if we cant parse it
                parsedFrame = self.parser[ftype][stype](data[self.rt:])
                # packet is mangled some how return the error
                if parsedFrame in [None, -1]:
                    return parsedFrame
                else:
                    parsedFrame["type"] = ftype
                    parsedFrame["stype"] = stype
                    parsedFrame["wepbit"] = self.wepbit
                    # strip the headers
                    parsedFrame['rtap'] = self.rt
                    # get the rssi from rtap data
                    if rtapData == -1:
                        # truncated rtap, make rssi None
                        parsedFrame['rssi'] = None
                    else:
                        parsedFrame['rssi'] = rtapData[5]
                    parsedFrame["raw"] = data
                return parsedFrame
            else:
                # we dont have a parser for the packet
                return None
        else:
            # we dont have a parser for the packet
            return None

    def data(self, data):
        return self.fdata(self, data)

    def fdata(self, data):
        """
            parse the src,dst,bssid from a data frame
        """
        # do a bit bitwise & to check which of the last 2 bits are set
        try:
            dsbits = ord(data[1]) & 3
            # from ds to station via ap
            if dsbits == 1:
                bssid = data[4:10]  # bssid addr 6 bytes
                src = data[10:16]  # src addr 6 bytes
                dst = data[16:22]  # destination addr 6 bytes
            # from station to ds va ap
            elif dsbits == 2:
                dst = data[4:10]  # destination addr 6 bytes
                bssid = data[10:16]  # bssid addr 6 bytes
                src = data[16:22]  # source addr 6 bytes
            # wds frame
            elif dsbits == 3:
                # we dont do anything with these yet
                return None
            else:
                # mangled ds bits
                self.mangled = True
                self.mangledcount += 1
                return -1
        except IndexError:
            self.mangled = True
            self.mangledcount += 1
            return -1
        return {"src":src, "dst":dst, "bssid":bssid, "ds":dsbits, "wepbit":self.wepbit}

    def probeResp(self, data):
        """
        Parse out probe response
        return a dict of with keys of
        src, dst, bssid, probe request
        """
        try:
            dsbits = ord(data[1]) & 3
            dst = data[4:10]  # destination addr 6 bytes
            src = data[10:16]  # source addr 6 bytes
            bssid = data[16:22]  # bssid addr 6 bytes
            # parse the IE tags
            # possible bug, no fixed 12 byte paramaters before ie tags?
            # these seem to have it...
            self.IE.parseIE(data[36:])
            if "ssid" not in self.IE.tagdata.keys():
                self.mangled = True
                self.mangledcount += 1
                return -1
            else:
                essid = self.IE.tagdata["ssid"]
            if "channel" not in self.IE.tagdata.keys():
                self.mangled = True
                self.mangledcount += 1
                return -1
            else:
                channel = self.IE.tagdata["channel"]
        except IndexError:
            self.mangled = True
            self.mangledcount += 1
            return -1
        return {"bssid":bssid, "essid":essid, "src":src,
            "dst":dst, "channel":channel, "extended":self.IE.tagdata, "ds":dsbits}

    def probeReq(self, data):
        """
        Parse out probe requests
        return a dict of with keys of
        src, dst, bssid, probe request
        """
        try:
            dsbits = ord(data[1]) & 3
            dst = data[4:10]  # destination addr 6 bytes
            src = data[10:16]  # source addr 6 bytes
            bssid = data[16:22]  # bssid addr 6 bytes
            # parse the IE tags
            # possible bug, no fixed 12 byte paramaters before ie tags?
            self.IE.parseIE(data[24:])
            if "ssid" not in self.IE.tagdata.keys():
                self.mangled = True
                self.mangledcount += 1
                return -1
            else:
                essid = self.IE.tagdata["ssid"]
            if "channel" not in self.IE.tagdata.keys():
                self.mangled = True
                self.mangledcount += 1
                return -1
            else:
                channel = self.IE.tagdata["channel"]
        except IndexError:
            self.mangled = True
            self.mangledcount += 1
            return -1
        return {"bssid":bssid, "essid":essid, "src":src,
            "dst":dst, "channel":channel, "extended":self.IE.tagdata, "ds":dsbits}

    def deauthDisass(self, data):
        """
        Parse out a deauthentication or disassoication packet
        """
        try:
            dsbits = ord(data[1]) & 3
            dst = data[4:10]  # destination addr 6 bytes
            src = data[10:16]  # source addr 6 bytes
            bssid = data[16:22]  # bssid addr 6 bytes
            reasonCode = struct.unpack('h', data[-2:])[0]
        except IndexError:
            self.mangled = True
            self.mangledcount += 1
            return -1
        return {"bssid":bssid, "src":src, "reasonCode":reasonCode,
            "dst":dst, "ds":dsbits}

    def beacon(self, data):
        """
        Parse out beacon packets
        return a dict with the keys of
        src, dst, bssid, essid, channel ....
        going to need to add more
        """
        akm = None
        encryption = None
        try:
            dsbits = ord(data[1]) & 3
            dst = data[4:10]  # destination addr 6 bytes
            src = data[10:16]  # source addr 6 bytes
            bssid = data[16:22]  # bssid addr 6 bytes
            # parse the IE tags
            # bits 34 and 35 are capabilities
            beaconWepBit = False
            if (struct.unpack('h', data[34:36])[0] & 16):
                beaconWepBit = True
            self.IE.parseIE(data[36:])
            if "ssid" not in self.IE.tagdata.keys():
                self.mangled = True
                self.mangledcount += 1
                return -1
            else:
                essid = self.IE.tagdata["ssid"]
            if "channel" not in self.IE.tagdata.keys():
                self.mangled = True
                self.mangledcount += 1
                return -1
            else:
                channel = self.IE.tagdata["channel"]
            # determine encryption level
            tagKeys = self.IE.tagdata.keys()
            if "rsn" in tagKeys:
                encryption = 'wpa2'
                cipher = []
                authkey = []
                for ptk in self.IE.tagdata['rsn']['ptkcs']:
                    cipher.append(ptk['ptkcsType'])
                if len(cipher) > 1:
                    cipher = '/'.join(cipher)
                else:
                    cipher = cipher[0]
                for akm in self.IE.tagdata['rsn']['akm']:
                    authkey.append(akm['akmType'])
                if len(authkey) > 1:
                    authkey = "/".join(authkey)
                else:
                    authkey = authkey[0]
            elif "wpa" in tagKeys:
                # its wpa1
                encryption = 'wpa'
                cipher = []
                authkey = []
                for ptk in self.IE.tagdata['wpa']['ptkcs']:
                    cipher.append(ptk['ptkcsType'])
                if len(cipher) > 1:
                    cipher = '/'.join(cipher)
                else:
                    cipher = cipher[0]
                for akm in self.IE.tagdata['wpa']['akm']:
                    authkey.append(akm['akmType'])
                if len(authkey) > 1:
                    authkey = "/".join(authkey)
                else:
                    authkey = authkey[0]
            elif beaconWepBit is True:
                authkey = "open"
                cipher = "WEP 64/128"
                encryption = 'WEP'
            elif beaconWepBit is False:
                # its open
                authkey = "open"
                encryption = "open"
                cipher = "None"
            else:
                authkey = "Unknown"
                encryption = "Unknown"
                cipher = "Unknown"
        except IndexError:
            self.mangled = True
            self.mangledcount += 1
            return -1
        return {"bssid":bssid, "essid":essid, "src":src, "dst":dst,
            "channel":channel, "extended":self.IE.tagdata, "ds":dsbits,
            "encryption":encryption, "auth":authkey, "cipher":cipher}

if __name__ == "__main__":
    x = Common(sys.argv[1])
    while True:
        frame = x.parseFrame(x.getFrame())
        #if frame != None:
        #    if frame["key"] == "\x20":
        #        print frame
        print x.parseFrame(x.getFrame())
