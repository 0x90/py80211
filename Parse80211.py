__author__ = "TheX1le, Crypt0s, radiotap parsing orginally by Scott Raynel in the radiotap.py project"

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
        self.tagdata = {"unparsed":[], "htPresent": False}  # dict to return parsed tags
        self.parser = {
            "\x00": self.ssid,      # ssid IE tag parser
            "\x01": self.rates,     # data rates tag parser
            "\x03": self.channel,   # channel tag parser
            "\x30": self.rsn,       # rsn tag parser
            "\x32": self.exrates,   # extended rates tag parser
            "\xDD": self.vendor221, # 221 vendor tag parser
            "\x3D": self.htinfo,    # HT information tag checker
            "\x07": self.country,   # Country Code Parser
            "\x85": self.ccxOne,    # Cisco CCX v1 Parser
            }
    
    def ccxOne(self, rbytes):
        """
        Parse ap hostname and number of clients
        from cisco CCX v1 IE tag
        """
        self.tagdata["APhostname"] = str(rbytes[12:-4])
        self.tagdata["ClientNum"] = ord(rbytes[-1])

    def country(self, rbytes):
        """
        Return Country Code from beacon packet
        """
        self.tagdata["country"] = str(rbytes[2:4])

    def htinfo(self, rbytes):
        """
        Check for existance of HT tag to denote support
        For 802.11N Mark its existance true for mgt frame
        save the reported HT primary channel
        """
        self.tagdata["htPresent"] = True
        # reported primary channel
        self.tagdata["htPriCH"] = ord(rbytes[2])

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
            0 : "None",
            1 : "802.1x or PMK",
            2 : "PSK",
            }
        try:
            # remove IE tag, len and Microsoft OUI
            packetLen = ord(rbytes[1])
            vendor_OUI = rbytes[2:5]
            vendor_OUI_type = ord(rbytes[5])
            vendor_OUI_stype = ord(rbytes[6])
            if vendor_OUI == "\x00\x50\xf2":
                # Microsoft
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
            if vendor_OUI == "\x00\x0b\x86":
                # aruba
                if vendor_OUI_type == 1:
                   if vendor_OUI_stype == 3:
                        # aruba does ap hostname this way
                        self.tagdata["APhostname"] = rbytes[7:]
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
        offsets = {}
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
            exrates.append((ord(exrate) & 127) * 0.5)
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
            rates.append((ord(rate) & 127) * 0.5)
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
            0 : "None",
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

class Parse80211:
    """
    Class file for parsing
    several common 802.11 frames
    """
    def __init__(self, rth, headsize):
        """
        start the parser
        rth = Boolean if there is Radio tap header
        headersize = actual header size
        """
        self.rth = rth
        self.headsize = headsize
        # this gets set to True if were seeing mangled packets
        self.mangled = False
        # number of mangled packets seen
        self.mangledcount = 0
        # create ie tag parser
        self.IE = IeTag80211()
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
        
        self.freqLookup = {
            2412 : 1, 2417 : 2, 2422 : 3,
            2427 : 4, 2432 : 5, 2437 : 6,
            2442 : 7, 2447 : 8, 2452 : 9,
            2457 : 10, 2462 : 11, 2467 : 12,
            2472 : 13, 2484 : 14, 5170 : 34, 
            5180 : 36, 5190 : 38, 5200 : 40, 
            5210 : 42, 5220 : 44, 5230 : 46, 
            5240 : 48, 5260 : 52, 5280 : 56, 
            5300 : 58, 5320 : 60, 5500 : 100, 
            5520 : 104, 5540 : 108, 5560 : 112, 
            5580 : 116, 5600 : 120, 5620 : 120, 
            5620 : 124, 5640 : 128, 5660 : 132, 
            5680 : 136, 5700 : 140, 5745 : 149, 
            5765 : 153, 5785 : 157, 5805 : 161, 
            5825 : 165
            }
    
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
                rformat += "b"
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

    def parseFrame(self, frame, ARP=False):
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
            self.rtapData = self.parseRtap(data[:self.rt])
        except Exception:
            # bad rtap header, pass for now
            self.rtapData = -1
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
                    if self.rtapData == -1:
                        # truncated rtap, make rssi None
                        parsedFrame['rssi'] = None
                    else:
                        parsedFrame['rssi'] = self.rtapData[5]
                    parsedFrame["raw"] = data
                if ARP is True:
                    if stype == '\x08':
                        # data packet, check for arp
                        pass
                        
                return parsedFrame
            else:
                # we dont have a parser for the packet
                return None
        else:
            # we dont have a parser for the packet
            return None
    
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
            channel = 0
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
            # BUG HERE No channel in 5ghz probe
            # REMOVE THISs
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
            try:
                if (struct.unpack('h', data[34:36])[0] & 16):
                    beaconWepBit = True
                self.IE.parseIE(data[36:])
            except:
                # mangled packet
                self.mangled = True
                self.mangledcount += 1
                return -1
            if "ssid" not in self.IE.tagdata.keys():
                self.mangled = True
                self.mangledcount += 1
                return -1
            else:
                essid = self.IE.tagdata["ssid"]
            channel = 0
            freq = 0
            # pull channel from radio tap
            # may not be 100% correct
            if self.rtapData == -1:
                #mangled packet
                self.mangled = True
                self.mangledcount += 1
            else:
                freq = self.rtapData[3] & 0xFFFF
            if "channel" not in self.IE.tagdata.keys():
                if "htPriCH" in self.IE.tagdata.keys():
                    # get channel from HT ie tag
                    channel = self.IE.tagdata["htPriCH"]
                else:
                    channel = self.freqLookup[freq]
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

