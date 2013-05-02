import sys
import time
import os
import optparse
# update the system path to look for Tool80211 one directory up
import pdb
try:
    import Tool80211
except ImportError:
    # Tool80211 not installed
    # assuming were running out of source directory
    sys.path.append('../')
    try:
        import Tool80211
    except ImportError, e:
        print e
        sys.exit(-1)
    

if __name__ == "__main__":
    print "Py80211 Sample Application"
    parser = optparse.OptionParser("%prog options [-i]")
    parser.add_option("-i", "--interface", dest="card", nargs=1,
        help="Interface to sniff and inject from")
    
    #check for correct number of arguments provided
    if len(sys.argv) < 3:
        parser.print_help()
        print "Calling Example"
        print "python pyview.py -i wlan0"
        sys.exit(0)
    else:
        (options, args) = parser.parse_args()
    try:
        """
        create an instance and create vap and monitor
        mode interface
        """
        airmonitor = Tool80211.Airview(options.card)
        airmonitor.start()
        ppmac = airmonitor.pformatMac
        while True:
            """
            run loop every 2 seconds to give us a chance to get new data
            this is a long time but not terrible
            """
            time.sleep(1)
            # clear the screen on every loop
            os.system("clear")
            """
            grab a local copy from airview thread
            This allows us to work with snapshots and not
            have to deal with thread lock issues
            """
            bss = airmonitor.apObjects 
            # print the current sniffing channel to the screen
            print "Channel %i" %(airmonitor.channel)
            # print out the access points and their essids
            print "Access point"
            for bssid in bss.keys():
                apbssid = ppmac(bssid)
                essid = bss[bssid].essid
                enc = bss[bssid].encryption
                auth = bss[bssid].auth
                channel = bss[bssid].channel
                cipher = bss[bssid].cipher
                print ("%s %s %s %s %s %s" %(apbssid, essid, enc, cipher, auth, channel)).encode("utf-8")

            """
            Print out the clients and anything they are assoicated to
            as well as probes to the screen
            """
            print "\nClients"
            # get local copies from airview thread
            # local clients
            clients = airmonitor.clientObjects
            # for each client show its data
            for mac in clients.keys():
                # pretty up the mac
                prettymac = ppmac(mac)
                # remove any wired devices we see via wired broadcasts
                if clients[mac].wired is True:
                    continue
                if clients[mac].assoicated is True:
                    assoicatedState = ppmac(clients[mac].bssid)
                else:
                    assoicatedState = clients[mac].bssid
                probes = clients[mac].probes
                # print out a probe list, otherwise just print the client and its assoication
                if probes != []:
                    print prettymac, assoicatedState, ','.join(probes)
                else:
                    print prettymac, assoicatedState
    except KeyboardInterrupt:
        print "\nbye\n"
        airmonitor.kill()
        sys.exit(0)


