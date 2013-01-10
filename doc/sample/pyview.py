import sys
import time
import os
import optparse
from py80211 import tools

print "Py80211 Sample Application"
parser = optparse.OptionParser("%prog options [-i]")
parser.add_option( "-i", "--interface", dest="card", nargs=1,
    help="Interface to sniff and inject from")
parser.add_option("-c", "--channel", dest="channels", default=False, nargs=120, action="append",
    help="Channels to sniff from")
parser.add_option("-b", "--bssid", dest="bssid", default=False,
    help="Show only clients on this bssid")

#check for correct number of arguments provided
if len(sys.argv) < 3:
    parser.print_help()
    sys.exit(0)
else:
    (options, args) = parser.parse_args()

try:
    """
       create an instance and create vap and monitor
        ode interface
    """
    airmonitor = tools.Airview(options.card, options.channels)
    if options.bssid:
        channel = airmonitor.find_channel_by_bssid(options.bssid)
        airmonitor = tools.Airview(options.card, channel)
    airmonitor.start()
    ppmac = airmonitor.pformatMac

    while True:
        """
           run loop every 1 seconds to give us a chance to get new data
            his is a long time but not terrible
        """
        time.sleep(1)
        os.system("clear")
        """
            grab a local copy from airview thread
            This allows us to work with snapshots and not
            have to deal with thread lock issues
        """
        lbss = airmonitor.bss
        # print the current sniffing channel to the screen
        print "Channel %i" %(airmonitor.channel)
        # print out the access points and their essids
        print "Access point"
        print lbss.keys()
        for bssid in lbss.keys():
            apbssid = ppmac(bssid)
            # we don't get as many mangled packets now, but every so often...
            # we don't do mangle detection yet, so for now we deal.
            essid = lbss[bssid]
            if airmonitor.verifySSID(bssid, essid) is False:
                # bad essids, skip printing
                continue
            else:
                print ("%s %s" %(apbssid, essid)).encode("utf-8")

        """
           Print out the clients and anything they are assoicated to
           as well as probes to the screen
        """
        print "\nClients"
        # get local copies from airview thread
        # local clients
        lclient = airmonitor.clients
        # local clientsExtra
        eclient = airmonitor.clients_extra
        # for each client show its data
        for client in lclient.keys():
            if options.bssid and lclient[client] != options.bssid:
                continue
            pclient = ppmac(client)
            # remove any wired devices we say via wired broadcasts
            if client in eclient.keys():
                if eclient[client]['wired'] == True:
                    continue
            plclient = lclient[client]
            if plclient != "Not Associated":
                plclient = ppmac(plclient)
            probes = airmonitor.getProbes(client)
            # print out a probe list, otherwise just print the client and its assoication
            if probes != None:
                pass
                print pclient, plclient, ','.join(probes)
            else:
                pass
                print pclient, plclient
except KeyboardInterrupt:
    print "\nbye\n"
    airmonitor.kill()
    sys.exit(0)
