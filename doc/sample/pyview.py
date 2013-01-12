import sys
import time
import os
import csv
import optparse
from py80211 import tools

print "Py80211 Sample Application"
parser = optparse.OptionParser("%prog options [-i]")
parser.add_option( "-i", "--interface", dest="card", nargs=1,
    help="Interface to sniff and inject from")
parser.add_option("-c", "--channel", dest="channels",
    default=[], action="append",
    help="Channels to sniff from")
parser.add_option("-b", "--bssid", dest="bssid", default=False,
    help="Show only clients on this bssid")
parser.add_option("-s", "--csv", dest="csv", default=False,
    help="Save info in a csv file")

if len(sys.argv) < 3:
    parser.print_help()
    sys.exit(0)
else:
    (options, args) = parser.parse_args()

try:
    airmonitor = tools.Airview(options.card, False, options.channels)
    if options.bssid:
        channel = airmonitor.find_channel_by_bssid(options.bssid)
        airmonitor = tools.Airview(options.card, False, channel)
    airmonitor.start()
    aps = {} # If we want the aps to be persistent (dont dissapear when
    # They're not already there, this goes here. Otherwise inside the while
    # loop

    while True:
        time.sleep(5)
        os.system("clear")
        print "Access points"
        lbss = airmonitor.bss
        for bssid in lbss:
            apbssid = airmonitor.pformatMac(bssid)
            essid = lbss[bssid]
            if airmonitor.verifySSID(bssid, essid) is False:
                continue

            aps[bssid] = {
                'bssid' : apbssid,
                'essid' : essid,
                'clients' : []
            }

        lost_clients = []
        for client in airmonitor.clients:
            if options.bssid and airmonitor.clients[client] != options.bssid:
                continue

            if client in airmonitor.clients_extra and \
                airmonitor.clients_extra[client]['wired'] == True:
                continue

            if airmonitor.clients[client] in aps:
                aps[airmonitor.clients[client]]['clients'].append({
                    'bssid' : client,
                    'probes' : airmonitor.getProbes(client)
                })
            else:
                lost_clients.append(client)
        for ap in aps:
            ap = aps[ap]
            if len(ap['essid']) < 9:
                print ("%s\t\t %s" %(ap['essid'], ap['bssid'])).encode('utf-8')
            else:
                print ("%s\t %s" %(ap['essid'], ap['bssid'])).encode('utf-8')
            for client in ap['clients']:
                if client['probes']:
                    probes = ','.join(client['probes'])
                else:
                    probes = ""
                if len(ap['essid']) < 9:
                    print "\t\t + %s %s" %(
                        airmonitor.pformatMac(client['bssid']),
                        probes
                    )
                else:
                    print "\t + %s %s" %(
                        airmonitor.pformatMac(client['bssid']),
                        probes
                    )
        if options.csv:
            with open(options.csv, 'w') as cap:
                writer = csv.writer(cap)
                for ap in aps:
                    ap = aps[ap]
                    writer.writerow([ap['bssid'], ap['essid']])


except KeyboardInterrupt:
    print "\nbye\n"
    airmonitor.kill()
    sys.exit(0)
