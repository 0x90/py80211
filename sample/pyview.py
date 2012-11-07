import sys
import time
import os

# update the system path to look for Tool80211 one directory up
sys.path.append('../')
import Tool80211

if __name__ == "__main__":
    try:
        """
        create an instance and create vap and monitor
        mode interface
        """
        x = Tool80211.Toolkit80211(sys.argv[1])
        """
        create an instance of Airview
        will only work with one interface for the time being
        """
        y = x.Airview(x.moniface)
        # start airview parsing and channel hopping
        y.start()
        ppmac = x.RandomBits.pformatMac
        while True:
            """
            run loop every 2 seconds to give us a chance to get new data
            this is a long time but not terrible
            """
            time.sleep(2)
            # clear the screen on every loop
            os.system("clear")
            """
            grab a local copy from airview thread
            This allows us to work with snapshots and not
            have to deal with thread lock issues
            """
            lbss = y.bss
            # print the current sniffing channel to the screen
            print "Channel %i" %(y.channel)
            # print out the access points and their essids
            print "Access point"
            for bssid in lbss.keys():
                apbssid = ppmac(bssid)
                print "%s %s" %(apbssid, lbss[bssid])
            """
            Print out the clients and anything they are assoicated to
            as well as probes to the screen
            """
            print "\nClients"
            # get local copies from airview thread
            # local clients
            lclient = y.clients
            # local clientsExtra
            eclient = y.clientsExtra
            # for each client show its data
            for client in lclient.keys():
                pclient = ppmac(client)
                # remove any wired devices we say via wired broadcasts
                if client in eclient.keys():
                    if eclient[client]['wired'] == True:
                        continue
                plclient = lclient[client]
                if plclient != "Not Assoicated":
                    plclient = ppmac(plclient)
                probes = y.getProbes(client)
                # print out a probe list, otherwise just print the client and its assoication
                if probes != None:
                    pass
                    print pclient, plclient, ','.join(probes)
                else:
                    pass
                    print pclient, plclient
    except KeyboardInterrupt:
        print "\nbye"
        x.exit()
        sys.exit(0)


