"""Custom topology example
Two directly connected switches plus a host for each switch:
   host --- switch --- switch --- host
Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')


        # Add links
        # red link 1Gb/s 5% packet loss
        self.addLink( s1, s2, bw=1000, loss=5)
        self.addLink( s2, s3, bw=1000, loss=5)
        self.addLink( s3, s4, bw=1000, loss=5)
        # blue link 100Mb/s
        self.addLink( h1, s1, bw=100)
        self.addLink( h2, s1, bw=100)
        self.addLink( h3, s2, bw=100)
        self.addLink( h4, s3, bw=100)
        self.addLink( h5, s4, bw=100)
        self.addLink( h6, s4, bw=100)


        # self.addLink( leftHost, leftSwitch )
        # self.addLink( leftSwitch, rightSwitch )
        # self.addLink( rightSwitch, rightHost )


topos = { 'mytopo': ( lambda: MyTopo() ) }