#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <cstdlib>
// #include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
// #include <arpa/inet.h>

// #define SENDFAKEARP

// get the local MAC address
bool get_local_mac(const char* if_name, uint8_t* mac_addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0); // create a socket
    if (fd < 0) {
        perror("Socket error");
        return false;
    }

    struct ifreq ifr;
    size_t if_name_len = strlen(if_name);
    if (if_name_len < sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name, if_name, if_name_len); // interface name
        ifr.ifr_name[if_name_len] = 0;
    } else {
        std::cerr << "Interface name is too long." << std::endl;
        close(fd);
        return false;
    }

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) { // get the MAC address
        perror("IOCTL error");
        close(fd);
        return false;
    }

    close(fd);

    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6); 
    return true;
}

// get local IP address
bool get_local_ip(const char* if_name, char* ip_addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0); // create a socket
    if (fd < 0) {
        perror("Socket error");
        return false;
    }

    struct ifreq ifr;
    size_t if_name_len = strlen(if_name);
    if (if_name_len < sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name, if_name, if_name_len); // interface name
        ifr.ifr_name[if_name_len] = 0;
    } else {
        std::cerr << "Interface name is too long." << std::endl;
        close(fd);
        return false;
    }

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) { // get the IP address
        perror("IOCTL error");
        close(fd);
        return false;
    }

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    strcpy(ip_addr, inet_ntoa(ipaddr->sin_addr));

    close(fd);
    return true;
}

// send an ARP request
bool send_arp_request(pcap_t* handle, const uint8_t* local_mac, const char* local_ip, const char* target_ip) {
    struct ether_header eth_hdr;
    struct ether_arp arp_req;

    // ethernet header fields
    memset(eth_hdr.ether_dhost, 0xff, sizeof(eth_hdr.ether_dhost)); // broadcast
    memcpy(eth_hdr.ether_shost, local_mac, sizeof(eth_hdr.ether_shost)); // sender MAC address
    eth_hdr.ether_type = htons(ETHERTYPE_ARP); // Ethernet type

    // set the ARP request fields
    arp_req.arp_hrd = htons(ARPHRD_ETHER); // hardware type
    arp_req.arp_pro = htons(ETH_P_IP); // protocol type
    arp_req.arp_hln = ETHER_ADDR_LEN; // hardware address length
    arp_req.arp_pln = sizeof(in_addr_t); // protocol address length
    arp_req.arp_op = htons(ARPOP_REQUEST); // ARP operation
    memcpy(arp_req.arp_sha, local_mac, sizeof(arp_req.arp_sha)); // sender hardware address
    inet_pton(AF_INET, local_ip, &arp_req.arp_spa); // sender IP address
    memset(arp_req.arp_tha, 0, sizeof(arp_req.arp_tha)); // target hardware address
    inet_pton(AF_INET, target_ip, &arp_req.arp_tpa); // target IP address

    // combine the Ethernet header and ARP request into a packet
    uint8_t packet[sizeof(eth_hdr) + sizeof(arp_req)];
    memcpy(packet, &eth_hdr, sizeof(eth_hdr));
    memcpy(packet + sizeof(eth_hdr), &arp_req, sizeof(arp_req));

    // Send the packet
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        std::cerr << "Error sending ARP request: " << pcap_geterr(handle) << std::endl;
        return false;
    }

    return true;
}

// read the ARP reply and extract the MAC address
bool get_mac_from_arp_reply(pcap_t* handle, const char* target_ip, uint8_t* target_mac) {
    const u_char* packet;
    struct pcap_pkthdr* header;
    struct ether_arp* arp_reply;
    struct in_addr target_addr, sender_addr;

    inet_pton(AF_INET, target_ip, &target_addr);

    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue; // Timeout elapsed
        if (res == -1 || res == -2) break; // Error or EOF

        struct ether_header* eth_hdr = (struct ether_header*)packet;
        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
            arp_reply = (struct ether_arp*)(packet + sizeof(struct ether_header));
            memcpy(&sender_addr, arp_reply->arp_spa, sizeof(sender_addr));

            // // printout some info
            // std::cout << "ARP reply from " << inet_ntoa(sender_addr) << std::endl;
            // std::cout << "Sender MAC address: ";
            // for (int i = 0; i < 6; i++) {
            //     std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)arp_reply->arp_sha[i];
            //     if (i < 5) std::cout << ":";
            // }
            // std::cout << std::endl;

            // ensure this is an ARP reply (2) for the correct target IP
            if (ntohs(arp_reply->arp_op) == ARPOP_REPLY && target_addr.s_addr == sender_addr.s_addr) {
                memcpy(target_mac, arp_reply->arp_sha, sizeof(arp_reply->arp_sha));
                return true;
            }
        }
    }

    return false;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_t* handle;
    uint8_t local_mac[6] = {0};
    char local_ip[INET_ADDRSTRLEN] = {0};
    char target_ip[INET_ADDRSTRLEN];
    uint8_t target_mac[6];

    // get the list of available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    // display the list of available devices
    int num = 0;
    for (pcap_if_t *device = alldevs; device != NULL; device = device->next) {
        printf("%d. %s - ", ++num, device->name);
        if (device->description) {
            printf("%s\n", device->description);
        } else {
            printf("No description available\n");
        }
    }

    // selects the device
    int device_num;
    printf("Enter the number of the device you want to capture packets from: ");
    scanf("%d", &device_num);

    if (device_num < 1 || device_num > num) {
        printf("Invalid device number\n");
        return 1;
    }

    pcap_if_t *device = alldevs;
    for (int i = 0; i < device_num - 1; i++) {
        device = device->next;
    }

    // open the selected device
    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "Couldn't open device " << device->name << ": " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // input the target IP address
    std::cout << "Enter the target IP address: ";
    std::cin >> target_ip;

    #ifdef SENDFAKEARP
    // send fake ARP to get the target MAC address
    strcpy(local_ip, "172.21.192.1");
    memcpy(local_mac, "\x00\x15\x5d\x8c\x94\xea", 6);
    #else
    // get the local MAC and IP address
    if (!get_local_mac(device->name, local_mac) || !get_local_ip(device->name, local_ip)) {
        std::cerr << "Couldn't get local MAC or IP address." << std::endl; 
        pcap_close(handle);
        return 1;
    }

    // local MAC and IP address
    std::cout << "Local IP address: " << local_ip << std::endl;
    std::cout << "Local MAC address: ";
    for (int i = 0; i < 6; i++) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)local_mac[i];
        if (i < 5) std::cout << ":";
    }
    std::cout << std::endl;
    #endif

    pcap_freealldevs(alldevs);

    // send the ARP request
    if (!send_arp_request(handle, local_mac, local_ip, target_ip)) {
        pcap_close(handle);
        return 1;
    }

    std::cout << "===================================" << std::endl;
    // Get the target MAC address from the ARP reply
    if (get_mac_from_arp_reply(handle, target_ip, target_mac)) {
        std::cout << "====>IP address: " << target_ip << "\n====>MAC address: ";
        for (int i = 0; i < 6; i++) {
            std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)target_mac[i];
            if (i < 5) std::cout << ":";
        }
        std::cout << std::endl;
    } else {
        std::cerr << "Could not get MAC address for IP " << target_ip << std::endl;
    }

    pcap_close(handle);
    return 0;
}