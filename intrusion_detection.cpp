#include <pcap.h>
#include <iostream>
#include <unordered_map>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <ctime>
#include <iomanip>

using namespace std;

struct ConnectionInfo {
    int packetCount;
    time_t firstSeen;
};

unordered_map<string, ConnectionInfo> connectionMap;
const int PACKET_THRESHOLD = 10;
const int TIME_WINDOW = 5; // 5 seconds

void detectIntrusion(const string& key, time_t timestamp) {
    if (connectionMap.find(key) == connectionMap.end()) {
        connectionMap[key] = {1, timestamp};
    } else {
        connectionMap[key].packetCount++;
        if (difftime(timestamp, connectionMap[key].firstSeen) <= TIME_WINDOW && connectionMap[key].packetCount > PACKET_THRESHOLD) {
            cout << "\033[1;31m[ALERT]\033[0m Possible intrusion detected from " << key << " at "
                 << put_time(localtime(&timestamp), "%Y-%m-%d %H:%M:%S") << endl;
        }
    }
}

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *ethHeader = (struct ether_header *)packet;
    
    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
        struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
        string srcIP = inet_ntoa(ipHeader->ip_src);
        string dstIP = inet_ntoa(ipHeader->ip_dst);
        time_t timestamp = pkthdr->ts.tv_sec;

        cout << "[INFO] Packet captured - Source: " << srcIP << " | Destination: " << dstIP << endl;
        detectIntrusion(srcIP, timestamp);
        detectIntrusion(dstIP, timestamp);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        return 1;
    }
    
    cout << "Available network interfaces:" << endl;
    int i = 0;
    for (device = alldevs; device; device = device->next) {
        cout << ++i << ". " << device->name;
        if (device->description) {
            cout << " - " << device->description;
        }
        cout << endl;
    }
    
    cout << "Enter the interface number: ";
    int ifaceNum;
    cin >> ifaceNum;
    
    device = alldevs;
    for (i = 1; i < ifaceNum && device; device = device->next, i++);
    if (!device) {
        cerr << "Invalid selection." << endl;
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "Could not open device: " << errbuf << endl;
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    cout << "\033[1;32m[START]\033[0m Monitoring network on " << device->name << "..." << endl;
    pcap_loop(handle, 0, packetHandler, nullptr);
    
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
