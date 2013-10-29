#include <map>
#include "packet_parser.h"

using namespace std;

typedef struct {
	int bytes_received;
	int bytes_sent;
	int packs_received;
	int packs_sent;
} endpoint_data;

typedef int (*selector)(endpoint_data&);

class Stats {
private:
	int ip, noip, tcp, udp, notcpudp;
	map<uint32_t, endpoint_data> ip_map;
	map<uint32_t, endpoint_data> port_map;
	int total_size;
	int total_packets;
	long timestart, timeend;
	int accepted_packets;

	endpoint_data& get_or_create(map<uint32_t, endpoint_data> &map, uint32_t key);
	void print_top_five(std::map<uint32_t, endpoint_data> &map, selector sel, const char* title, int print_ip);
	void stats_for(std::map<uint32_t, endpoint_data> &map, int print_ip);
public:
	Stats();
	void start();
	void stop();
	int parse_packet(const uint8_t* packet, const struct pcap_pkthdr* header, short accepted);
	int print_stats();
};