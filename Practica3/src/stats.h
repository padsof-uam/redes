#include <map>
#include <cstdio>
#include "packet_parser.h"
#include "filter.h"

using namespace std;

#define ARRIVAL_TIMES_FILE "arrivals"
#define SIZES_FILE "sizes"

typedef struct
{
    int bytes_received;
    int bytes_sent;
    int packs_received;
    int packs_sent;
} endpoint_data;

typedef struct
{
    uint16_t p_src;
    uint16_t p_dst;
} port_pair;

struct paircomp
{
    bool operator()(const port_pair &a, const port_pair &b) const
    {
        return ((a.p_dst << 2) + a.p_src) < ((b.p_dst << 2) + b.p_src);
    }
};

typedef int (*selector)(endpoint_data &);

class Stats
{
private:
    int ip, noip, tcp, udp, notcpudp;
    map<uint32_t, endpoint_data> ip_map;
    map<uint32_t, endpoint_data> port_map;
    map<port_pair, double, paircomp> port_arrivals;
    int total_size;
    int total_packets;
    long timestart, timeend;
    int accepted_packets;
    FILE *arrival_times;
    FILE *f_sizes;
    filter_params *fparams;
    short is_filtering_ports;
    long first_packet_time;
    long last_packet_time;

    endpoint_data &get_or_create(map<uint32_t, endpoint_data> &map, uint32_t key);
    void print_top_five(std::map<uint32_t, endpoint_data> &map, selector sel, const char *title, int print_ip);
    void stats_for(std::map<uint32_t, endpoint_data> &map, int print_ip);
    void mark_port_arrival(const struct pcap_pkthdr *header, const int port_src, const int port_dst, const long prev_packet_time);
    long get_ms_time(const struct timeval &ts);
    void process_port_arrivals(double duration);
public:
    Stats(filter_params *params);
    ~Stats();
    int parse_packet(const uint8_t *packet, const struct pcap_pkthdr *header, short accepted);
    int print_stats();
};
