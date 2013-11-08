#include "stats.h"
#include "filter.h"
#include <list>
#include <utility>
#include <errno.h>

static long get_us_time()
{
    struct timeval tval;

    gettimeofday(&tval, NULL);

    return tval.tv_sec * 1000 * 1000 + tval.tv_usec;
}

Stats::Stats()
{
    ip = 0;
    noip = 0;
    udp = 0;
    tcp = 0;
    notcpudp = 0;
    accepted_packets = 0;
    total_packets = 0;
    total_size = 0;
    arrival_times = NULL;
    f_sizes = NULL;

    arrival_times = fopen(ARRIVAL_TIMES_FILE, "w");
    f_sizes = fopen(SIZES_FILE, "w");

    if (!f_sizes)
        fprintf(stderr, "Error: fopen: %s. File: %s, %s %d.\n", strerror(errno), SIZES_FILE, __FILE__, __LINE__);
    if (!arrival_times)
        fprintf(stderr, "Error: fopen: %s. File: %s, %s %d.\n", strerror(errno), ARRIVAL_TIMES_FILE, __FILE__, __LINE__);
}

Stats::~Stats()
{
    if (arrival_times)
        fclose(arrival_times);

    if (f_sizes)
        fclose(f_sizes);
}

endpoint_data &Stats::get_or_create(map<uint32_t, endpoint_data> &map, uint32_t key)
{
    std::map<uint32_t, endpoint_data>::iterator it;

    it = map.find(key);

    if (it == map.end())
    {
        endpoint_data data = {0, 0, 0, 0};
        map[key] = data;
    }

    return map[key];
}

int Stats::parse_packet(const uint8_t *packet, const struct pcap_pkthdr *header, short accepted)
{
    uint32_t p_eth_type, p_protocol, p_ip_dst, p_ip_src, p_port_dst, p_port_src;
    uint32_t ip_header_size;

    total_packets++;
    accepted_packets += accepted;

    if (accepted)
        total_size += header->len;

    if(f_sizes)
        fprintf(f_sizes, "%d\n", header->len);

    extract(packet, ETH_ALEN * 2, 1, 16, &p_eth_type);

    packet += ETH_ALEN * 2 + ETH_TLEN; // ETH header end.

    if (p_eth_type != ETH_TYPE_IP)
    {
        noip++;
        return 0;
    }

    ip++;

    extract_offset(packet, 0, 4, 1, 4, &ip_header_size);

    extract(packet, 9, 1, 8, &p_protocol);
    extract(packet, 12, 1, 32, &p_ip_src);
    extract(packet, 16, 1, 32, &p_ip_dst);

    endpoint_data &ip_src_data = get_or_create(ip_map, p_ip_src);

    ip_src_data.bytes_sent += header->len;
    ip_src_data.packs_sent++;

    endpoint_data &ip_dst_data = get_or_create(ip_map, p_ip_dst);

    ip_dst_data.bytes_received += header->len;
    ip_dst_data.packs_received++;

    packet += ip_header_size * 4; // IP header end.

    if (p_protocol == TCP)
    {
        tcp++;
    }
    else if (p_protocol == UDP)
    {
        udp++;
    }
    else
    {
        notcpudp++;
        return 0;
    }

    extract(packet, 0, 1, 16, &p_port_src);
    extract(packet, 2, 1, 16, &p_port_dst);

    endpoint_data &port_src_data = get_or_create(port_map, p_port_src);

    port_src_data.bytes_sent += header->len;
    port_src_data.packs_sent++;

    endpoint_data &port_dst_data = get_or_create(port_map, p_port_dst);

    port_dst_data.bytes_received += header->len;
    port_dst_data.packs_received++;

    return 0;
}

bool compare_pair(std::pair<uint32_t, int> a, std::pair<uint32_t, int> b)
{
    return a.second > b.second;
}

static int select_bytes_received(endpoint_data &data)
{
    return data.bytes_received;
}

static int select_bytes_sent(endpoint_data &data)
{
    return data.bytes_sent;
}

static int select_packs_sent(endpoint_data &data)
{
    return data.packs_sent;
}

static int select_packs_received(endpoint_data &data)
{
    return data.packs_received;
}

void Stats::print_top_five(std::map<uint32_t, endpoint_data> &map, selector sel, const char *title, int print_ip)
{
    std::list<pair<uint32_t, int> > pairs;
    std::map<uint32_t, endpoint_data>::iterator iter;
    std::list<pair<uint32_t, int> >::iterator p_iter;
    int i = 0;
    char ipstr[20];

    for (iter = map.begin(); iter != map.end(); iter++)
        pairs.push_back(std::make_pair(iter->first, sel(iter->second)));

    pairs.sort(compare_pair);

    printf("%s:\n", title);

    for (p_iter = pairs.begin(); p_iter != pairs.end() && i < 5; p_iter++, i++)
    {
        if (print_ip)
        {
            ip_tostr(p_iter->first, ipstr);
            printf("\t%s:   ", ipstr);
        }
        else
        {
            printf("\t%" PRIu32 ":", p_iter->first);
        }

        printf("\t %d\n", p_iter->second);
    }

    printf("\n");
}

void Stats::stats_for(std::map<uint32_t, endpoint_data> &map, int print_ip)
{
    print_top_five(map, select_bytes_received, "Bytes recibidos", print_ip);
    print_top_five(map, select_bytes_sent, "Bytes enviados", print_ip);
    print_top_five(map, select_packs_received, "Paquetes recibidos", print_ip);
    print_top_five(map, select_packs_sent, "Paquetes enviados", print_ip);
}

int Stats::print_stats()
{
    double filtered_percentage = 100 * (double) accepted_packets / total_packets;
    double duration = (double)(timeend - timestart) / 1000000;
    double packs_per_sec = total_packets / duration;
    double throughput = total_size / duration;

    printf("Estadísticas:\n");
    printf("\tDuración:\t %.3f segundos\n", duration);
    printf("\tCapturados:\t %d (%.2f paquetes/s)\n", total_packets, packs_per_sec);
    printf("\tDescartados:\t %d (%.2f %%)\n", total_packets - accepted_packets, 100 - filtered_percentage);
    printf("\tAceptados:\t %d (%.2f %%)\n", accepted_packets, filtered_percentage);
    printf("\tThroughput:\t %.2f Bps\n", throughput);
    printf("\n");
    printf("\tPaquetes no IP:\t\t %d (%.2f %%)\n", noip, 100 * (double) noip / total_packets);
    printf("\tPaquetes IP:\t\t %d (%.2f %%)\n", ip, 100 * (double) ip / total_packets);
    printf("\tPaquetes TCP:\t\t %d (%.2f %%)\n", tcp, 100 * (double) tcp / total_packets);
    printf("\tPaquetes UDP:\t\t %d (%.2f %%)\n", udp, 100 * (double) udp / total_packets);
    printf("\tPaquetes no TCP/UDP:\t %d (%.2f %%)\n", notcpudp, 100 * (double) notcpudp / total_packets);
    printf("\n");

    printf("===== Top 5 IPs =====\n");
    stats_for(ip_map, 1);

    printf("===== Top 5 puertos =====\n");
    stats_for(port_map, 0);

    return 0;
}

void Stats::start()
{
    timestart = get_us_time();
    last_time_received = timestart;
}

void Stats::stop()
{
    timeend = get_us_time();
}

void Stats::mark_arrival(const int port_dst, const int port_src)
{
    long current;

    if (port_dst == 0 || port_src == 0)
        return;

    current = get_us_time();

    if(arrival_times)
        fprintf(arrival_times, "%ld\n", current - last_time_received);

    last_time_received = current;
}