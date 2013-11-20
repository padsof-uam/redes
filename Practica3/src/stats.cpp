#include "stats.h"
#include "filter.h"
#include <list>
#include <utility>
#include <errno.h>
#include <time.h>


Stats::Stats(filter_params *params)
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
    fparams = params;
    first_packet_time = -1;
    last_packet_time = 0;
    last_tps_second = 0;
    current_throughput = 0;

    is_filtering_ports = params->port_dst != 0 && params->port_src != 0;

    arrival_times = fopen(ARRIVAL_TIMES_FILE, "w");
    f_sizes = fopen(SIZES_FILE, "w");
    f_throughput = fopen(THROUGHPUT_FILE, "w");

    if (!f_sizes)
        fprintf(stderr, "Error: fopen: %s. File: %s, %s %d.\n", strerror(errno), SIZES_FILE, __FILE__, __LINE__);
    if (!arrival_times)
        fprintf(stderr, "Error: fopen: %s. File: %s, %s %d.\n", strerror(errno), ARRIVAL_TIMES_FILE, __FILE__, __LINE__);
    if (!f_throughput)
        fprintf(stderr, "Error: fopen: %s. File: %s, %s %d.\n", strerror(errno), THROUGHPUT_FILE, __FILE__, __LINE__);
}

Stats::~Stats()
{
    if (arrival_times)
        fclose(arrival_times);

    if (f_sizes)
        fclose(f_sizes);

    if(f_throughput)
        fclose(f_throughput);
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

static double _get_ms_time(const struct timeval &ts)
{
    return (double) ts.tv_sec * 1000 + (double) ts.tv_usec / 1000;
}

void Stats::mark_port_arrival(const struct pcap_pkthdr *header, const uint16_t port_src, const uint16_t port_dst, const double prev_packet_time)
{
    if (arrival_times && is_filtering_ports)
    {
        double arrival_time;

        if (prev_packet_time == 0)
            arrival_time = 0;
        else
            arrival_time = _get_ms_time(header->ts) - prev_packet_time;
             
        fprintf(arrival_times, "%f\n", arrival_time);
    }
    else
    {
        map<port_pair, double>::iterator iter;
        port_pair pair = { port_src, port_dst };
        iter = port_arrivals.find(pair);

        if (iter == port_arrivals.end())
            port_arrivals[pair] = header->len;
        else
            iter->second += header->len;
    }
}

int Stats::parse_packet(const uint8_t *packet, const struct pcap_pkthdr *header, short accepted)
{
    uint32_t p_eth_type, p_protocol, p_ip_dst, p_ip_src, p_port_dst, p_port_src;
    uint32_t ip_header_size;
    double packet_time;
    double previous_packet_time = last_packet_time;
    int vlan_offset = 0;

    total_packets++;
    accepted_packets += accepted;

    if (accepted)
        total_size += header->len;

    if (f_sizes)
        fprintf(f_sizes, "%d\n", header->len);

    packet_time = _get_ms_time(header->ts);

    if (first_packet_time < 0)
        first_packet_time = packet_time;

    last_packet_time = packet_time;

    save_throughput_per_sec((packet_time - first_packet_time) / 1000, header->len);

    extract(packet, ETH_ALEN * 2, 1, 16, &p_eth_type);
    correct_for_vlan(packet, &p_eth_type, &vlan_offset);

    if (p_eth_type != ETH_TYPE_IP)
    {
        noip++;
        return 0;
    }

    packet += ETH_ALEN * 2 + ETH_TLEN + vlan_offset; // ETH header end.

    ip++;

    extract_offset(packet, 0, 4, 1, 4, &ip_header_size);
    extract(packet, 9, 1, 8, &p_protocol);
    extract(packet, 12, 1, 32, &p_ip_src);
    extract(packet, 16, 1, 32, &p_ip_dst);

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
        save_sentreceived_data(header->len, 0, 0, p_ip_src, p_ip_dst);
        return 0;
    }

    extract(packet, 0, 1, 16, &p_port_src);
    extract(packet, 2, 1, 16, &p_port_dst);

    save_sentreceived_data(header->len, p_port_src, p_port_dst, p_ip_src, p_ip_dst);

    if (accepted)
        mark_port_arrival(header, p_port_src, p_port_dst, previous_packet_time);

    return 0;
}
void Stats::save_throughput_per_sec(int packet_time_sec, int len)
{
    printf("Packet len %d arrived at second %d\n", len, packet_time_sec);
    while (packet_time_sec > last_tps_second)
    {
        fprintf(f_throughput, "%d\n", current_throughput);
        current_throughput = 0;
        last_tps_second++;
    }

    current_throughput += len;
}

void Stats::save_sentreceived_data(int len, uint32_t port_src, uint32_t port_dst, uint32_t ip_src, uint32_t ip_dst)
{
    endpoint_data &ip_src_data = get_or_create(ip_map, ip_src);

    ip_src_data.bytes_sent += len;
    ip_src_data.packs_sent++;

    endpoint_data &ip_dst_data = get_or_create(ip_map, ip_dst);

    ip_dst_data.bytes_received += len;
    ip_dst_data.packs_received++;

    if (port_src != 0 && port_dst != 0)
    {
        endpoint_data &port_src_data = get_or_create(port_map, port_src);

        port_src_data.bytes_sent += len;
        port_src_data.packs_sent++;

        endpoint_data &port_dst_data = get_or_create(port_map, port_dst);

        port_dst_data.bytes_received += len;
        port_dst_data.packs_received++;
    }
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
    double duration = (double)(last_packet_time - first_packet_time) / 1000;
    double packs_per_sec = total_packets / duration;
    double throughput = total_size / duration;

    printf("Estadísticas:\n");
    printf("\tDuración:\t %.3f s\n", duration);
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

    if (!is_filtering_ports)
        process_port_arrivals(duration);

    return 0;
}

void Stats::process_port_arrivals(double duration)
{
    if (!arrival_times)
        return;

    map<port_pair, double>::iterator iter;

    for (iter = port_arrivals.begin(); iter != port_arrivals.end(); iter++)
        fprintf(arrival_times, "%d-%d\t %.5f\n", iter->first.p_src, iter->first.p_dst, iter->second / duration);
}
