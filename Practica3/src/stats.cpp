#include "stats.h"
#include "filter.h"
#include <list>
#include <utility>

Stats::Stats()
{
    ip = 0;
    noip = 0;
    udp = 0;
    tcp = 0;
    notcpudp = 0;
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

int Stats::parse_packet(const uint8_t *packet, const struct pcap_pkthdr *header)
{
    uint32_t p_eth_type, p_protocol, p_ip_dst, p_ip_src, p_port_dst, p_port_src;
    uint32_t ip_header_size;

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

static int select_bytes_received(endpoint_data& data)
{
	return data.bytes_received;
}

static int select_bytes_sent(endpoint_data& data)
{
	return data.bytes_sent;
}

static int select_packs_sent(endpoint_data& data)
{
	return data.packs_sent;
}

static int select_packs_received(endpoint_data& data)
{
	return data.packs_received;
}

void Stats::print_top_five(std::map<uint32_t, endpoint_data> &map, selector sel, const char* title, int print_ip)
{
	std::list<pair<uint32_t, int> > pairs;
	std::map<uint32_t, endpoint_data>::iterator iter;
	std::list<pair<uint32_t, int> >::iterator p_iter;
	int i = 0;
	char ipstr[20];

	for(iter = map.begin(); iter != map.end(); iter++)
		pairs.push_back(std::make_pair(iter->first, sel(iter->second)));

	pairs.sort(compare_pair);

	printf("%s:\n", title);

	for(p_iter = pairs.begin(); p_iter != pairs.end() && i < 5; p_iter++, i++)
	{
		if(print_ip)
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
	std::map<uint32_t, endpoint_data>::iterator iter;
	int total = ip + noip;

	printf("Paquetes no IP:\t %d (%.2f %%)\n", noip, 100 * (double) noip / total);
	printf("Paquetes IP:\t %d (%.2f %%)\n", ip, 100 * (double) ip / total);
	printf("Paquetes TCP:\t %d (%.2f %%)\n", tcp, 100 * (double) tcp / total);
	printf("Paquetes UDP:\t %d (%.2f %%)\n", udp, 100 * (double) udp / total);
	printf("Paquetes no TCP/UDP:\t %d (%.2f %%)\n", notcpudp, 100 * (double) notcpudp / total);

	printf("\n");

	printf("===== Top 5 IPs =====\n");
	stats_for(ip_map, 1);

	printf("===== Top 5 puertos =====\n");
	stats_for(port_map, 0);

	return 0;
}