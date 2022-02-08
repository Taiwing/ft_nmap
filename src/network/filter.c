/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   filter.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/18 08:01:16 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/07 21:39:56 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

//IPv4 is filtered at the socket level (ETH_P_IP)
const struct sock_filter	g_bpfcode_ipv4_layer4[] = {
	// Load and compare IPv4 protocol (ip[9])
	{ 0x30,  0,  0, 0x00000009 },
	{ 0x15,  0, 11, 0000000000 },	// protocol TCP | UDP (1)

	// Load and compare IPv4 source address (ip[12])
	{ 0x20,  0,  0, 0x0000000c },
	{ 0x15,  0,  9, 0000000000 },	// ipv4 source address (3)

	// Load and compare IPv4 destination address (ip[16])
	{ 0x20,  0,  0, 0x00000010 },
	{ 0x15,  0,  7, 0000000000 },	// ipv4 destination address (5)

	// Load and compare TCP or UDP source port (ip[20])
	{ 0x28,  0,  0, 0x00000014 },
	{ 0x35,  0,  5, 0000000000 },	// smallest source port (7)
	{ 0x25,  4,  0, 0000000000 },	// biggest source port (8)

	// Load and compare TCP or UDP destination port (ip[22])
	{ 0x28,  0,  0, 0x00000016 },
	{ 0x35,  0,  2, 0000000000 },	// smallest destination port (10)
	{ 0x25,  1,  0, 0000000000 },	// biggest destination port (11)

	// Return Match or Drop
	{ 0x06,  0,  0, RAW_DATA_MAXSIZE },
	{ 0x06,  0,  0, 0000000000 },
};

const struct sock_filter	g_bpfcode_ipv4_icmp[] = {
	// Load and compare IPv4 protocol (ip[9])
	{ 0x30,  0,  0, 0x00000009 },
	{ 0x15,  0, 13, 0000000000 },	// protocol ICMP (1)

	// Load and compare IPv4 source address (ip[12])
	{ 0x20,  0,  0, 0x0000000c },
	{ 0x15,  0, 11, 0000000000 },	// ipv4 source address (3)

	// Load and compare IPv4 destination address (ip[16])
	{ 0x20,  0,  0, 0x00000010 },
	{ 0x15,  0,  9, 0000000000 },	// ipv4 destination address (5)

	// Load and compare ICMP protocol (ip[37])
	{ 0x30,  0,  0, 0x00000025 },
	{ 0x15,  0,  7, 0000000000 },	// ICMP protocol (7)

	// Load and compare ICMP payload TCP or UDP source port (ip[48])
	{ 0x28,  0,  0, 0x00000030 },
	{ 0x35,  0,  5, 0000000000 },	// smallest source port (9)
	{ 0x25,  4,  0, 0000000000 },	// biggest source port (10)

	// Load and compare ICMP payload TCP or UDP destination port (ip[50])
	{ 0x28,  0,  0, 0x00000032 },
	{ 0x35,  0,  2, 0000000000 },	// smallest destination port (12)
	{ 0x25,  1,  0, 0000000000 },	// biggest destination port (13)

	// Return Match or Drop
	{ 0x06,  0,  0, RAW_DATA_MAXSIZE },
	{ 0x06,  0,  0, 0000000000 },
};

//IPv6 is filtered at the socket level (ETH_P_IPV6)
const struct sock_filter	g_bpfcode_ipv6_layer4[] = {
	// Load and compare IPv6 protocol (ip6[6])
	{ 0x30,  0,  0, 0x00000006 },
	{ 0x15,  0, 71, 0000000000 },	// protocol TCP | UDP (1)

	// Load and compare IPv6 source address (ip6[8]-ip6[23])
	{ 0x30,  0,  0, 0x00000008 },
	{ 0x15,  0, 69, 0000000000 },	// first ipv6 source byte (3)
	{ 0x30,  0,  0, 0x00000009 },
	{ 0x15,  0, 67, 0000000000 },
	{ 0x30,  0,  0, 0x0000000a },
	{ 0x15,  0, 65, 0000000000 },
	{ 0x30,  0,  0, 0x0000000b },
	{ 0x15,  0, 63, 0000000000 },
	{ 0x30,  0,  0, 0x0000000c },
	{ 0x15,  0, 61, 0000000000 },
	{ 0x30,  0,  0, 0x0000000d },
	{ 0x15,  0, 59, 0000000000 },
	{ 0x30,  0,  0, 0x0000000e },
	{ 0x15,  0, 57, 0000000000 },
	{ 0x30,  0,  0, 0x0000000f },
	{ 0x15,  0, 55, 0000000000 },
	{ 0x30,  0,  0, 0x00000010 },
	{ 0x15,  0, 53, 0000000000 },
	{ 0x30,  0,  0, 0x00000011 },
	{ 0x15,  0, 51, 0000000000 },
	{ 0x30,  0,  0, 0x00000012 },
	{ 0x15,  0, 49, 0000000000 },
	{ 0x30,  0,  0, 0x00000013 },
	{ 0x15,  0, 47, 0000000000 },
	{ 0x30,  0,  0, 0x00000014 },
	{ 0x15,  0, 45, 0000000000 },
	{ 0x30,  0,  0, 0x00000015 },
	{ 0x15,  0, 43, 0000000000 },
	{ 0x30,  0,  0, 0x00000016 },
	{ 0x15,  0, 41, 0000000000 },
	{ 0x30,  0,  0, 0x00000017 },
	{ 0x15,  0, 39, 0000000000 },	// last ipv6 source byte (33)

	// Load and compare IPv6 destination address (ip6[24]-ip6[39])
	{ 0x30,  0,  0, 0x00000018 },
	{ 0x15,  0, 37, 0000000000 },	// first ipv6 destination byte (35)
	{ 0x30,  0,  0, 0x00000019 },
	{ 0x15,  0, 35, 0000000000 },
	{ 0x30,  0,  0, 0x0000001a },
	{ 0x15,  0, 33, 0000000000 },
	{ 0x30,  0,  0, 0x0000001b },
	{ 0x15,  0, 31, 0000000000 },
	{ 0x30,  0,  0, 0x0000001c },
	{ 0x15,  0, 29, 0000000000 },
	{ 0x30,  0,  0, 0x0000001d },
	{ 0x15,  0, 27, 0000000000 },
	{ 0x30,  0,  0, 0x0000001e },
	{ 0x15,  0, 25, 0000000000 },
	{ 0x30,  0,  0, 0x0000001f },
	{ 0x15,  0, 23, 0000000000 },
	{ 0x30,  0,  0, 0x00000020 },
	{ 0x15,  0, 21, 0000000000 },
	{ 0x30,  0,  0, 0x00000021 },
	{ 0x15,  0, 19, 0000000000 },
	{ 0x30,  0,  0, 0x00000022 },
	{ 0x15,  0, 17, 0000000000 },
	{ 0x30,  0,  0, 0x00000023 },
	{ 0x15,  0, 15, 0000000000 },
	{ 0x30,  0,  0, 0x00000024 },
	{ 0x15,  0, 13, 0000000000 },
	{ 0x30,  0,  0, 0x00000025 },
	{ 0x15,  0, 11, 0000000000 },
	{ 0x30,  0,  0, 0x00000026 },
	{ 0x15,  0,  9, 0000000000 },
	{ 0x30,  0,  0, 0x00000027 },
	{ 0x15,  0,  7, 0000000000 },	// last ipv6 destination byte (65)

	// Load and compare TCP or UDP source port (ip6[40])
	{ 0x28,  0,  0, 0x00000028 },
	{ 0x35,  0,  5, 0000000000 },	// smallest source port (67)
	{ 0x25,  4,  0, 0000000000 },	// biggest source port (68)

	// Load and compare TCP or UDP destination port (ip6[42])
	{ 0x28,  0,  0, 0x0000002a },
	{ 0x35,  0,  2, 0000000000 },	// smallest destination port (70)
	{ 0x25,  1,  0, 0000000000 },	// biggest destination port (71)

	// Return Match or Drop
	{ 0x06,  0,  0, RAW_DATA_MAXSIZE },
	{ 0x06,  0,  0, 0000000000 },
};

const struct sock_filter	g_bpfcode_ipv6_icmp[] = {
	// Load and compare IPv6 protocol (ip6[6])
	{ 0x30,  0,  0, 0x00000006 },
	{ 0x15,  0, 73, 0000000000 },	// protocol ICMP6 (1)

	// Load and compare IPv6 source address (ip6[8]-ip6[23])
	{ 0x30,  0,  0, 0x00000008 },
	{ 0x15,  0, 71, 0000000000 },	// first ipv6 source byte (3)
	{ 0x30,  0,  0, 0x00000009 },
	{ 0x15,  0, 69, 0000000000 },
	{ 0x30,  0,  0, 0x0000000a },
	{ 0x15,  0, 67, 0000000000 },
	{ 0x30,  0,  0, 0x0000000b },
	{ 0x15,  0, 65, 0000000000 },
	{ 0x30,  0,  0, 0x0000000c },
	{ 0x15,  0, 63, 0000000000 },
	{ 0x30,  0,  0, 0x0000000d },
	{ 0x15,  0, 61, 0000000000 },
	{ 0x30,  0,  0, 0x0000000e },
	{ 0x15,  0, 59, 0000000000 },
	{ 0x30,  0,  0, 0x0000000f },
	{ 0x15,  0, 57, 0000000000 },
	{ 0x30,  0,  0, 0x00000010 },
	{ 0x15,  0, 55, 0000000000 },
	{ 0x30,  0,  0, 0x00000011 },
	{ 0x15,  0, 53, 0000000000 },
	{ 0x30,  0,  0, 0x00000012 },
	{ 0x15,  0, 51, 0000000000 },
	{ 0x30,  0,  0, 0x00000013 },
	{ 0x15,  0, 49, 0000000000 },
	{ 0x30,  0,  0, 0x00000014 },
	{ 0x15,  0, 47, 0000000000 },
	{ 0x30,  0,  0, 0x00000015 },
	{ 0x15,  0, 45, 0000000000 },
	{ 0x30,  0,  0, 0x00000016 },
	{ 0x15,  0, 43, 0000000000 },
	{ 0x30,  0,  0, 0x00000017 },
	{ 0x15,  0, 41, 0000000000 },	// last ipv6 source byte (33)

	// Load and compare IPv6 destination address (ip6[24]-ip6[39])
	{ 0x30,  0,  0, 0x00000018 },
	{ 0x15,  0, 39, 0000000000 },	// first ipv6 destination byte (35)
	{ 0x30,  0,  0, 0x00000019 },
	{ 0x15,  0, 37, 0000000000 },
	{ 0x30,  0,  0, 0x0000001a },
	{ 0x15,  0, 35, 0000000000 },
	{ 0x30,  0,  0, 0x0000001b },
	{ 0x15,  0, 33, 0000000000 },
	{ 0x30,  0,  0, 0x0000001c },
	{ 0x15,  0, 31, 0000000000 },
	{ 0x30,  0,  0, 0x0000001d },
	{ 0x15,  0, 29, 0000000000 },
	{ 0x30,  0,  0, 0x0000001e },
	{ 0x15,  0, 27, 0000000000 },
	{ 0x30,  0,  0, 0x0000001f },
	{ 0x15,  0, 25, 0000000000 },
	{ 0x30,  0,  0, 0x00000020 },
	{ 0x15,  0, 23, 0000000000 },
	{ 0x30,  0,  0, 0x00000021 },
	{ 0x15,  0, 21, 0000000000 },
	{ 0x30,  0,  0, 0x00000022 },
	{ 0x15,  0, 19, 0000000000 },
	{ 0x30,  0,  0, 0x00000023 },
	{ 0x15,  0, 17, 0000000000 },
	{ 0x30,  0,  0, 0x00000024 },
	{ 0x15,  0, 15, 0000000000 },
	{ 0x30,  0,  0, 0x00000025 },
	{ 0x15,  0, 13, 0000000000 },
	{ 0x30,  0,  0, 0x00000026 },
	{ 0x15,  0, 11, 0000000000 },
	{ 0x30,  0,  0, 0x00000027 },
	{ 0x15,  0,  9, 0000000000 },	// last ipv6 destination byte (65)

	// Load and compare ICMP6 payload protocol (ip6[54])
	{ 0x30,  0,  0, 0x00000036 },
	{ 0x15,  0,  7, 0000000000 },	// protocol (67)

	// Load and compare ICMP6 payload TCP or UDP source port (ip6[88])
	{ 0x28,  0,  0, 0x00000058 },
	{ 0x35,  0,  5, 0000000000 },	// smallest source port (69)
	{ 0x25,  4,  0, 0000000000 },	// biggest source port (70)

	// Load and compare ICMP6 payload TCP or UDP destination port (ip6[90])
	{ 0x28,  0,  0, 0x0000005a },
	{ 0x35,  0,  2, 0000000000 },	// smallest destination port (72)
	{ 0x25,  1,  0, 0000000000 },	// biggest destination port (73)

	// Return Match or Drop
	{ 0x06,  0,  0, RAW_DATA_MAXSIZE },
	{ 0x06,  0,  0, 0000000000 },
};

#define BPF_FILTER_SIZE(arr)	(sizeof(arr) / sizeof(arr[0]))

static void	filter_ipv6_icmp(int sockfd, int protocol, t_nmap_config *cfg)
{
	uint16_t			filter_length = BPF_FILTER_SIZE(g_bpfcode_ipv6_icmp);
	struct sock_filter	filter[BPF_FILTER_SIZE(g_bpfcode_ipv6_icmp)];
	struct sock_fprog	bpf = { .len = filter_length, .filter = filter };
	t_ip				*src = &cfg->host_job.dev->ip, *dst = &cfg->host_job.ip;

	ft_memcpy(filter, g_bpfcode_ipv6_icmp, sizeof(filter));
	filter[1].k = IPPROTO_ICMPV6;
	for (int i = 0; i < 16; ++i)
		filter[i * 2 + 3].k = dst->v6.sin6_addr.s6_addr[i];
	for (int i = 0; i < 16; ++i)
		filter[i * 2 + 35].k = src->v6.sin6_addr.s6_addr[i];
	filter[67].k = protocol;
	filter[69].k = PORT_DEF;
	filter[70].k = PORT_DEF + cfg->total_scan_count - 1;
	filter[72].k = cfg->ports[0];
	filter[73].k = cfg->ports[cfg->nports - 1];
	if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0)
		ft_exit(EXIT_FAILURE, "%s: setsockopt: %s", __func__, strerror(errno));
}

static void	filter_ipv6_layer4(int sockfd, int protocol, t_nmap_config *cfg)
{
	uint16_t			filter_length = BPF_FILTER_SIZE(g_bpfcode_ipv6_layer4);
	struct sock_filter	filter[BPF_FILTER_SIZE(g_bpfcode_ipv6_layer4)];
	struct sock_fprog	bpf = { .len = filter_length, .filter = filter };
	t_ip				*src = &cfg->host_job.dev->ip, *dst = &cfg->host_job.ip;

	ft_memcpy(filter, g_bpfcode_ipv6_layer4, sizeof(filter));
	filter[1].k = protocol;
	for (int i = 0; i < 16; ++i)
		filter[i * 2 + 3].k = dst->v6.sin6_addr.s6_addr[i];
	for (int i = 0; i < 16; ++i)
		filter[i * 2 + 35].k = src->v6.sin6_addr.s6_addr[i];
	filter[67].k = cfg->ports[0];
	filter[68].k = cfg->ports[cfg->nports - 1];
	filter[70].k = PORT_DEF;
	filter[71].k = PORT_DEF + cfg->total_scan_count - 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0)
		ft_exit(EXIT_FAILURE, "%s: setsockopt: %s", __func__, strerror(errno));
}

static void	filter_ipv4_icmp(int sockfd, int protocol, t_nmap_config *cfg)
{
	uint16_t			filter_length = BPF_FILTER_SIZE(g_bpfcode_ipv4_icmp);
	struct sock_filter	filter[BPF_FILTER_SIZE(g_bpfcode_ipv4_icmp)];
	struct sock_fprog	bpf = { .len = filter_length, .filter = filter };
	t_ip				*src = &cfg->host_job.dev->ip, *dst = &cfg->host_job.ip;

	ft_memcpy(filter, g_bpfcode_ipv4_icmp, sizeof(filter));
	filter[1].k = IPPROTO_ICMP;
	filter[3].k = htonl(dst->v4.sin_addr.s_addr);
	filter[5].k = htonl(src->v4.sin_addr.s_addr);
	filter[7].k = protocol;
	filter[9].k = PORT_DEF;
	filter[10].k = PORT_DEF + cfg->total_scan_count - 1;
	filter[12].k = cfg->ports[0];
	filter[13].k = cfg->ports[cfg->nports - 1];
	if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0)
		ft_exit(EXIT_FAILURE, "%s: setsockopt: %s", __func__, strerror(errno));
}

static void	filter_ipv4_layer4(int sockfd, int protocol, t_nmap_config *cfg)
{
	uint16_t			filter_length = BPF_FILTER_SIZE(g_bpfcode_ipv4_layer4);
	struct sock_filter	filter[BPF_FILTER_SIZE(g_bpfcode_ipv4_layer4)];
	struct sock_fprog	bpf = { .len = filter_length, .filter = filter };
	t_ip				*src = &cfg->host_job.dev->ip, *dst = &cfg->host_job.ip;

	ft_memcpy(filter, g_bpfcode_ipv4_layer4, sizeof(filter));
	filter[1].k = protocol;
	filter[3].k = htonl(dst->v4.sin_addr.s_addr);
	filter[5].k = htonl(src->v4.sin_addr.s_addr);
	filter[7].k = cfg->ports[0];
	filter[8].k = cfg->ports[cfg->nports - 1];
	filter[10].k = PORT_DEF;
	filter[11].k = PORT_DEF + cfg->total_scan_count - 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0)
		ft_exit(EXIT_FAILURE, "%s: setsockopt: %s", __func__, strerror(errno));
}

static void	filter_icmp(enum e_recv_sockets socket_type, t_nmap_config *cfg)
{
	int	protocol;

	protocol = SOCKET_SRECV_IS_UDP(socket_type) ? IPPROTO_UDP : IPPROTO_TCP;
	if (SOCKET_SRECV_IS_IPV4(socket_type))
		filter_ipv4_icmp(cfg->recv_sockets[socket_type], protocol, cfg);
	else if (SOCKET_SRECV_IS_IPV6(socket_type))
		filter_ipv6_icmp(cfg->recv_sockets[socket_type], protocol, cfg);
}

static void	filter_layer4(enum e_recv_sockets socket_type, t_nmap_config *cfg)
{
	int	protocol;

	protocol = SOCKET_SRECV_IS_UDP(socket_type) ? IPPROTO_UDP : IPPROTO_TCP;
	if (SOCKET_SRECV_IS_IPV4(socket_type))
		filter_ipv4_layer4(cfg->recv_sockets[socket_type], protocol, cfg);
	else if (SOCKET_SRECV_IS_IPV6(socket_type))
		filter_ipv6_layer4(cfg->recv_sockets[socket_type], protocol, cfg);
}

void		set_filters(t_nmap_config *cfg)
{
	uint16_t	family = cfg->host_job.family;

	if (family == AF_INET && cfg->has_udp_scans)
	{
		filter_layer4(E_SRECV_UDPV4, cfg);
		filter_icmp(E_SRECV_ICMP_UDPV4, cfg);
	}
	if (family == AF_INET && cfg->has_tcp_scans)
	{
		filter_layer4(E_SRECV_TCPV4, cfg);
		filter_icmp(E_SRECV_ICMP_TCPV4, cfg);
	}
	if (family == AF_INET6 && cfg->has_udp_scans)
	{
		filter_layer4(E_SRECV_UDPV6, cfg);
		filter_icmp(E_SRECV_ICMP_UDPV6, cfg);
	}
	if (family == AF_INET6 && cfg->has_tcp_scans)
	{
		filter_layer4(E_SRECV_TCPV6, cfg);
		filter_icmp(E_SRECV_ICMP_TCPV6, cfg);
	}
}
