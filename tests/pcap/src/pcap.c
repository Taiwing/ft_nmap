/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pcap.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/05 05:03:01 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/20 14:57:43 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "test_pcap.h"

int					main(int argc, char **argv)
{
	struct iphdr		iphdr;
	struct ipv6hdr		ipv6hdr;
	pcap_t				*descr;
	int					type, ip;
	struct sockaddr_in	srcip_v4 = { 0 };
	struct sockaddr_in6	srcip_v6 = { 0 };
	struct sockaddr_in	dstip_v4 = { 0 };
	struct sockaddr_in6	dstip_v6 = { 0 };
	u_char				packet[PACKET_SIZE_MAX] = { 0 };
	char				*dev, net[INET6_ADDRSTRLEN], mask[INET6_ADDRSTRLEN];
	char				ip4[INET6_ADDRSTRLEN] = { 0 },
						ip6[INET6_ADDRSTRLEN] = { 0 };
	bpf_u_int32			netp;

	char				*prog = argv[0];
	char				*user_filter = NULL;
	char				*user_dstip_v4 = NULL;
	char				*user_dstip_v6 = NULL;
	char				*user_srcip_v4 = NULL;
	char				*user_srcip_v6 = NULL;
	char				*user_sport = NULL;
	char				*user_dport = NULL;
	for (int i = 1; i < argc; ++i)
	{
		if (!strcmp(argv[i], "--filter"))
			user_filter = argv[++i];
		else if (!strcmp(argv[i], "--dstip_v4"))
			user_dstip_v4 = argv[++i];
		else if (!strcmp(argv[i], "--dstip_v6"))
			user_dstip_v6 = argv[++i];
		else if (!strcmp(argv[i], "--srcip_v4"))
			user_srcip_v4 = argv[++i];
		else if (!strcmp(argv[i], "--srcip_v6"))
			user_srcip_v6 = argv[++i];
		else if (!strcmp(argv[i], "--sport"))
			user_sport = argv[++i];
		else if (!strcmp(argv[i], "--dport"))
			user_dport = argv[++i];
	}

	/*
	printf("sizes:\n");
	printf("ether_header: %zu\n", sizeof(struct ether_header));
	printf("iphdr: %zu\n", sizeof(struct iphdr));
	printf("ipv6hdr: %zu\n", sizeof(struct ipv6hdr));
	printf("icmphdr: %zu\n", sizeof(struct icmphdr));
	printf("icmp6hdr: %zu\n", sizeof(struct icmp6hdr));
	printf("tcphdr: %zu\n", sizeof(struct tcphdr));
	printf("udphdr: %zu\n", sizeof(struct udphdr));
	printf("MAX_HEADER_SIZE: %zu\n\n", MAX_HEADER_SIZE);
	*/

	printf("---- Network ----\n");
	if (get_network(prog, &dev, net, mask, &netp))
		return (EXIT_FAILURE);
	printf("dev: %s\n", dev);
	printf("net: %s\n", net);
	printf("mask: %s\n", mask);
	if ((ip = get_ips(&srcip_v4, &srcip_v6, dev, prog)) < 0)
		return (EXIT_FAILURE);
	else if (!ip)
	{
		dprintf(2, "%s: get_ips: no valid ip for %s interface\n", prog, dev);
		return (EXIT_FAILURE);
	}
	if (print_ips(ip, ip4, ip6, &srcip_v4, &srcip_v6, prog))
		return (EXIT_FAILURE);
	memcpy(&dstip_v4, &srcip_v4, sizeof(dstip_v4));
	memcpy(&dstip_v6, &srcip_v6, sizeof(dstip_v6));

	printf("\n---- Receive packet ----\n");
	if (!(descr = open_device(prog, dev)))
		return (EXIT_FAILURE);
	if (set_filter(descr, ip, ip4, ip6, user_filter, prog, netp))
		return (EXIT_FAILURE);
	if (grab_packet(prog, descr, packet))
		return (EXIT_FAILURE);
	if (print_ether_type(&type, packet))
		return (EXIT_FAILURE);
	if (type == ETHERTYPE_IP)
	{
		memcpy(&iphdr, packet + sizeof(struct ether_header),
			sizeof(struct iphdr));
		print_iphdr(&iphdr, AF_INET, prog);
		if (!user_dstip_v4)
			memcpy(&dstip_v4.sin_addr, &iphdr.saddr, sizeof(dstip_v4.sin_addr));
	}
	else if (type == ETHERTYPE_IPV6)
	{
		memcpy(&ipv6hdr, packet + sizeof(struct ether_header),
			sizeof(struct ipv6hdr));
		print_iphdr(&ipv6hdr, AF_INET6, prog);
		if (!user_dstip_v6)
			memcpy(&dstip_v6.sin6_addr, &ipv6hdr.saddr, sizeof(dstip_v6.sin6_addr));
	}
	pcap_close(descr);
	printf("\n");

	if (ip != 3)
	{
		dprintf(2, "%s: ipv4 and ipv6 are not both available\n", prog);
		return (EXIT_FAILURE);
	}
	uint16_t		sport = PORT_DEF, dport = PORT_DEF;
	struct iphdr	ip4h = { 0 };
	struct ipv6hdr	ip6h = { 0 };
	struct tcphdr	tcph = { 0 };
	struct udphdr	udph = { 0 };
	int				ip4tcp_socket, ip4udp_socket, ip6tcp_socket, ip6udp_socket;
	unsigned char	ipbuf[sizeof(struct in6_addr)];
	if ((ip4tcp_socket = init_socket(AF_INET, IPPROTO_TCP, prog)) < 0)
		return (EXIT_FAILURE);
	if ((ip4udp_socket = init_socket(AF_INET, IPPROTO_UDP, prog)) < 0)
		return (EXIT_FAILURE);
	if ((ip6tcp_socket = init_socket(AF_INET6, IPPROTO_TCP, prog)) < 0)
		return (EXIT_FAILURE);
	if ((ip6udp_socket = init_socket(AF_INET6, IPPROTO_UDP, prog)) < 0)
		return (EXIT_FAILURE);
	if (user_srcip_v4 && inet_pton(AF_INET, user_srcip_v4, ipbuf) > 0)
		memcpy(&srcip_v4.sin_addr, ipbuf, sizeof(srcip_v4.sin_addr));
	if (user_srcip_v6 && inet_pton(AF_INET6, user_srcip_v6, ipbuf) > 0)
		memcpy(&srcip_v6.sin6_addr, ipbuf, sizeof(srcip_v6.sin6_addr));
	if (user_dstip_v4 && inet_pton(AF_INET, user_dstip_v4, ipbuf) > 0)
		memcpy(&dstip_v4.sin_addr, ipbuf, sizeof(dstip_v4.sin_addr));
	if (user_dstip_v6 && inet_pton(AF_INET6, user_dstip_v6, ipbuf) > 0)
		memcpy(&dstip_v6.sin6_addr, ipbuf, sizeof(dstip_v6.sin6_addr));
	if (user_sport)
		sport = atoi(user_sport);
	if (user_dport)
		dport = atoi(user_dport);

	printf("---- Send IPv4 UDP packet ----\n");
	t_iph_args	ipv4args = {
		.version = 4,
		.dstip = (struct sockaddr *)&dstip_v4,
		.srcip = (struct sockaddr *)&srcip_v4,
		.protocol = IP_HEADER_UDP,
		.hop_limit = 255,
		.layer5_len = 0,
	};
	init_ip_header(&ip4h, &ipv4args);
	print_iphdr(&ip4h, AF_INET, prog);
	bzero(packet, sizeof(packet));
	if (init_udp_header((uint8_t *)&udph, &ip4h, sport, dport) < 0)
		dprintf(2, "%s: init_udp_header: failure\n", prog);
	print_udphdr(&udph);
	memcpy(packet, &ip4h, sizeof(ip4h));
	memcpy(packet + sizeof(ip4h), &udph, sizeof(udph));
	if (sendto(ip4udp_socket, packet, ntohs(ip4h.tot_len), 0,
			(struct sockaddr *)&dstip_v4, sizeof(dstip_v4)) < 0)
		dprintf(2, "%s: sendto: %s\n", prog, strerror(errno));
	else
		printf("Status: Package Sent\n");

	printf("\n---- Send IPv6 UDP packet ----\n");
	t_iph_args	ipv6args = {
		.version = 6,
		.dstip = (struct sockaddr *)&dstip_v6,
		.srcip = (struct sockaddr *)&srcip_v6,
		.protocol = IP_HEADER_UDP,
		.hop_limit = 255,
		.layer5_len = 0,
	};
	init_ip_header(&ip6h, &ipv6args);
	print_iphdr(&ip6h, AF_INET6, prog);
	bzero(packet, sizeof(packet));
	bzero(&udph, sizeof(struct udphdr));
	if (init_udp_header((uint8_t *)&udph, &ip6h, sport, dport) < 0)
		dprintf(2, "%s: init_udp_header: failure\n", prog);
	print_udphdr(&udph);
	memcpy(packet, &ip6h, sizeof(ip6h));
	memcpy(packet + sizeof(ip6h), &udph, sizeof(udph));
	if (sendto(ip6udp_socket, packet, ntohs(ip6h.payload_len) + sizeof(ip6h), 0,
			(struct sockaddr *)&dstip_v6, sizeof(dstip_v6)) < 0)
		dprintf(2, "%s: sendto: %s\n", prog, strerror(errno));
	else
		printf("Status: Package Sent\n");

	printf("\n---- Send IPv4 TCP packet ----\n");
	ipv4args.protocol = IP_HEADER_TCP;
	init_ip_header(&ip4h, &ipv4args);
	print_iphdr(&ip4h, AF_INET, prog);
	t_tcph_args	tcpargs = {
		.iphdr = &ip4h,
		.version = 4,
		.srcp = sport,
		.dstp = dport,
		.seq = 0x12344321,
		.ack = 0,
		.flags = TH_SYN,
		.win = 0xffff,
		.urp = 0,
	};
	bzero(packet, sizeof(packet));
	if (init_tcp_header((uint8_t *)&tcph, &tcpargs) < 0)
		dprintf(2, "%s: init_tcp_header: failure\n", prog);
	print_tcphdr(&tcph);
	memcpy(packet, &ip4h, sizeof(ip4h));
	memcpy(packet + sizeof(ip4h), &tcph, sizeof(tcph));
	if (sendto(ip4tcp_socket, packet, ntohs(ip4h.tot_len), 0,
			(struct sockaddr *)&dstip_v4, sizeof(dstip_v4)) < 0)
		dprintf(2, "%s: sendto: %s\n", prog, strerror(errno));
	else
		printf("Status: Package Sent\n");

	printf("\n---- Send IPv6 TCP packet ----\n");
	ipv6args.protocol = IP_HEADER_TCP;
	init_ip_header(&ip6h, &ipv6args);
	print_iphdr(&ip6h, AF_INET6, prog);
	tcpargs.iphdr = &ip6h;
	tcpargs.version = 6;
	bzero(packet, sizeof(packet));
	if (init_tcp_header((uint8_t *)&tcph, &tcpargs) < 0)
		dprintf(2, "%s: init_tcp_header: failure\n", prog);
	print_tcphdr(&tcph);
	memcpy(packet, &ip6h, sizeof(ip6h));
	memcpy(packet + sizeof(ip6h), &tcph, sizeof(tcph));
	if (sendto(ip6tcp_socket, packet, ntohs(ip6h.payload_len) + sizeof(ip6h),
			0, (struct sockaddr *)&dstip_v6, sizeof(dstip_v6)) < 0)
		dprintf(2, "%s: sendto: %s\n", prog, strerror(errno));
	else
		printf("Status: Package Sent\n");

	//TODO: put in clean ft_atexit handler
	close(ip4tcp_socket);
	close(ip4udp_socket);
	close(ip6tcp_socket);
	close(ip6udp_socket);
	//TODO
	return (EXIT_SUCCESS);
}
