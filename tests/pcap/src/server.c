/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   server.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/20 17:22:31 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/21 18:27:02 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "test_pcap.h"

static void	phandler(u_char *user, const struct pcap_pkthdr *h,
	const u_char *bytes)
{
	static int		nb = 0;
	int				type = 0;
	uint16_t		size = 0;
	struct iphdr	*ip4h = NULL;
	struct ipv6hdr	*ip6h = NULL;

	if (h->len >= ETHER_HDR_LEN)
		size = h->len - ETHER_HDR_LEN;
	memcpy(user, h, sizeof(struct pcap_pkthdr));
	memcpy(user + sizeof(struct pcap_pkthdr), bytes,
		h->len > HEADER_SIZE_MAX ? HEADER_SIZE_MAX : h->len);
	printf("\n---- Received Packet NB %d ----\n", ++nb);
	print_ether_type(&type, (u_char *)bytes);
	bytes += ETHER_HDR_LEN;
	ip4h = type == ETHERTYPE_IP ? (struct iphdr *)bytes : NULL;
	ip6h = type == ETHERTYPE_IPV6 ? (struct ipv6hdr *)bytes : NULL;
	if (!ip4h && !ip6h)
		dprintf(2, "%s: %s: invalid ether type: %d\n",
			"horsewithnoname", __func__, type);
	else if ((ip4h && size < sizeof(struct iphdr))
		|| (ip6h && size < sizeof(struct ipv6hdr)))
		dprintf(2, "%s: %s: not enough data for IP%s header: %hu bytes\n",
			"horsewithnoname", __func__, ip4h ? "" : "v6", size);
	else
	{
		print_iphdr((void *)bytes, ip4h ? AF_INET : AF_INET6, "horsewithnoname");
		size -= ip4h ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
		print_nexthdr((void *)bytes, ip4h ? AF_INET : AF_INET6, size, "horsewithnoname");
	}
}

static int	server_internal(u_char *packet, int timeout, char *dev, char *ip4,
		char *ip6, uint16_t sport, uint16_t dport, bpf_u_int32 netp, char *prog)
{
	pcap_t	*descr;
	char	filter[FILTER_MAXLEN] = { 0 };

	if (sport && dport)
	{
		snprintf(filter, FILTER_MAXLEN, "(dst port %1$hu && src port %2$hu) "
			"|| (icmp || icmp6)", sport, dport);
		printf("DEBUG: filter: %s\n", filter); //TEMP
	}
	printf("\n---- Initialize server ----\n");
	if (!(descr = open_device(dev, HEADER_SIZE_MAX, timeout, prog)))
		return (EXIT_FAILURE);
	if (set_filter(descr, 3, ip4, ip6, filter, prog, netp))
		return (EXIT_FAILURE);
	printf("Start grabbing ^-^\n\n");
	if (grab_packet(packet, descr, phandler, 0, prog))
		return (EXIT_FAILURE);
	pcap_close(descr);
	return (EXIT_SUCCESS);
}

int	server(u_char *packet, pid_t sender_proc, int timeout, char *dev, char *ip4,
		char *ip6, uint16_t sport, uint16_t dport, bpf_u_int32 netp, char *prog)
{
	int server_status = server_internal(packet, timeout, dev, ip4, ip6,
		sport, dport, netp, prog);
	int	sender_status = 0;

	if (sender_proc && waitpid(sender_proc, &sender_status, 0) < 0)
	{
		dprintf(2, "%s: waitpid: %s\n", prog, strerror(errno));
		return (EXIT_FAILURE);
	}
	return (server_status || sender_status);
}
