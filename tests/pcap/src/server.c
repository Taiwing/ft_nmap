/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   server.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/20 17:22:31 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/21 11:02:17 by yforeau          ###   ########.fr       */
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

	(void)user;
	if (h->len >= ETHER_HDR_LEN)
		size = h->len - ETHER_HDR_LEN;
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

static int	server_internal(char *dev, char *ip4, char *ip6, uint16_t sport,
		uint16_t dport, bpf_u_int32 netp, char *prog)
{
	pcap_t	*descr;
	char	filter[FILTER_MAXLEN] = { 0 };

	snprintf(filter, FILTER_MAXLEN, "(dst port %1$hu && src port %2$hu) "
		"|| (icmp || icmp6)", sport, dport);
	printf("DEBUG: filter: %s\n", filter); //TEMP
	printf("\n---- Initialize server ----\n");
	if (!(descr = open_device(dev, HEADER_SIZE_MAX, 5, prog)))
		return (EXIT_FAILURE);
	if (set_filter(descr, 3, ip4, ip6, filter, prog, netp))
		return (EXIT_FAILURE);
	printf("Start grabbing ^-^\n\n");
	if (grab_packet(NULL, descr, phandler, 0, prog))
		return (EXIT_FAILURE);
	pcap_close(descr);
	return (EXIT_SUCCESS);
}

int	server(pid_t sender_proc, char *dev, char *ip4, char *ip6, uint16_t sport,
		uint16_t dport, bpf_u_int32 netp, char *prog)
{
	int server_status = server_internal(dev, ip4, ip6, sport, dport, netp, prog);
	int	sender_status = 0;

	if (waitpid(sender_proc, &sender_status, 0) < 0)
	{
		dprintf(2, "%s: waitpid: %s\n", prog, strerror(errno));
		return (EXIT_FAILURE);
	}
	return (server_status || sender_status);
}
