/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   grab_packet.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/20 14:35:26 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/20 14:54:39 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "test_pcap.h"

pcap_t		*open_device(char *prog, char *dev)
{
	pcap_t	*descr;
	char	errbuf[PCAP_ERRBUF_SIZE];

	//if (!(descr = pcap_open_live(dev, BUFSIZ, 0, 1000000, errbuf)))
	if (!(descr = pcap_open_live(dev, 100, 0, 1, errbuf)))
		dprintf(2, "%s: pcap_open_live: %s\n", prog, errbuf);
	return (descr);
}

#define FILTER_MAXLEN	1024

int			set_filter(pcap_t *descr, int ip, char *ip4, char *ip6,
				char *user_filter, char *prog, bpf_u_int32 netp)
{
	char				filter[FILTER_MAXLEN] = { 0 };
	struct bpf_program	fp = { 0 };

	strncat(filter, "(dst host ", INET6_ADDRSTRLEN);
	if (ip & 1)
		strncat(filter, ip4, INET6_ADDRSTRLEN);
	if (ip == 3)
		strncat(filter, " || dst host ", INET6_ADDRSTRLEN);
	if (ip & 2)
		strncat(filter, ip6, INET6_ADDRSTRLEN);
	strncat(filter, ")", INET6_ADDRSTRLEN);
	if (user_filter)
	{
		strncat(filter, " && (", INET6_ADDRSTRLEN);
		strncat(filter, user_filter, INET6_ADDRSTRLEN);
		strncat(filter, ")", INET6_ADDRSTRLEN);
	}
	if (pcap_compile(descr, &fp, filter, 1, netp) == PCAP_ERROR)
	{
		dprintf(2, "%s: pcap_compile: %s\n", prog, pcap_geterr(descr));
		return (1);
	}
	printf("pcap filter: %s\n", filter);
	if (pcap_setfilter(descr, &fp) == PCAP_ERROR)
	{
		dprintf(2, "%s: pcap_setfilter: %s\n", prog, pcap_geterr(descr));
		return (1);
	}
	pcap_freecode(&fp); //TODO: put in clean ft_atexit handler
	return (0);
}

static void	phandler(u_char *user, const struct pcap_pkthdr *h,
	const u_char *bytes)
{
	//TEMP
	write(1, ".", 1);
	//TEMP
	memcpy(user, h, sizeof(struct pcap_pkthdr));
	memcpy(user + sizeof(struct pcap_pkthdr), bytes, h->len);
}

int			grab_packet(char *prog, pcap_t *descr, u_char *packet)
{
	int						ret;
	struct pcap_pkthdr		*h;
	u_char					buf[PACKET_SIZE_MAX];

	//if ((ret = pcap_dispatch(descr, 1, phandler, buf)) == PCAP_ERROR)
	if ((ret = pcap_dispatch(descr, 0, phandler, buf)) == PCAP_ERROR)
	{
		dprintf(2, "%s: pcap_dispatch: did not grab packet :(\n", prog);
		return (1);
	}
	else if (ret == PCAP_ERROR_BREAK)
	{
		dprintf(2, "%s: pcap_dispatch: loop has been broken\n", prog);
		return (1);
	}
	h = (struct pcap_pkthdr *)buf;
	memcpy(packet, buf + sizeof(struct pcap_pkthdr), h->len);
	printf("\nGrabbed packet of length %d\n", h->len);
	printf("Received at .... %s\n", ctime((const time_t *)&h->ts.tv_sec));
	printf("Ethernet address length is %d\n", ETHER_HDR_LEN);
	return (0);
}
