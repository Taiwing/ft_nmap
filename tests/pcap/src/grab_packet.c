/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   grab_packet.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/20 14:35:26 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/21 18:31:40 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "test_pcap.h"

pcap_t		*open_device(char *dev, int maxlen, int timeout, char *prog)
{
	pcap_t	*descr;
	char	errbuf[PCAP_ERRBUF_SIZE];

	//if (!(descr = pcap_open_live(dev, BUFSIZ, 0, 1000000, errbuf)))
	if (!(descr = pcap_open_live(dev, maxlen, 0, timeout, errbuf)))
		dprintf(2, "%s: pcap_open_live: %s\n", prog, errbuf);
	return (descr);
}

int			set_filter(pcap_t *descr, int ip, char *ip4, char *ip6,
				char *user_filter, char *prog, bpf_u_int32 netp)
{
	char				filter[FILTER_MAXLEN] = { 0 };
	struct bpf_program	fp = { 0 };

	snprintf(filter, FILTER_MAXLEN, "(dst host %s%s%s)", ip & 1 ? ip4 : ip6,
		ip == 3 ? " || dst host " : "", ip == 3 ? ip6 : "");
	if (user_filter && strlen(user_filter))
		snprintf(filter + strlen(filter), FILTER_MAXLEN - strlen(filter),
			" && (%s)", user_filter);
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

int			grab_packet(u_char *packet, pcap_t *descr,
				pcap_handler callback, int cnt, char *prog)
{
	int						ret;
	struct pcap_pkthdr		*h;
	u_char					buf[PACKET_SIZE_MAX];

	if ((ret = pcap_dispatch(descr, cnt, callback, buf)) == PCAP_ERROR)
	{
		dprintf(2, "%s: pcap_dispatch: did not grab packet :(\n", prog);
		return (1);
	}
	else if (ret == PCAP_ERROR_BREAK)
	{
		dprintf(2, "%s: pcap_dispatch: loop has been broken\n", prog);
		return (1);
	}
	if (packet)
	{
		h = (struct pcap_pkthdr *)buf;
		memcpy(packet, buf + sizeof(struct pcap_pkthdr),
			h->len > HEADER_SIZE_MAX ? HEADER_SIZE_MAX : h->len);
		printf("\nGrabbed packet of length %d\n", h->len);
		printf("Received at .... %s\n", ctime((const time_t *)&h->ts.tv_sec));
		printf("Ethernet address length is %d\n", ETHER_HDR_LEN);
	}
	return (0);
}
