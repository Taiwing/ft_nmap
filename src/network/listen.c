/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   listen.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/30 07:37:42 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/31 15:40:42 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

const char	*g_filter_format = "(src host %1$s && dst host %2$s) "
	"&& ((%3$s src port %4$hu && %3$s dst port %5$hu) || %6$s)";

static pcap_t	*open_device(t_scan *scan, int maxlen, int timeout)
{
	pcap_t	*descr;
	char	errbuf[PCAP_ERRBUF_SIZE];

	if (!(descr = pcap_open_live(scan->job->dev->name, maxlen,
			0, timeout, errbuf)))
		ft_exit(EXIT_FAILURE, "pcap_open_live: %s\n", errbuf);
	return (descr);
}

static void		set_filter(pcap_t *descr, char *filter, t_scan *scan)
{
	int					ret;
	struct bpf_program	fp = { 0 };
	bpf_u_int32			netp = scan->job->family == AF_INET ?
		PCAP_NETMASK_UNKNOWN : scan->job->dev->netmask.v4.sin_addr.s_addr;

	if (pcap_compile(descr, &fp, filter, 1, netp) == PCAP_ERROR)
	{
		pcap_close(descr);
		ft_exit(EXIT_FAILURE, "pcap_compile: %s\n", pcap_geterr(descr));
	}
	ret = pcap_setfilter(descr, &fp);
	pcap_freecode(&fp);
	if (ret == PCAP_ERROR)
	{
		pcap_close(descr);
		ft_exit(EXIT_FAILURE, "pcap_setfilter: %s\n", pcap_geterr(descr));
	}
	if (scan->cfg->verbose > 1)
		verbose_listener_setup(scan, filter);
}

pcap_t			*setup_listener(t_scan *scan, uint16_t srcp, uint16_t dstp)
{
	pcap_t	*descr = NULL;
	t_job	*job = scan->job;
	t_ip	*srcip = &job->dev->ip, *dstip = &job->host_ip;
	char	filter[FILTER_MAXLEN + 1] = { 0 };
	char	srcipbuf[INET6_ADDRSTRLEN + 1], dstipbuf[INET6_ADDRSTRLEN + 1];

	if (!(descr = open_device(scan, HEADER_MAXSIZE, 1)))
		return (NULL);
	ft_snprintf(filter, FILTER_MAXLEN, g_filter_format,
		inet_ntop(job->family, ip_addr(dstip), dstipbuf, INET6_ADDRSTRLEN),
		inet_ntop(job->family, ip_addr(srcip), srcipbuf, INET6_ADDRSTRLEN),
		scan->type == E_UDP ? "udp" : "tcp", dstp, srcp,
		job->family == AF_INET ? "icmp" : "icmp6");
	set_filter(descr, filter, scan);
	return (descr);
}

void			grab_reply(uint8_t *user, const struct pcap_pkthdr *h,
					const uint8_t *bytes)
{
	t_packet		*reply;
	int				type = 0;
	size_t			size = 0;

	if (h->len < sizeof(struct ether_header))
		ft_exit(EXIT_FAILURE, "%s: too small for an ether header", __func__);
	reply = (t_packet *)user;
	if (reply->size)
		ft_exit(EXIT_FAILURE, "%s: reply already initialized", __func__);
	size = h->len - sizeof(struct ether_header);
	size = size > RAW_DATA_MAXSIZE ? RAW_DATA_MAXSIZE : size;
	type = ntohs(((struct ether_header *)bytes)->ether_type);
	bytes += sizeof(struct ether_header);
	if (type != ETHERTYPE_IP && type != ETHERTYPE_IPV6)
		ft_exit(EXIT_FAILURE, "%s: invalid ether type: %d", __func__, type);
	else if ((type == ETHERTYPE_IP && size < sizeof(struct iphdr))
		|| (type == ETHERTYPE_IPV6 && size < sizeof(struct ipv6hdr)))
		ft_exit(EXIT_FAILURE, "%s: too small for an IP%s header: %hu bytes",
			__func__, type == ETHERTYPE_IP ? "v4" : "v6", size);
	ft_memcpy(reply->raw_data, bytes, size);
	init_packet(reply, type == ETHERTYPE_IP ? E_IH_V4 : E_IH_V6);
	if (reply->size > size)
		ft_exit(EXIT_FAILURE, "%s: computed size bigger than received data",
			__func__);
}

int				ft_listen(t_packet *reply, pcap_t *descr, pcap_handler callback)
{
	int	ret;

	if ((ret = pcap_dispatch(descr, 0, callback,
			(uint8_t *)reply)) == PCAP_ERROR)
		ft_exit(EXIT_FAILURE, "pcap_dispatch: pcap error");
	else if (ret == PCAP_ERROR_BREAK)
		return (-1);
	return (0);
}
