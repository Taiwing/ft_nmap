/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   listen.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/30 07:37:42 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/07 12:09:57 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static pcap_t	*open_device(t_scan *scan, int maxlen, int timeout)
{
	pcap_t	*descr;
	char	errbuf[PCAP_ERRBUF_SIZE];

	if (!(descr = pcap_open_live(NULL, maxlen, 0, timeout, errbuf)))
		ft_exit(EXIT_FAILURE, "pcap_open_live: %s\n", errbuf);
	return (descr);
}

#define SET_FILTER_ERRBUF_SIZE	(PCAP_ERRBUF_SIZE + 128)

static void		set_filter(pcap_t *descr, char *filter, t_scan *scan)
{
	int					ret;
	struct bpf_program	fp = { 0 };
	char				errbuf[SET_FILTER_ERRBUF_SIZE + 1] = { 0 };
	bpf_u_int32			netp = scan->job->family == AF_INET ?
		PCAP_NETMASK_UNKNOWN : scan->job->dev->netmask.v4.sin_addr.s_addr;

	if (pcap_compile(descr, &fp, filter, 1, netp) == PCAP_ERROR)
	{
		ft_snprintf(errbuf, SET_FILTER_ERRBUF_SIZE,
			"pcap_compile: %s", pcap_geterr(descr));
		pcap_close(descr);
		ft_exit(EXIT_FAILURE, errbuf);
	}
	ret = pcap_setfilter(descr, &fp);
	pcap_freecode(&fp);
	if (ret == PCAP_ERROR)
	{
		ft_snprintf(errbuf, SET_FILTER_ERRBUF_SIZE,
			"pcap_setfilter: %s", pcap_geterr(descr));
		pcap_close(descr);
		ft_exit(EXIT_FAILURE, errbuf);
	}
	if (scan->cfg->verbose > 1)
		verbose_listener_setup(scan, filter);
}

const char	*g_filter_format =
"(src host %1$s && dst host %2$s) "
"&& ((%4$s src port %5$hu && %4$s dst port %6$hu) "
"|| (%7$s[%8$d] == %9$d && %7$s[%10$d:2] == %6$hu && %7$s[%11$d:2] == %5$hu))";
/*
"&& ((%4$s src port %5$hu && %4$s dst port %6$hu) "
"|| (%7$s && %7$s[%7$stype] == icmp-unreach))";
*/

pcap_t			*setup_listener(t_scan *scan, uint16_t srcp, uint16_t dstp)
{
	pcap_t	*descr = NULL;
	t_job	*job = scan->job;
	t_ip	*srcip = &job->dev->ip, *dstip = &job->host_ip;
	char	filter[FILTER_MAXLEN + 1] = { 0 };
	char	*ip = job->family == AF_INET ? "ip" : "ip6";
	char	*layer4 = scan->type == E_UDP ? "udp" : "tcp";
	char	*icmp = job->family == AF_INET ? "icmp" : "icmp6";
	char	srcipbuf[INET6_ADDRSTRLEN + 1], dstipbuf[INET6_ADDRSTRLEN + 1];

	if (!(descr = open_device(scan, HEADER_MAXSIZE, 1)))
		return (NULL);
	ft_snprintf(filter, FILTER_MAXLEN, g_filter_format,
		inet_ntop(job->family, ip_addr(dstip), dstipbuf, INET6_ADDRSTRLEN),
		inet_ntop(job->family, ip_addr(srcip), srcipbuf, INET6_ADDRSTRLEN),
		ip, layer4, dstp, srcp, icmp, 17, scan->type == E_UDP ? IP_HEADER_UDP
		: IP_HEADER_TCP, 28, 30);
	//TEMP
	//ft_printf("FILTER: %s\n", filter);
	//TEMP
	set_filter(descr, filter, scan);
	return (descr);
}

//TODO: move these into the nmap config structure because they should be
//availabe everywhere in the program
int		g_linktype = 0;
size_t	linkhdr_size = 0;

#include <pcap/sll.h>

void			grab_reply(uint8_t *user, const struct pcap_pkthdr *h,
					const uint8_t *bytes)
{
	t_packet		*reply;
	int				type = 0;
	size_t			size = 0;

	if (h->len < linkhdr_size)
		ft_exit(EXIT_FAILURE, "%s: too small for a link layer header",
			__func__);
	reply = (t_packet *)user;
	//TODO: uncomment and test it does not happen (or if it does why ???)
	//if (reply->size)
		//ft_exit(EXIT_FAILURE, "%s: reply already initialized", __func__);
	size = h->len - linkhdr_size;
	size = size > RAW_DATA_MAXSIZE ? RAW_DATA_MAXSIZE : size;
	type = ntohs(g_linktype == DLT_LINUX_SLL ?
		((struct sll_header *)bytes)->sll_protocol :
		((struct sll2_header *)bytes)->sll2_protocol);
	bytes += linkhdr_size;
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
	//TEMP
	/*
	ft_printf("size: %zu\n", size);
	verbose_scan(g_scan, reply, "Debug from grab_reply:");
	*/
	//TEMP
}

int				ft_listen(t_packet *reply, pcap_t *descr, pcap_handler callback)
{
	int	ret;

	if ((g_linktype = pcap_datalink(descr)) == PCAP_ERROR_NOT_ACTIVATED)
		ft_exit(EXIT_FAILURE, "%s: pcap_datalink failure", __func__);
	if (g_linktype != DLT_LINUX_SLL && g_linktype != DLT_LINUX_SLL2)
		ft_exit(EXIT_FAILURE, "%s: unsupported link layer type: %d", __func__,
			g_linktype);
	linkhdr_size = g_linktype == DLT_LINUX_SLL ? sizeof(struct sll_header)
		: sizeof(struct sll2_header);
	if ((ret = pcap_dispatch(descr, 0, callback,
			(uint8_t *)reply)) == PCAP_ERROR)
		ft_exit(EXIT_FAILURE, "pcap_dispatch: pcap error");
	else if (ret == PCAP_ERROR_BREAK)
		return (-1);
	return (0);
}
