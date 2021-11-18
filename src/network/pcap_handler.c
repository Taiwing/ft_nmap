/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pcap_handler.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/17 08:21:27 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/18 19:18:04 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static t_probe	*get_probe(t_packet *reply)
{
	enum e_nexthdr	type = reply->nexthdr;
	t_nexthdr		*hdr = reply->next;
	uint16_t		dport, sport;

	if (type == E_NH_ICMP || type == E_NH_ICMP6)
	{
		hdr = reply->last;
		type = reply->lasthdr;
	}
	switch (type)
	{
		case E_NH_UDP:
			sport = hdr == reply->next ? hdr->udp.uh_dport : hdr->udp.uh_sport;
			dport = hdr == reply->next ? hdr->udp.uh_sport : hdr->udp.uh_dport;
			break ;
		case E_NH_TCP:
			sport = hdr == reply->next ? hdr->tcp.th_dport : hdr->tcp.th_sport;
			dport = hdr == reply->next ? hdr->tcp.th_sport : hdr->tcp.th_dport;
			break ;
		default:
			return (NULL);
	}
	if (sport < PORT_DEF || g_cfg->probes[sport - PORT_DEF].dstp != dport)
		return (NULL);
	return (g_cfg->probes + sport - PORT_DEF);
}

void			init_reply_task(const uint8_t *bytes, size_t size,
					int type, uint16_t probe)
{
	t_packet	reply;
	t_list		*new_task;
	t_task		task = { E_TASK_REPLY, NULL, E_STATE_NONE };

	if (bytes)
		init_packet(&reply, type == ETHERTYPE_IP ? E_IH_V4 : E_IH_V6,
			(uint8_t *)bytes);
	if (reply.size > size)
		ft_exit(EXIT_FAILURE, "%s: packet parsing failure (size)", __func__);
	if ((task.probe = bytes ? get_probe(&reply) : g_cfg->probes + probe))
		task.result = scan_result(task.probe->scan_type, bytes ? &reply : NULL);
	if (g_cfg->verbose)
		verbose_reply(g_cfg, &task, bytes ? &reply : NULL);
	if (g_cfg->debug && !task.probe && bytes)
		debug_invalid_packet(g_cfg, &reply);
	if (task.result == E_STATE_NONE)
		return ;
	new_task = ft_lstnew(&task, sizeof(task));
	if (!g_cfg->speedup)
	{
		push_tasks(&g_cfg->main_tasks, new_task, g_cfg, 0);
		pcap_breakloop(g_cfg->descr);
	}
	else
		push_tasks(&g_cfg->worker_tasks, new_task, g_cfg, 1);
}

void			pcap_handlerf(uint8_t *u, const struct pcap_pkthdr *h,
	const uint8_t *bytes)
{
	int				type = 0;
	size_t			size = 0;

	(void)u;
	if (h->len < g_cfg->linkhdr_size)
		ft_exit(EXIT_FAILURE, "%s: too small for a link layer header",
			__func__);
	size = h->len - g_cfg->linkhdr_size;
	size = size > RAW_DATA_MAXSIZE ? RAW_DATA_MAXSIZE : size;
	type = ntohs(g_cfg->linktype == DLT_LINUX_SLL ?
		((struct sll_header *)bytes)->sll_protocol :
		((struct sll2_header *)bytes)->sll2_protocol);
	bytes += g_cfg->linkhdr_size;
	if (type != ETHERTYPE_IP && type != ETHERTYPE_IPV6)
		ft_exit(EXIT_FAILURE, "%s: invalid ether type: %d", __func__, type);
	else if ((type == ETHERTYPE_IP && size < sizeof(struct iphdr))
		|| (type == ETHERTYPE_IPV6 && size < sizeof(struct ipv6hdr)))
		ft_exit(EXIT_FAILURE, "%s: too small for an IP%s header: %hu bytes",
			__func__, type == ETHERTYPE_IP ? "v4" : "v6", size);
	init_reply_task(bytes, size, type, 0);
}
