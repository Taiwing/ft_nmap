/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pcap_handler.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/17 08:21:27 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/17 15:40:56 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static t_probe	*get_probe(t_packet *reply)
{
	enum e_nexhdr	type;
	uint16_t		port;

	if ((type = reply->nexhdr) == E_NH_NONE)
		return (NULL);
	else if (type == E_NH_UDP)
		port = hdr->udp.uh_dport;
	else if (type == E_NH_TCP)
		port = hdr->tcp.th_dport;
	else if ((type = reply->lasthdr) == E_NH_UDP)
		port = hdr->udp.uh_sport;
	else if (type == E_NH_TCP)
		port = hdr->tcp.th_sport;
	else
		return (NULL);
	return (port < PORT_DEF ? NULL: g_cfg->probes + port - PORT_DEF);
}

void			init_reply_task(const uint8_t *bytes, size_t size,
					int type, uint16_t probe)
{
	t_packet	reply;
	t_list		*new_task;
	t_task		task = { E_TASK_REPLY, NULL, 0 };

	if (bytes)
		init_packet(&reply, type == ETHERTYPE_IP ? E_IH_V4 : E_IH_V6,
			bytes);
	if (reply.size > size)
		ft_exit(EXIT_FAILURE, "%s: computed size bigger than received data",
			__func__);
	if (!(task.probe = bytes ? get_probe(&reply) : g_cfg->probes + probe))
		ft_exit(EXIT_FAILURE, "%s: probe not found\n", __func__);
	task.result = scan_result(task.probe->scan_type, bytes ? &reply : NULL);
	if (task.result == E_STATE_NONE)
		return ;
	new_task = ft_lstnew(&task, sizeof(task));
	if (!g_cfg->speedup)
	{
		push_tasks(&g_cfg->main_tasks, new_task, 0);
		pcap_breakloop(g_cfg->descr);
	}
	else
		push_tasks(&g_cfg->worker_tasks, new_task, 1);
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
	size = h->len - linkhdr_size;
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
