/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse_reply_packet.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/12 20:43:03 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/04 09:18:39 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static t_probe	*get_probe(t_packet *reply, t_nmap_config *cfg)
{
	int				is_icmp = reply->nexthdr && reply->nexthdr < E_NH_TCP;
	enum e_nexthdr	type = is_icmp ? reply->lasthdr : reply->nexthdr;
	t_nexthdr		*hdr = is_icmp ? reply->last : reply->next;
	uint16_t		dport, sport;

	switch (type)
	{
		case E_NH_UDP:
			sport = ntohs(is_icmp ? hdr->udp.uh_sport : hdr->udp.uh_dport);
			dport = ntohs(is_icmp ? hdr->udp.uh_dport : hdr->udp.uh_sport);
			break ;
		case E_NH_TCP:
			sport = ntohs(is_icmp ? hdr->tcp.th_sport : hdr->tcp.th_dport);
			dport = ntohs(is_icmp ? hdr->tcp.th_dport : hdr->tcp.th_sport);
			break ;
		default:
			return (NULL);
	}
	if (sport < PORT_DEF || cfg->probes[sport - PORT_DEF].dstp != dport)
		return (NULL);
	return (cfg->probes + sport - PORT_DEF);
}

static uint8_t	*check_link_layer(t_task *task, t_nmap_config *cfg,
		enum e_iphdr *iph, size_t *size)
{
	int				type;
	uint8_t			*bytes = task->reply;

	if (task->reply_size < cfg->linkhdr_size)
		ft_exit(EXIT_FAILURE, "%s: too small for a link layer header",
			__func__);
	*size = task->reply_size - cfg->linkhdr_size;
	*size = *size > RAW_DATA_MAXSIZE ? RAW_DATA_MAXSIZE : *size;
	type = ntohs(cfg->linktype == DLT_LINUX_SLL ?
		((struct sll_header *)bytes)->sll_protocol :
		((struct sll2_header *)bytes)->sll2_protocol);
	if (type != ETHERTYPE_IP && type != ETHERTYPE_IPV6)
		ft_exit(EXIT_FAILURE, "%s: invalid ether type: %d", __func__, type);
	else if ((type == ETHERTYPE_IP && *size < sizeof(struct iphdr))
		|| (type == ETHERTYPE_IPV6 && *size < sizeof(struct ipv6hdr)))
		ft_exit(EXIT_FAILURE, "%s: too small for an IP%s header: %hu bytes",
			__func__, type == ETHERTYPE_IP ? "v4" : "v6", size);
	bytes += cfg->linkhdr_size;
	*iph = type == ETHERTYPE_IP ? E_IH_V4 : E_IH_V6;
	return (bytes);
}

uint8_t			parse_reply_packet(t_task *task, t_nmap_config *cfg,
		t_probe **probe)
{
	enum e_iphdr	iph;
	size_t			size;
	uint8_t			*bytes;
	t_packet		reply = { 0 };
	uint8_t			result = E_STATE_NONE;

	bytes = check_link_layer(task, cfg, &iph, &size);
	init_packet(&reply, iph, (uint8_t *)bytes);
	if (reply.size > size)
	{
		if (cfg->debug)
			debug_invalid_packet(cfg, &reply, "Dropping Invalid Packet");
		ft_exit(EXIT_FAILURE, "%s: packet parsing failure (size)", __func__);
	}
	if ((*probe = get_probe(&reply, cfg)))
	{
		result = scan_result((*probe)->scan_type, &reply);
		if (cfg->verbose)
			verbose_reply(cfg, *probe, &reply, result);
	}
	else if (cfg->debug)
		debug_invalid_packet(cfg, &reply, "Dropping Probeless Packet");
	return (result);
}
