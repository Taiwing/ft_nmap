/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_result.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/31 21:04:12 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/05 16:27:09 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static uint8_t	parse_icmp_reply(t_packet *reply, int is_udp)
{
	uint8_t	code;

	if (reply->nexthdr == E_NH_ICMP
		&& reply->next->icmp.type == ICMP_DEST_UNREACH)
	{
		if ((code = reply->next->icmp.code) == ICMP_PORT_UNREACH)
			return (is_udp ? E_STATE_CLOSED : E_STATE_FILTERED);
		else if (code <= 2 || code == 9 || code == 10 || code == 13)
			return (E_STATE_FILTERED);
	}
	else if (reply->nexthdr == E_NH_ICMP6
		&& reply->next->icmp6.icmp6_type == ICMPV6_DEST_UNREACH)
	{
		if ((code = reply->next->icmp6.icmp6_code) == ICMPV6_PORT_UNREACH)
			return (is_udp ? E_STATE_CLOSED : E_STATE_FILTERED);
		else if (code <= 3)
			return (E_STATE_FILTERED);
	}
	return (E_STATE_NONE);
}

static uint8_t	scan_syn_res(t_packet *reply)
{
	if (!reply)
		return (E_STATE_FILTERED);
	else if (reply->nexthdr == E_NH_TCP)
	{
		if (reply->next->tcp.th_flags == TH_SYN
			|| reply->next->tcp.th_flags == (TH_SYN | TH_ACK))
			return (E_STATE_OPEN);
		else if (reply->next->tcp.th_flags & TH_RST)
			return (E_STATE_CLOSED);
	}
	return (parse_icmp_reply(reply, 0));
}

static uint8_t	scan_udp_res(t_packet *reply)
{
	if (!reply)
		return (E_STATE_OPEN | E_STATE_FILTERED);
	else if (reply->nexthdr == E_NH_UDP)
		return (E_STATE_OPEN);
	return (parse_icmp_reply(reply, 1));
}

static uint8_t	scan_ack_res(t_packet *reply)
{
	if (!reply)
		return (E_STATE_FILTERED);
	else if (reply->nexthdr == E_NH_TCP && reply->next->tcp.th_flags & TH_RST)
		return (E_STATE_UNFILTERED);
	return (parse_icmp_reply(reply, 0));
}

static uint8_t	scan_nfx_res(t_packet *reply)
{
	if (!reply)
		return (E_STATE_OPEN | E_STATE_FILTERED);
	else if (reply->nexthdr == E_NH_TCP && reply->next->tcp.th_flags & TH_RST)
		return (E_STATE_CLOSED);
	return (parse_icmp_reply(reply, 0));
}

uint8_t			scan_result(enum e_scans type, t_packet *reply)
{
	uint8_t	result;

	switch (type)
	{
		case E_SYN: result = scan_syn_res(reply);				break;
		case E_UDP: result = scan_udp_res(reply);				break;
		case E_ACK: result = scan_ack_res(reply);				break;
		case E_NULL:
		case E_FIN:
		case E_XMAS: result = scan_nfx_res(reply);				break;
	}
	return (result);
}
