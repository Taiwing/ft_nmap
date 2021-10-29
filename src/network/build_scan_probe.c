/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   build_scan_probe.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/29 19:11:15 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/29 20:34:14 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static int	set_tcpflags(t_tcph_args *args, enum e_scans scan)
{
	uint8_t	flags;

	switch (scan)
	{
		case E_SYN: flags = TH_SYN;							break;
		case E_NULL: flags = 0;								break;
		case E_ACK: flags = TH_ACK;							break;
		case E_FIN: flags = TH_FIN;							break;
		case E_XMAS: flags = TH_FIN | TH_PUSH | TH_URG;		break;
		default: return (1);
	}
	args->flags = flags;
	return (0);
}

int	build_scan_probe(uint8_t *dest, t_scan *scan, uint16_t srcp, uint16_t dstp)
{
	uint8_t	iphdr[IPHDR_MAXSIZE] = { 0 };
	uint8_t	layer4hdr[LAYER4HDR_MAXSIZE] = { 0 };
	uint8_t	version = scan->job->host_ip.family == AF_INET ? 4 : 6;
	t_tcph_args	tcpargs = { .iphdr = iphdr, .version = version, .srcp = srcp,
		.dstp = dstp, .seq = 0x12344321, .win = 0xfff };
	t_iph_args	ipargs = { .version = version, .dstip = &scan->job->host_ip,
		.srcip = version == 4 ? &scan->cfg->netinf.defdev_v4->ip : 
		&scan->cfg->netinf.defdev_v6->ip, .protocol = scan->type == E_UDP ?
		IP_HEADER_UDP : IP_HEADER_TCP, .hop_limit = 255, .layer5_len = 0 };
	int		ipsz = version == 4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
	int		l4sz = ipargs.protocol == IP_HEADER_UDP ?
		sizeof(struct udphdr) : sizeof(struct tcphdr);

	if (init_ip_header(iphdr, &ipargs))
		return (-1);
	if (ipargs.protocol == IP_HEADER_UDP
		&& init_udp_header(layer4hdr, iphdr, srcp, dstp))
		return (-1);
	if (ipargs.protocol == IP_HEADER_TCP && (set_tcpflags(&tcpargs, scan->type)
		|| init_tcp_header(layer4hdr, &tcpargs)))
		return (-1);
	ft_memcpy(dest, iphdr, ipsz);
	ft_memcpy(dest + ipsz, layer4hdr, l4sz);
	return (ipsz + l4sz);
}
