/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   probe.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/30 11:58:34 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/18 16:54:06 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void		send_probe(t_nmap_config *cfg, t_probe *probe)
{
	if (sendto(cfg->socket[probe->socket], probe->packet.raw_data,
		probe->packet.size, 0, (struct sockaddr *)probe->dstip,
		ip_sock_size(probe->dstip)) < 0)
		ft_exit(EXIT_FAILURE, "sendto: %s", strerror(errno));
}

static void	set_tcpflags(t_tcph_args *args, enum e_scans scan)
{
	uint8_t	flags;

	switch (scan)
	{
		case E_SYN: flags = TH_SYN;							break;
		case E_NULL: flags = 0;								break;
		case E_ACK: flags = TH_ACK;							break;
		case E_FIN: flags = TH_FIN;							break;
		case E_XMAS: flags = TH_FIN | TH_PUSH | TH_URG;		break;
		default: flags = 0;
	}
	args->flags = flags;
}

void	build_probe_packet(t_probe *probe, uint8_t version)
{
	size_t	ipsz = version == 4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
	t_tcph_args	tcpargs = { .iphdr = probe->packet.raw_data, .version = version,
		.srcp = probe->srcp, .dstp = probe->dstp, .seq = 0x12344321,
		.win = 0xfff };
	t_iph_args	ipargs = { .version = version, .dstip = probe->dstip,
		.srcip = probe->srcip, .protocol = probe->scan_type == E_UDP ?
		IP_HEADER_UDP : IP_HEADER_TCP, .hop_limit = 255, .layer5_len = 0 };

	init_ip_header(probe->packet.raw_data, &ipargs);
	if (ipargs.protocol == IP_HEADER_UDP)
		init_udp_header(probe->packet.raw_data + ipsz, probe->packet.raw_data,
			probe->srcp, probe->dstp);
	else if (ipargs.protocol == IP_HEADER_TCP)
	{
		set_tcpflags(&tcpargs, probe->scan_type);
		init_tcp_header(probe->packet.raw_data + ipsz, &tcpargs);
	}
	init_packet(&probe->packet, version == 4 ? E_IH_V4 : E_IH_V6, NULL);
}
