/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   probe.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/30 11:58:34 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/15 14:53:34 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void		send_probe(t_nmap_config *cfg, t_probe *probe)
{
	if (sendto(cfg->socket[probe->socket], probe->packet, probe->size, 0,
			(struct sockaddr *)probe->dstip, ip_sock_size(probe->dstip)) < 0)
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

void	build_probe(t_task *task)
{
	uint8_t	version = task->host_job->family == AF_INET ? 4 : 6;
	size_t	ipsz = version == 4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
	t_tcph_args	tcpargs = { .iphdr = task->probe->raw_data, .version = version,
		.srcp = task->srcp, .dstp = task->dstp, .seq = 0x12344321,
		.win = 0xfff };
	t_iph_args	ipargs = { .version = version, .dstip = task->dstip,
		.srcip = task->srcip, .protocol = task->scan_type == E_UDP ?
		IP_HEADER_UDP : IP_HEADER_TCP, .hop_limit = 255, .layer5_len = 0 };

	init_ip_header(task->probe->raw_data, &ipargs);
	if (ipargs.protocol == IP_HEADER_UDP)
		init_udp_header(task->probe->raw_data + ipsz, task->probe->raw_data,
			task->srcp, task->dstp);
	else if (ipargs.protocol == IP_HEADER_TCP)
	{
		set_tcpflags(&tcpargs, task->scan_type);
		init_tcp_header(task->probe->raw_data + ipsz, &tcpargs);
	}
	init_packet(task->probe, version == 4 ? E_IH_V4 : E_IH_V6);
}
