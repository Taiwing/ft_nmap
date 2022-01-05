/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   probe.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/30 11:58:34 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/05 16:33:46 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void		send_probe(t_nmap_config *cfg, t_scan_job *scan_job)
{
	if (sendto(cfg->socket[scan_job->socket], scan_job->packet.raw_data,
		scan_job->packet.size, 0, (struct sockaddr *)scan_job->dstip,
		ip_sock_size(scan_job->dstip)) < 0)
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

void	build_probe_packet(t_scan_job *scan_job, uint8_t version)
{
	size_t	ipsz = version == 4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
	t_tcph_args	tcpargs = { .iphdr = scan_job->packet.raw_data,
		.version = version, .srcp = scan_job->srcp, .dstp = scan_job->dstp,
		.seq = 0x12344321, .win = 0xfff };
	t_iph_args	ipargs = { .version = version, .dstip = scan_job->dstip,
		.srcip = scan_job->srcip, .protocol = scan_job->type == E_UDP ?
		IP_HEADER_UDP : IP_HEADER_TCP, .hop_limit = 255, .layer5_len = 0 };

	init_ip_header(scan_job->packet.raw_data, &ipargs);
	if (ipargs.protocol == IP_HEADER_UDP)
		init_udp_header(scan_job->packet.raw_data + ipsz,
			scan_job->packet.raw_data, scan_job->srcp, scan_job->dstp);
	else if (ipargs.protocol == IP_HEADER_TCP)
	{
		set_tcpflags(&tcpargs, scan_job->type);
		init_tcp_header(scan_job->packet.raw_data + ipsz, &tcpargs);
	}
	init_packet(&scan_job->packet, version == 4 ? E_IH_V4 : E_IH_V6, NULL);
}
