/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   probe.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/30 11:58:34 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/05 20:04:03 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void		send_probe(t_nmap_config *cfg, t_scan_job *scan_job, uint16_t i)
{
	if (cfg->speedup)
		nmap_mutex_lock(&cfg->send_mutex, &g_send_locked);
	if (cfg->sent_packet_count > 0
		&& (cfg->scan_delay.tv_sec || cfg->scan_delay.tv_usec))
		shitty_usleep(&cfg->scan_delay);
	if (sendto(cfg->send_sockets[scan_job->socket],
		scan_job->probes[i]->raw_data, scan_job->probes[i]->size, 0,
		(struct sockaddr *)scan_job->dstip, ip_sock_size(scan_job->dstip)) < 0)
		ft_exit(EXIT_FAILURE, "sendto: %s", strerror(errno));
	++cfg->sent_packet_count;
	if (cfg->speedup)
		nmap_mutex_unlock(&cfg->send_mutex, &g_send_locked);
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

static void	init_layer4_header(t_packet *dest, uint16_t protocol,
		uint8_t version, t_scan_job *scan_job)
{
	size_t	ipsz = version == 4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
	t_tcph_args	tcpargs = { .iphdr = dest->raw_data, .version = version,
		.srcp = scan_job->srcp, .dstp = scan_job->dstp, .seq = 0x12344321,
		.win = 0xfff };

	if (protocol == IP_HEADER_UDP)
		init_udp_header(dest->raw_data + ipsz, dest->raw_data,
			scan_job->srcp, scan_job->dstp);
	else if (protocol == IP_HEADER_TCP)
	{
		set_tcpflags(&tcpargs, scan_job->type);
		init_tcp_header(dest->raw_data + ipsz, &tcpargs);
	}
}

void	build_probe_packet(t_packet *dest, t_scan_job *scan_job,
		uint8_t *layer5, uint16_t l5_len)
{
	uint8_t	version = scan_job->srcip->family == AF_INET ? 4 : 6;
	t_iph_args	ipargs = { .version = version, .dstip = scan_job->dstip,
		.srcip = scan_job->srcip, .protocol = scan_job->type == E_UDP ?
		IP_HEADER_UDP : IP_HEADER_TCP, .hop_limit = 255, .layer5_len = l5_len };

	init_ip_header(dest->raw_data, &ipargs);
	if (layer5 && l5_len && (ipargs.protocol == IP_HEADER_TCP
		|| ipargs.protocol == IP_HEADER_UDP))
		ft_memcpy(dest->raw_data
			+ (version == 4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr))
			+ (ipargs.protocol == IP_HEADER_TCP ? sizeof(struct tcphdr)
			: sizeof(struct udphdr)), layer5, l5_len);
	init_layer4_header(dest, ipargs.protocol, version, scan_job);
	init_packet(dest, version == 4 ? E_IH_V4 : E_IH_V6, NULL);
}
