/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   probe.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/30 11:58:34 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/30 15:22:11 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void		send_probe(t_nmap_config *cfg, t_probe *probe)
{
	if (sendto(cfg->socket[probe->socket], probe->packet, probe->size, 0,
			(struct sockaddr *)probe->ip, ip_sock_size(probe->ip)) < 0)
		ft_exit(EXIT_FAILURE, "sendto: %s", strerror(errno));
}

void		share_probe(t_scan *scan, size_t size)
{
	uint64_t		thread = ft_thread_self();
	t_ip			*ip = &scan->job->host_ip;
	int				tcp = scan->type != E_UDP;
	t_probe			*probe = scan->cfg->probe + thread - !!thread;
	enum e_sockets	socket = (ip->family == AF_INET ? E_UDPV4 : E_UDPV6) + tcp;

	if (scan->cfg->speedup)
		nmap_mutex_lock(&g_cfg->probe_mutex, &g_probe_locked);
	probe->ip = ip;
	probe->size = size;
	probe->packet = scan->probe;
	probe->socket = socket;
	probe->descr = scan->descr;
	probe->retry = 0;
	probe->is_ready = 1;
	if (scan->cfg->speedup)
		nmap_mutex_unlock(&g_cfg->probe_mutex, &g_probe_locked);
}

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
