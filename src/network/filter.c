/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   filter.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/18 08:01:16 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/16 07:28:15 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	filter_icmp(enum e_recv_sockets socket_type, t_nmap_config *cfg)
{
	t_filter_spec	spec = {
		.icmp_protocol = SOCKET_SRECV_IS_UDP(socket_type) ?
			IPPROTO_UDP : IPPROTO_TCP,
		.src = &cfg->host_job.ip,
		.dst = &cfg->host_job.dev->ip,
		.min_src_port = PORT_DEF,
		.max_src_port = PORT_DEF + cfg->total_scan_count - 1,
		.min_dst_port = cfg->ports[0],
		.max_dst_port = cfg->ports[cfg->nports - 1],
	};

	if (ft_packet_filter_icmp_layer4(cfg->recv_sockets[socket_type], &spec) < 0)
		ft_exit(EXIT_FAILURE, "ft_packet_filter_icmp_layer4: %s",
			ft_strerror(ft_errno));
}

static void	filter_layer4(enum e_recv_sockets socket_type, t_nmap_config *cfg)
{
	t_filter_spec	spec = {
		.protocol = SOCKET_SRECV_IS_UDP(socket_type) ?
			IPPROTO_UDP : IPPROTO_TCP,
		.src = &cfg->host_job.ip,
		.dst = &cfg->host_job.dev->ip,
		.min_src_port = cfg->ports[0],
		.max_src_port = cfg->ports[cfg->nports - 1],
		.min_dst_port = PORT_DEF,
		.max_dst_port = PORT_DEF + cfg->total_scan_count - 1,
	};

	if (ft_packet_filter_layer4(cfg->recv_sockets[socket_type], &spec) < 0)
		ft_exit(EXIT_FAILURE, "ft_packet_filter_layer4: %s",
			ft_strerror(ft_errno));
}

void		set_filters(t_nmap_config *cfg)
{
	uint16_t	family = cfg->host_job.family;

	if (family == AF_INET && cfg->has_udp_scans)
	{
		filter_layer4(E_SRECV_UDPV4, cfg);
		filter_icmp(E_SRECV_ICMP_UDPV4, cfg);
	}
	if (family == AF_INET && cfg->has_tcp_scans)
	{
		filter_layer4(E_SRECV_TCPV4, cfg);
		filter_icmp(E_SRECV_ICMP_TCPV4, cfg);
	}
	if (family == AF_INET6 && cfg->has_udp_scans)
	{
		filter_layer4(E_SRECV_UDPV6, cfg);
		filter_icmp(E_SRECV_ICMP_UDPV6, cfg);
	}
	if (family == AF_INET6 && cfg->has_tcp_scans)
	{
		filter_layer4(E_SRECV_TCPV6, cfg);
		filter_icmp(E_SRECV_ICMP_TCPV6, cfg);
	}
}
