/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sockets.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/30 12:29:57 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/15 10:35:34 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static int	init_socket(int domain, int protocol)
{
	int	sfd, one, ret;

	one = 1;
	if ((sfd = socket(domain, SOCK_RAW, protocol)) < 0)
		ft_exit(EXIT_FAILURE, "socket: %s", strerror(errno));
	ret = -2;
	if (domain == AF_INET)
		ret = setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(int));
	else if (domain == AF_INET6)
		ret = setsockopt(sfd, IPPROTO_IPV6, IPV6_HDRINCL, &one, sizeof(int));
	if (ret < 0)
		close(sfd);
	if (ret == -2)
		ft_exit(EXIT_FAILURE, "%s: domain must be AF_INET or AF_INET6\n",
			__func__);
	else if (ret < 0)
		ft_exit(EXIT_FAILURE, "setsockopt: %s\n", strerror(errno));
	return (sfd);
}

void		close_sockets(t_nmap_config *cfg)
{
	for (int i = 0; i < SOCKET_COUNT; ++i)
		if (cfg->socket[i] >= 0)
			close(cfg->socket[i]);
}

void		init_sockets(t_nmap_config *cfg)
{
	int	has_udp_scans = cfg->scans[E_UDP];
	int has_tcp_scans = !!(cfg->nscans - has_udp_scans);

	if (cfg->ip_mode != E_IPV6)
	{
		if (has_udp_scans)
			cfg->socket[E_UDPV4] = init_socket(AF_INET, IPPROTO_UDP);
		if (has_tcp_scans)
			cfg->socket[E_TCPV4] = init_socket(AF_INET, IPPROTO_TCP);
	}
	if (cfg->ip_mode != E_IPV4)
	{
		if (has_udp_scans)
			cfg->socket[E_UDPV6] = init_socket(AF_INET6, IPPROTO_UDP);
		if (has_tcp_scans)
			cfg->socket[E_TCPV6] = init_socket(AF_INET6, IPPROTO_TCP);
	}
}
