/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sockets.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/30 12:29:57 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/16 16:01:43 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void		close_sockets(t_nmap_config *cfg)
{
	for (int i = 0; i < SOCKET_SEND_COUNT; ++i)
		if (cfg->send_sockets[i] >= 0)
			close(cfg->send_sockets[i]);
	for (int i = 0; i < SOCKET_RECV_COUNT; ++i)
		if (cfg->recv_sockets[i] >= 0)
			close(cfg->recv_sockets[i]);
}

void	init_send_sockets(t_nmap_config *cfg)
{
	int domain, protocol;

	for (int i = 0; i < SOCKET_SEND_COUNT; ++i)
	{
		domain = SOCKET_SSEND_IS_IPV4(i) ? AF_INET : AF_INET6;
		protocol = SOCKET_SSEND_IS_TCP(i) ? IPPROTO_TCP : IPPROTO_UDP;
		if ((cfg->ip_mode == E_IPV6 && domain == AF_INET)
			|| (cfg->ip_mode == E_IPV4 && domain == AF_INET6)
			|| (!cfg->has_tcp_scans && protocol == IPPROTO_TCP)
			|| (!cfg->has_udp_scans && protocol == IPPROTO_UDP))
			continue;
		if ((cfg->send_sockets[i] =
			ft_send_socket_init(domain, protocol, 1)) < 0)
			ft_exit(EXIT_FAILURE, "ft_send_socket_init: %s",
				ft_strerror(ft_errno));
	}
}

void	init_recv_sockets(t_nmap_config *cfg)
{
	int	domain;

	for (int i = 0; i < E_SRECV_STDIN; ++i)
	{
		domain = SOCKET_SRECV_IS_IPV4(i) ? AF_INET : AF_INET6;
		if ((cfg->ip_mode == E_IPV6 && domain == AF_INET)
			|| (cfg->ip_mode == E_IPV4 && domain == AF_INET6)
			|| (!cfg->has_tcp_scans && SOCKET_SRECV_IS_TCP(i))
			|| (!cfg->has_udp_scans && SOCKET_SRECV_IS_UDP(i)))
			continue;
		if ((cfg->recv_sockets[i] = ft_recv_socket_init(domain)) < 0)
			ft_exit(EXIT_FAILURE, "ft_recv_socket_init: %s",
				ft_strerror(ft_errno));
	}
}
