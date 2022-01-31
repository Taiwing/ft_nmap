/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sockets.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/30 12:29:57 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/31 06:52:26 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static int	init_send_socket(int domain, int protocol)
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

static int	init_recv_socket(int domain)
{
	int	sfd;
	int	socket_protocol = domain == AF_INET ? ETH_P_IP : ETH_P_IPV6;

	if ((sfd = socket(AF_PACKET, SOCK_DGRAM, htons(socket_protocol))) < 0)
		ft_exit(EXIT_FAILURE, "socket: %s", strerror(errno));
	return (sfd);
}

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
	if (cfg->ip_mode != E_IPV6)
	{
		if (cfg->has_udp_scans)
			cfg->send_sockets[E_SSEND_UDPV4] =
				init_send_socket(AF_INET, IPPROTO_UDP);
		if (cfg->has_tcp_scans)
			cfg->send_sockets[E_SSEND_TCPV4] =
				init_send_socket(AF_INET, IPPROTO_TCP);
	}
	if (cfg->ip_mode != E_IPV4)
	{
		if (cfg->has_udp_scans)
			cfg->send_sockets[E_SSEND_UDPV6] =
				init_send_socket(AF_INET6, IPPROTO_UDP);
		if (cfg->has_tcp_scans)
			cfg->send_sockets[E_SSEND_TCPV6] =
				init_send_socket(AF_INET6, IPPROTO_TCP);
	}
}

void	init_recv_sockets(t_nmap_config *cfg)
{
	if (cfg->ip_mode != E_IPV6)
	{
		if (cfg->has_udp_scans)
			cfg->recv_sockets[E_SRECV_UDPV4] = init_recv_socket(AF_INET);
		if (cfg->has_udp_scans)
			cfg->recv_sockets[E_SRECV_ICMP_UDPV4] = init_recv_socket(AF_INET);
		if (cfg->has_tcp_scans)
			cfg->recv_sockets[E_SRECV_TCPV4] = init_recv_socket(AF_INET);
		if (cfg->has_tcp_scans)
			cfg->recv_sockets[E_SRECV_ICMP_TCPV4] = init_recv_socket(AF_INET);
	}
	if (cfg->ip_mode != E_IPV4)
	{
		if (cfg->has_udp_scans)
			cfg->recv_sockets[E_SRECV_UDPV6] = init_recv_socket(AF_INET6);
		if (cfg->has_udp_scans)
			cfg->recv_sockets[E_SRECV_ICMP_UDPV6] = init_recv_socket(AF_INET6);
		if (cfg->has_tcp_scans)
			cfg->recv_sockets[E_SRECV_TCPV6] = init_recv_socket(AF_INET6);
		if (cfg->has_tcp_scans)
			cfg->recv_sockets[E_SRECV_ICMP_TCPV6] = init_recv_socket(AF_INET6);
	}
}
