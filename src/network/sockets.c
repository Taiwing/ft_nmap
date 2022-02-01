/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sockets.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/30 12:29:57 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/01 20:38:18 by yforeau          ###   ########.fr       */
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

/*
** This filter simply drops every packet. This is set immediately after the
** socket is created so that we can drain the socket before setting the real
** filter we want to set. This makes sure no invalid packet will make it through
** to the packet parsing part of the program. Also, filter switching is done
** atomically which means that there will be no overlap or gap between the
** different filters set during the program's execution.
**
** source: https://natanyellin.com/posts/ebpf-filtering-done-right/
*/
struct sock_filter		g_zero_filter[] = {{ 0x06, 0, 0, 0 }};
const struct sock_fprog	g_zero_bpf = { .len = 1, .filter = g_zero_filter };

static int	init_recv_socket(int domain)
{
	int		sfd;
	char	drain[1];
	int		socket_protocol = domain == AF_INET ? ETH_P_IP : ETH_P_IPV6;

	if ((sfd = socket(AF_PACKET, SOCK_DGRAM, htons(socket_protocol))) < 0)
		ft_exit(EXIT_FAILURE, "socket: %s", strerror(errno));
	if (setsockopt(sfd, SOL_SOCKET, SO_ATTACH_FILTER,
			&g_zero_bpf, sizeof(g_zero_bpf)) < 0)
		ft_exit(EXIT_FAILURE, "%s: setsockopt: %s", __func__, strerror(errno));
	while (recv(sfd, drain, sizeof(drain), MSG_DONTWAIT) >= 0);
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
