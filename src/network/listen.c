/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   listen.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/30 07:37:42 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/15 15:18:08 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

const char	*g_socket_recv_strings[SOCKET_RECV_COUNT] = {
	[E_SRECV_UDPV4] = "UDPV4",
	[E_SRECV_UDPV6] = "UDPV6",
	[E_SRECV_TCPV4] = "TCPV4",
	[E_SRECV_TCPV6] = "TCPV6",
	[E_SRECV_ICMP_UDPV4] = "ICMP_UDPV4",
	[E_SRECV_ICMP_UDPV6] = "ICMP_UDPV6",
	[E_SRECV_ICMP_TCPV4] = "ICMP_TCPV4",
	[E_SRECV_ICMP_TCPV6] = "ICMP_TCPV6",
	[E_SRECV_STDIN] = "STDIN",
};

static void	socket_handler(int listen_fd, enum e_recv_sockets recv_type,
		struct timeval *reply_time)
{
	int				size;
	char			bytes[MAX_RAW_DATA_SIZE];
	t_task			task = { .type = E_TASK_REPLY };

	if ((size = recv(listen_fd, bytes, MAX_RAW_DATA_SIZE, MSG_DONTWAIT)) < 0)
		ft_exit(EXIT_FAILURE, "%s: recv: %s", __func__, strerror(errno));
	else if (size)
	{
		++g_cfg->received_packet_count;
		ft_memcpy(&task.reply_time, reply_time, sizeof(task.reply_time));
		task.reply = ft_memdup(bytes, size);
		task.reply_size = size;
		task.reply_ip_header = SOCKET_SRECV_IS_IPV4(recv_type) ?
			E_IH_V4 : E_IH_V6;
		push_task(&g_cfg->thread_tasks, g_cfg, &task, 1);
	}
}

static void	pollin_handler(int listen_fd, enum e_recv_sockets recv_type,
		struct timeval *reply_time)
{
	char			buf[1];
	t_task			stats_task = { .type = E_TASK_PRINT_STATS };

	if (recv_type != E_SRECV_STDIN)
		return (socket_handler(listen_fd, recv_type, reply_time));
	if (read(listen_fd, buf, 1) < 0)
		ft_exit(EXIT_FAILURE, "read: %s", strerror(errno));
	push_task(&g_cfg->thread_tasks, g_cfg, &stats_task, 1);
}

int			ft_listen(struct pollfd *listen_fds, int fds_count, int timeout)
{
	struct timeval	reply_time;
	int				reply_count;

	if (!(reply_count = poll(listen_fds, fds_count, timeout)))
		return (reply_count);
	else if (reply_count < 0)
		ft_exit(EXIT_FAILURE, "%s: poll: %s", __func__, strerror(errno));
	if (gettimeofday(&reply_time, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	for (int i = 0; i < fds_count; ++i)
	{
		if (listen_fds[i].revents & (POLLERR | POLLHUP | POLLNVAL))
			ft_exit(EXIT_FAILURE, "%s: received %hu revents on %s socket",
				__func__, listen_fds[i].revents, g_socket_recv_strings[i]);
		else if (listen_fds[i].revents & POLLIN)
			pollin_handler(listen_fds[i].fd, i, &reply_time);
	}
	return (reply_count);
}
