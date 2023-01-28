/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   group_scan.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/01/28 17:35:56 by yforeau           #+#    #+#             */
/*   Updated: 2023/01/28 17:47:25 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static t_scan	open_scan(t_ip *ip, struct timeval *timeout,
	enum e_ftscan_type scan_type, uint16_t port)
{
	t_scan	scan;

	switch (scan_type)
	{
		case E_FTSCAN_ECHO_PING:
			if ((scan = ft_echo_ping_open(ip, timeout)) < 0)
				ft_exit(EXIT_FAILURE, "ft_echo_ping_open: %s",
					ft_strerror(ft_errno));
			break;
		case E_FTSCAN_TCP_SYN:
			if ((scan = ft_tcp_syn_open(ip, port, timeout)) < 0)
				ft_exit(EXIT_FAILURE, "ft_tcp_syn_open: %s",
					ft_strerror(ft_errno));
			break;
		default:
			ft_exit(EXIT_FAILURE, "impossible error");
			break;
	}
	return (scan);
}

static void		close_scan_group(t_pollsc *scans, size_t count)
{
	for (size_t i = 0; i < count; ++i)
		ft_scan_close(scans[i].scan);
}

static void		send_probe_group(t_pollsc *scans, size_t count)
{
	for (size_t i = 0; i < count; ++i)
		if (ft_scan_send(scans[i].scan) < 0)
			ft_exit(EXIT_FAILURE, "ft_scan_send: %s", ft_strerror(ft_errno));
}

#define	SCAN_CLOSE	-1
#define	SCAN_OPEN	1

static int		group_is_done(int *done, t_pollsc *scans, size_t count)
{
	size_t		done_count = 0;
	t_scanres	result = { 0 };

	for (size_t i = 0; i < count; ++i)
	{
		if (scans[i].events || done[i])
			++done_count;
		if (!scans[i].events || done[i])
			continue;
		if (ft_scan_result(&result, scans[i].scan) < 0)
			ft_exit(EXIT_FAILURE, "ft_scan_result: %s", ft_strerror(ft_errno));
		done[i] = result.open ? SCAN_OPEN : SCAN_CLOSE;
		ft_scan_close(scans[i].scan);
		scans[i].scan *= -1;
	}
	return (done_count == count);
}

/*
** group_results: move every open host at the beginning of the group array and
** return their count
*/
static size_t	group_results(int *done, t_ip *group, size_t count)
{
	size_t	open = 0;

	for (size_t i = 0; i < count; ++i)
	{
		if (done[i] == SCAN_CLOSE)
			continue;
		if (i != open)
			ft_memcpy(group + open, group + i, sizeof(*group));
		++open;
	}
	return (open);
}

#define	GROUP_SIZE_MAX	256

/*
** group_scan: takes an ip array and execute the same scan on all of them
**
** group: is both the input and the result, ips on which the scan will have
** returned and 'open' status will be put at the start of the array
** count: number of ips to scan (size of group)
** timeout: time to wait for a response
** type: type of scan
** port: port if tcp scan
**
** Returns the number of open ips contained in group, or -1 on error.
*/
size_t			group_scan(t_ip *group, size_t count, struct timeval *timeout,
	enum e_ftscan_type type, uint16_t port)
{
	int			ret = 0;
	int			done[GROUP_SIZE_MAX] = { 0 };
	t_pollsc	scans[GROUP_SIZE_MAX] = { 0 };

	if (!group || !count)
		return (0);
	if (count > GROUP_SIZE_MAX)
		ft_exit(EXIT_FAILURE, "count is bigger than max group size %d\n",
			GROUP_SIZE_MAX);
	for (size_t i = 0; i < count; ++i)
		scans[i].scan = open_scan(group + i, timeout, type, port);
	send_probe_group(scans, count);
	while (!g_cfg->end && !g_cfg->adventure_breakloop
		&& (ret = ft_scan_poll(scans, count, NULL)) >= 0)
	{
		if (!ret) continue;
		else if (group_is_done(done, scans, count))
			return (group_results(done, group, count));
	}
	if (ret < 0)
		ft_exit(EXIT_FAILURE, "ft_scan_poll: %s", ft_strerror(ft_errno));
	close_scan_group(scans, count);
	return (0);
}
