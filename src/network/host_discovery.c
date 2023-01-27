/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   host_discovery.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/01/27 18:54:37 by yforeau           #+#    #+#             */
/*   Updated: 2023/01/27 19:38:32 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/*
** Send probes to check if a host is up and eventually estimate rtt. Return 0
** if host is up and ready to be scanned, 1 otherwise. Exits on error.
*/
int	ping_host_discovery(t_ip *ip, unsigned scan_count, t_nmap_config *cfg)
{
	t_scan			scan;
	unsigned		count;
	t_scanres		result;
	struct timeval	timeout = DEF_HOST_DISCOVERY_TIMEOUT;

	if ((scan = ft_echo_ping_open(ip, &timeout)) < 0)
		ft_exit(EXIT_FAILURE, "ft_echo_ping_open: %s", ft_strerror(ft_errno));
	for (count = 0; count < scan_count; ++count)
	{
		if (ft_echo_ping(&result, scan) < 0)
			ft_exit(EXIT_FAILURE, "ft_echo_ping: %s", ft_strerror(ft_errno));
		if (!result.open)
			break;
		if (!count && cfg)
			reset_timeout(cfg, &result.rtt);
		else if (cfg)
			rtt_update_from_instance_rtt(&result.rtt);
	}
	ft_scan_close(scan);
	if (cfg)
		cfg->host_up += count > 0;
	return (!count);
}

/*
** Send TCP probes to check if the host is up and is a website. Return 0 if host
** is up and ready to be scanned, 1 otherwise. Exits on error.
*/
int	web_host_discovery(t_ip *ip)
{
	t_scan			scan;
	t_scanres		result;
	struct timeval	timeout = DEF_HOST_DISCOVERY_TIMEOUT;

	if ((scan = ft_tcp_syn_open(ip, 80, &timeout)) < 0)
		ft_exit(EXIT_FAILURE, "ft_tcp_syn_open: %s", ft_strerror(ft_errno));
	else if (ft_tcp_syn(&result, scan) < 0)
		ft_exit(EXIT_FAILURE, "ft_tcp_syn: %s", ft_strerror(ft_errno));
	ft_scan_close(scan);
	if (!result.open)
		return (1);
	if ((scan = ft_tcp_syn_open(ip, 443, &timeout)) < 0)
		ft_exit(EXIT_FAILURE, "ft_tcp_syn_open: %s", ft_strerror(ft_errno));
	else if (ft_tcp_syn(&result, scan) < 0)
		ft_exit(EXIT_FAILURE, "ft_tcp_syn: %s", ft_strerror(ft_errno));
	ft_scan_close(scan);
	return (!result.open);
}
