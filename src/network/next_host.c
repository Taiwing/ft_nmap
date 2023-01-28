/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   next_host.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/28 09:02:59 by yforeau           #+#    #+#             */
/*   Updated: 2023/01/28 17:40:46 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/*
** ping_scan: send 10 probes to check if host is up and estimate rtt
**
** Return 0 if host is up and ready to be scanned, 1 otherwise. Exits on error.
*/
static int	ping_scan(t_ip *ip, t_nmap_config *cfg)
{
	t_scan			scan;
	int				count;
	t_scanres		result;
	struct timeval	timeout = DEF_HOST_DISCOVERY_TIMEOUT;

	if ((scan = ft_echo_ping_open(ip, &timeout)) < 0)
		ft_exit(EXIT_FAILURE, "ft_echo_ping_open: %s", ft_strerror(ft_errno));
	for (count = 0; count < DEF_PING_COUNT; ++count)
	{
		if (ft_echo_ping(&result, scan) < 0)
			ft_exit(EXIT_FAILURE, "ft_echo_ping: %s", ft_strerror(ft_errno));
		if (!result.open)
			break;
		if (!count)
			reset_timeout(cfg, &result.rtt);
		else
			rtt_update_from_instance_rtt(&result.rtt);
	}
	ft_scan_close(scan);
	cfg->host_up += count > 0;
	return (!count);
}

static char	*get_target(t_nmap_config *cfg, t_ip *ip)
{
	char	*ret = NULL;

	if (cfg->hosts && !*cfg->hosts)
		cfg->hosts = NULL;
	else if (cfg->hosts)
		ret = ft_strdup(*cfg->hosts++);
	if (!cfg->hosts && cfg->hosts_file && cfg->hosts_fd < 0
		&& (cfg->hosts_fd = open(cfg->hosts_file, O_RDONLY)) < 0)
		ft_exit(EXIT_FAILURE, "open: %s", strerror(errno));
	else if (!cfg->hosts && cfg->hosts_fd >= 0
		&& get_next_line(cfg->hosts_fd, (char **)&ret) < 0)
		ft_exit(EXIT_FAILURE, "get_next_line: unknown error");
	else if (!cfg->hosts && cfg->hosts_fd >= 0 && !ret)
	{
		cfg->hosts_file = NULL;
		close(cfg->hosts_fd);
		cfg->hosts_fd = -1;
	}
	if (!cfg->hosts && !cfg->hosts_file
		&& cfg->adventure_mode != E_ADVENTURE_OFF)
		ret = adventure(ip, cfg);
	return (ret);
}

char		*next_host(t_ip *ip, t_nmap_config *cfg)
{
	int		ret;
	char	*target = NULL;
	int		family = cfg->ip_mode == E_IPALL ? AF_UNSPEC
		: cfg->ip_mode == E_IPV4 ? AF_INET : AF_INET6;

	while ((target = get_target(cfg, ip)))
	{
		++cfg->host_count;
		if (!cfg->hosts && !cfg->hosts_file
			&& cfg->adventure_mode != E_ADVENTURE_OFF)
			break;
		if ((ret = ft_get_ip(ip, target, family)))
			ft_dprintf(2, "%s: %s: %s\n", cfg->exec, target, gai_strerror(ret));
		else if (!cfg->ping_scan
			|| !(ret = ping_scan(ip, cfg))
			|| !cfg->skip_non_responsive)
			break;
		ft_memdel((void **)&target);
	}
	return (target);
}
