/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   next_host.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/28 09:02:59 by yforeau           #+#    #+#             */
/*   Updated: 2023/01/27 19:13:21 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

//TODO: pass ip to this function so that it can be loaded directly in adventure mode
static char	*get_target(t_nmap_config *cfg)
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
	/*
	if (!cfg->hosts && !cfg->hosts_file
		&& cfg->adventure_mode != E_ADVENTURE_OFF)
	{
		//TODO: add the needed number of host discovery tasks, one and only one
		// if cfg->speedup == 0 and as much as the max count of hosts we want
		// minus how many we already have in the array if in multithreaded mode

		//TODO: then loop while there's no adventure host available
		// in cfg->speedup == 0 execute --> pseudo_thread_worker(1)
		// and MAYBE print some message that we are looking for a valid random
		// host (TBD)

		//TODO: once a host is found copy the ip to the future ip parameter of
		// the get_target function and strdup a stringified version to ret
	}
	*/
	return (ret);
}

char		*next_host(t_ip *ip, t_nmap_config *cfg)
{
	int		ret;
	char	*target = NULL;
	int		family = cfg->ip_mode == E_IPALL ? AF_UNSPEC
		: cfg->ip_mode == E_IPV4 ? AF_INET : AF_INET6;

	while ((target = get_target(cfg)))
	{
		++cfg->host_count;
		//TODO: reorganize this for when we are in adventure mode (we do not
		// need to ping again or to use ft_get_ip(), actually we can just break)
		if ((ret = ft_get_ip(ip, target, family)))
			ft_dprintf(2, "%s: %s: %s\n", cfg->exec, target, gai_strerror(ret));
		else if (!cfg->ping_scan
			|| !(ret = ping_host_discovery(ip, DEF_PING_COUNT, cfg))
			|| !cfg->skip_non_responsive)
			break;
		ft_memdel((void **)&target);
	}
	return (target);
}
