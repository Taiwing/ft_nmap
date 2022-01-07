/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   next_host.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/28 09:02:59 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/07 15:36:14 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

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
	return (ret);
}

char		*next_host(t_ip *ip, t_nmap_config *cfg)
{
	char	*target = NULL;

	while ((target = get_target(cfg)))
	{
		++cfg->host_count;
		if (!get_destinfo(ip, target, cfg))
			break ;
		ft_memdel((void **)&target);
	}
	return (target);
}
