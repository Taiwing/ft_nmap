/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   adventure.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/01/27 20:29:52 by yforeau           #+#    #+#             */
/*   Updated: 2023/01/28 20:40:40 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

t_ip	*push_adventure_hosts(t_nmap_config *cfg, t_ip *ip,
	size_t count, int prio)
{
	t_ip	*ret = NULL;
	size_t	room_left = 0;

	if (prio)
		nmap_mutex_lock(&cfg->adventure_mutex, &g_adventure_locked);
	if (ip && cfg->adventure_host_count < MAX_ADVENTURE_HOSTS)
	{
		room_left = MAX_ADVENTURE_HOSTS - cfg->adventure_host_count;
		count = count > room_left ? room_left : count;
		ret = ft_memcpy(cfg->adventure_hosts + cfg->adventure_host_count,
			ip, count * sizeof(*ip));
		cfg->adventure_host_count += count;
	}
	if (prio)
		nmap_mutex_unlock(&cfg->adventure_mutex, &g_adventure_locked);
	return (ret);
}

t_ip	*pop_adventure_host(t_ip *dest, t_nmap_config *cfg, int prio)
{
	t_ip	*ret = NULL;

	if (prio)
		nmap_mutex_lock(&cfg->adventure_mutex, &g_adventure_locked);
	if (dest && cfg->adventure_host_count > 0)
		ret = ft_memcpy(dest,
			cfg->adventure_hosts + --cfg->adventure_host_count, sizeof(*dest));
	if (prio)
		nmap_mutex_unlock(&cfg->adventure_mutex, &g_adventure_locked);
	return (ret);
}

// Share of total thread count that should be allocated to finding hosts
#define	ADVENTURE_THREAD_SHARE		3
// Minimum count of adventure threads
#define	ADVENTURE_THREAD_COUNT_MIN	1

//TODO: maybe print a message when waiting like a dumbass
char	*adventure(t_ip *adventure_host, t_nmap_config *cfg)
{
	t_task	adventure_task = { .type = E_TASK_ADVENTURE };

	cfg->adventure_breakloop = 0;
	push_task(&cfg->thread_tasks, cfg, &adventure_task, 1);
	while (!cfg->adventure_host_count && !cfg->end)
		if (!cfg->speedup)
			pseudo_thread_worker(1);
	if (pop_adventure_host(adventure_host, cfg, !!cfg->speedup))
	{
		++cfg->host_up;
		return (ft_strdup(ft_ip_str(adventure_host)));
	}
	return (NULL);
}
