/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   adventure.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/01/27 20:29:52 by yforeau           #+#    #+#             */
/*   Updated: 2023/01/28 14:20:28 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/*
** Send probes to check if a host is up and eventually estimate rtt. Return 0
** if host is up and ready to be scanned, 1 otherwise. Exits on error.
*/
int	ping_adventure(t_ip *ip, unsigned scan_count, t_nmap_config *cfg)
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
int	web_adventure(t_ip *ip)
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

t_ip	*push_adventure_host(t_nmap_config *cfg, t_ip *ip, int prio)
{
	t_ip	*ret = NULL;

	if (prio)
		nmap_mutex_lock(&cfg->adventure_mutex, &g_adventure_locked);
	if (ip && cfg->adventure_host_count < MAX_ADVENTURE_HOSTS)
		ret = ft_memcpy(cfg->adventure_hosts + cfg->adventure_host_count++,
			ip, sizeof(*ip));
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

//TODO: maybe print a message when waiting like a dumbass
char	*adventure(t_ip *adventure_host, t_nmap_config *cfg)
{
	int		task_count;
	t_list	*adventure_tasks = NULL;
	t_task	task = { .type = E_TASK_ADVENTURE };

	//TODO: TOFIX find a way to smoothly pass from this step to scanning
	// because right now the adventure tasks are overflowing the task list
	// and are running ad infinitum while the probe/reply are waiting to be
	// chosen (very big sad).
	cfg->adventure_breakloop = 0;
	task_count = !!cfg->speedup ?
		MAX_ADVENTURE_HOSTS - cfg->adventure_host_count : 1;
	while (task_count--)
		ft_lst_push_front(&adventure_tasks, &task, sizeof(task));
	if (adventure_tasks)
		push_front_tasks(&cfg->thread_tasks,
			adventure_tasks, cfg, cfg->speedup);
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
