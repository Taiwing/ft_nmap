/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   verbose.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/30 06:17:13 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/30 18:41:30 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	verbose_listener_setup(t_scan *scan, char *filter)
{
	if (scan->cfg->speedup)
		nmap_mutex_lock(&scan->cfg->global_mutex, &g_global_locked);
	ft_putchar('\n');
	if (scan->cfg->speedup)
		ft_printf("Worker Thread %llu (%#llx)\n",
			ft_thread_self(), pthread_self());
	ft_printf("Pcap filter set:\n%s\n", filter);
	if (scan->cfg->speedup)
		nmap_mutex_unlock(&scan->cfg->global_mutex, &g_global_locked);
}

void	verbose_scan(t_scan *scan, uint8_t *probe, int size, const char *action)
{
	if (scan->cfg->speedup)
		nmap_mutex_lock(&scan->cfg->global_mutex, &g_global_locked);
	ft_printf("\n---- Scan type %s on host '%s' port %hu (task %hu/%d) ----\n", 
		g_nmap_scan_strings[scan->type], scan->job->host,
		scan->cfg->ports[scan->task_id], scan->task_id + 1, scan->cfg->nports);
	if (scan->cfg->speedup)
		ft_printf("Worker Thread %llu (%#llx)\n",
			ft_thread_self(), pthread_self());
	ft_printf("%s\n", action);
	print_packet(probe, scan->job->family, size, (char *)scan->cfg->exec);
	if (scan->cfg->speedup)
		nmap_mutex_unlock(&scan->cfg->global_mutex, &g_global_locked);
}
