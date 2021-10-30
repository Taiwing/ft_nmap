/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   alarm_tick.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/30 14:37:03 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/30 15:18:21 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <signal.h>
#include "ft_nmap.h"

static void	alarm_tick(int sig)
{
	int		i = 0;
	t_probe	*probe = g_cfg->probe;

	(void)sig;
	ft_printf("-----> Hello! <-----\n"); //TEMP
	if (g_cfg->speedup)
		nmap_mutex_lock(&g_cfg->probe_mutex, &g_probe_locked);
	do {
		if (probe[i].is_ready && probe[i].retry++ < MAX_RETRY)
			send_probe(g_cfg, probe + i);
		else if (probe[i].is_ready)
		{
			//pcap_breakloop(probe[i].descr); //TODO: when we actually loop
			ft_bzero(probe + i, sizeof(t_probe));
		}
	} while (++i < g_cfg->speedup);
	if (g_cfg->speedup)
		nmap_mutex_unlock(&g_cfg->probe_mutex, &g_probe_locked);
	alarm(1);
}

void	set_alarm_tick(void)
{
	struct sigaction	act = { .sa_handler = alarm_tick, .sa_flags = 0 };

	if (sigemptyset(&act.sa_mask) < 0)
		ft_exit(EXIT_FAILURE, "sigemptyset: %s", strerror(errno));
	if (sigaction(SIGALRM, &act, NULL) < 0)
		ft_exit(EXIT_FAILURE, "sigaction: %s", strerror(errno));
	alarm(1);
}
