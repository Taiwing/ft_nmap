/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   timeout.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/13 12:54:55 by yforeau           #+#    #+#             */
/*   Updated: 2022/03/06 12:38:44 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	reset_timeout(t_nmap_config *cfg, struct timeval *init)
{
	if (!init)
		init = &cfg->rtt.initial_timeout;
	ft_memcpy(&cfg->rtt.timeout, init, sizeof(cfg->rtt.timeout));
	ft_memcpy(&cfg->rtt.smoothed, init, sizeof(cfg->rtt.smoothed));
	ft_bzero(&cfg->rtt.variance, sizeof(cfg->rtt.variance));
}

void	probe_timeout(struct timeval *sent_ts, struct timeval *timeout_ts)
{
	if (g_cfg->speedup)
		nmap_mutex_lock(&g_cfg->rtt_mutex, &g_rtt_locked);
	if (gettimeofday(sent_ts, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	if (ft_timeval_add(timeout_ts, sent_ts, &g_cfg->rtt.timeout) < 0)
		ft_exit(EXIT_FAILURE, "ft_timeval_add: %s", ft_strerror(ft_errno));
	if (g_cfg->speedup)
		nmap_mutex_unlock(&g_cfg->rtt_mutex, &g_rtt_locked);
}
