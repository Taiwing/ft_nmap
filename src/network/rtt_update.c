/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rtt_update.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/06 11:10:58 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/18 19:40:07 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	rtt_variance(struct timeval *instance_rtt)
{
	struct timeval	tmp;

	if (ft_timeval_sub(&tmp, instance_rtt, &g_cfg->rtt.smoothed) < 0)
		ft_exit(EXIT_FAILURE, "ft_timeval_sub: %s", ft_strerror(ft_errno));
	if (ft_timeval_abs(&tmp, &tmp) < 0)
		ft_exit(EXIT_FAILURE, "ft_timeval_abs: %s", ft_strerror(ft_errno));
	if (ft_timeval_sub(&tmp, &tmp, &g_cfg->rtt.variance) < 0)
		ft_exit(EXIT_FAILURE, "ft_timeval_sub: %s", ft_strerror(ft_errno));
	if (ft_timeval_div(&tmp, &tmp, 4) < 0)
		ft_exit(EXIT_FAILURE, "ft_timeval_div: %s", ft_strerror(ft_errno));
	if (ft_timeval_add(&g_cfg->rtt.variance, &g_cfg->rtt.variance, &tmp) < 0)
		ft_exit(EXIT_FAILURE, "ft_timeval_add: %s", ft_strerror(ft_errno));
}

static void	rtt_smoothed(struct timeval *instance_rtt)
{
	struct timeval	tmp;

	if (ft_timeval_sub(&tmp, instance_rtt, &g_cfg->rtt.smoothed) < 0)
		ft_exit(EXIT_FAILURE, "ft_timeval_sub: %s", ft_strerror(ft_errno));
	if (ft_timeval_div(&tmp, &tmp, 8) < 0)
		ft_exit(EXIT_FAILURE, "ft_timeval_div: %s", ft_strerror(ft_errno));
	if (ft_timeval_add(&g_cfg->rtt.smoothed, &g_cfg->rtt.smoothed, &tmp) < 0)
		ft_exit(EXIT_FAILURE, "ft_timeval_sub: %s", ft_strerror(ft_errno));
}

static void	rtt_timeout(void)
{
	struct timeval	tmp;

	if (ft_timeval_mul(&tmp, &g_cfg->rtt.variance, 4) < 0)
		ft_exit(EXIT_FAILURE, "ft_timeval_mul: %s", ft_strerror(ft_errno));
	if (ft_timeval_add(&g_cfg->rtt.timeout, &g_cfg->rtt.smoothed, &tmp) < 0)
		ft_exit(EXIT_FAILURE, "ft_timeval_add: %s", ft_strerror(ft_errno));
	if (ft_timeval_cmp(&g_cfg->rtt.timeout, &g_cfg->rtt.min_timeout) < 0)
		ft_memcpy(&g_cfg->rtt.timeout, &g_cfg->rtt.min_timeout,
			sizeof(g_cfg->rtt.timeout));
	else if (ft_timeval_cmp(&g_cfg->rtt.timeout, &g_cfg->rtt.max_timeout) > 0)
		ft_memcpy(&g_cfg->rtt.timeout, &g_cfg->rtt.max_timeout,
			sizeof(g_cfg->rtt.timeout));
}

/*
** Implement orginal nmap's RTT timeout computation algorithm described here:
** https://nmap.org/book/port-scanning-algorithms.html
** It is itself based on the TCP protocol's timeout system.
*/
void	rtt_update(struct timeval *sent, struct timeval *received)
{
	struct timeval	instance_rtt;

	if (g_cfg->speedup)
		nmap_mutex_lock(&g_cfg->rtt_mutex, &g_rtt_locked);
	if (ft_timeval_sub(&instance_rtt, received, sent) < 0)
		ft_exit(EXIT_FAILURE, "ft_timeval_sub: %s", ft_strerror(ft_errno));
	rtt_variance(&instance_rtt);
	rtt_smoothed(&instance_rtt);
	rtt_timeout();
	if (g_cfg->speedup)
		nmap_mutex_unlock(&g_cfg->rtt_mutex, &g_rtt_locked);
}
