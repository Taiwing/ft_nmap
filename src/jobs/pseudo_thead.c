/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pseudo_thead.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/21 18:04:59 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/22 10:01:46 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	pseudo_thread_worker(void)
{
	t_worker_config	wcfg = {
		.type = E_WORKER_PSEUDO_THREAD,
		.task_list = &g_cfg->thread_tasks,
		.task_types = WORKER_TASKS,
	};

	if (gettimeofday(&wcfg.expiry, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	wcfg.expiry.tv_sec += g_cfg->max_rtt_timeout.tv_sec / 10;
	wcfg.expiry.tv_usec += (g_cfg->max_rtt_timeout.tv_nsec / 1000) / 10;
	worker(&wcfg);
}
