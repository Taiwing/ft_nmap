/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pseudo_thead.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/21 18:04:59 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/21 18:06:03 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	pseudo_thread_worker(void)
{
	t_worker_config	wcfg = {
		.type = E_WORKER_PSEUDO_THREAD,
		.task_list = &g_cfg->thread_tasks,
		.task_match = { .task_types = WORKER_TASKS },
	};

	if (gettimeofday(&wcfg.task_match.exec_time, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	wcfg.expiry.tv_sec = wcfg.task_match.exec_time.tv_sec
		+ g_cfg->max_rtt_timeout.tv_sec / 10;
	wcfg.expiry.tv_usec = wcfg.task_match.exec_time.tv_usec
		+ (g_cfg->max_rtt_timeout.tv_nsec / 1000) / 10;
	worker(&wcfg);
}
