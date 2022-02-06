/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   probe_retry.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/17 21:33:17 by yforeau           #+#    #+#             */
/*   Updated: 2022/02/06 11:42:36 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	probe_retry_time(struct timeval *sent_ts, struct timeval *retry_ts)
{
	if (g_cfg->speedup)
		nmap_mutex_lock(&g_cfg->rtt_mutex, &g_rtt_locked);
	if (gettimeofday(sent_ts, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	if (timeval_add(retry_ts, sent_ts, &g_cfg->rtt.timeout) < 0)
		ft_exit(EXIT_FAILURE, "timeval_add: overflow");
	if (g_cfg->speedup)
		nmap_mutex_unlock(&g_cfg->rtt_mutex, &g_rtt_locked);
}

void	set_scan_job_timeout(t_nmap_config *cfg, t_scan_job *scan_job,
	struct timeval *exec_time)
{
	t_task			task = { .type = E_TASK_REPLY, .scan_job = scan_job };

	if (cfg->verbose)
		verbose_reply(cfg, scan_job, NULL, 0);
	push_reply_task(cfg, &task, exec_time);
}

void	push_probe_task(t_nmap_config *cfg, t_scan_job *scan_job,
	struct timeval *exec_time)
{
	t_list	*new_task = NULL;
	t_task	task = { .type = E_TASK_PROBE, .scan_job = scan_job };

	if (exec_time)
		ft_memcpy(&task.exec_time, exec_time, sizeof(struct timeval));
	new_task = ft_lstnew(&task, sizeof(task));
	push_back_tasks(&cfg->thread_tasks, new_task, cfg, !!cfg->speedup);
}
