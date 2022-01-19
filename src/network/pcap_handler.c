/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pcap_handler.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/17 08:21:27 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/19 08:18:09 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void			push_reply_task(t_nmap_config *cfg, t_task *task,
		struct timeval *exec_time)
{
	t_list		*new_task;

	new_task = ft_lstnew(task, sizeof(t_task));
	if (!exec_time)
		push_front_tasks(&cfg->thread_tasks, new_task, cfg, !!cfg->speedup);
	else
	{
		ft_memcpy(&task->exec_time, exec_time, sizeof(struct timeval));
		push_back_tasks(&cfg->thread_tasks, new_task, cfg, !!cfg->speedup);
	}
}

static void		start_pcap_worker(void)
{
	t_worker_config	wcfg = {
		.type = E_WORKER_PSEUDO_THREAD,
		.task_list = &g_cfg->thread_tasks,
		.task_match = { .task_types = WORKER_TASKS },
	};

	g_cfg->pcap_worker_is_working = 1;
	if (gettimeofday(&wcfg.task_match.exec_time, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	wcfg.expiry.tv_sec = wcfg.task_match.exec_time.tv_sec
		+ ((DEF_TIMEOUT / 1000) / 2);
	worker(&wcfg);
	g_cfg->pcap_worker_is_working = 0;
}

void			pcap_handlerf(uint8_t *u, const struct pcap_pkthdr *h,
	const uint8_t *bytes)
{
	t_task			task = { .type = E_TASK_REPLY };

	(void)u;
	++g_cfg->received_packet_count;
	task.reply = ft_memdup(bytes, h->len);
	task.reply_size = h->len;
	push_reply_task(g_cfg, &task, NULL);
	if (!g_cfg->speedup)
		start_pcap_worker();
}
