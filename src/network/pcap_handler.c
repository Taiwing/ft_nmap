/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   pcap_handler.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/17 08:21:27 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/04 08:49:35 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void			push_reply_task(t_task *task)
{
	t_list		*new_task;

	new_task = ft_lstnew(task, sizeof(t_task));
	if (!g_cfg->speedup)
	{
		push_tasks(&g_cfg->main_tasks, new_task, g_cfg, 0);
		g_cfg->current_probe = -1;
		pcap_breakloop(g_cfg->descr);
	}
	else
		push_tasks(&g_cfg->worker_tasks, new_task, g_cfg, 1);
}

void			pcap_handlerf(uint8_t *u, const struct pcap_pkthdr *h,
	const uint8_t *bytes)
{
	t_task			task = { .type = E_TASK_REPLY };

	(void)u;
	task.reply = ft_memdup(bytes, h->len);
	task.reply_size = h->len;
	push_reply_task(&task);
}
