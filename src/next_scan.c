/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   next_scan.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/24 01:22:52 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/24 01:49:36 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static t_scan	*get_a_scan(t_scan *scan)
{
	int	i;

	for (i = scan->type; i < NB_SCANS; ++i)
		if (scan->cfg->scans[i] && !scan->task->scans[i])
			break;
	if (i == NB_SCANS)
		return (NULL);
	scan->type = i;
	scan->task->scans[i] = STATE_ONGOING;
	scan->task->status |= STATE_ONGOING;
	scan->job->status |= STATE_ONGOING;
	if (++scan->task->ongoing == scan->cfg->nscans)
	{
		scan->task->status |= STATE_FULL;
		if (++scan->job->ongoing == scan->cfg->nports)
			scan->job->status |= STATE_FULL;
	}
	return (scan);
}

static t_scan	*get_a_task(t_scan *scan)
{
	uint16_t	i;

	for (i = scan->task_id; i < scan->cfg->nports; ++i)
		if (!(scan->job->tasks[i].status & STATE_FULL))
			break;
	if (i == scan->cfg->nports)
		return (NULL);
	scan->task_id = i;
	scan->task = scan->job->tasks + i;
	scan->type = 0;
	return (get_a_scan(scan));
}

static t_scan	*get_a_job(t_scan *scan)
{
	t_job	*job = NULL;
	t_list	**lst = scan->job_ptr ? &scan->job_ptr : &scan->cfg->jobs;

	for (; *lst; lst = &((*lst)->next))
	{
		job = (t_job *)((*lst)->content);
		if (!(job->status & STATE_FULL))
			break;
	}
	scan->job = job;
	if (!*lst && !(*lst = init_new_job(scan)))
		return (NULL);
	scan->job_ptr = *lst;
	scan->task_id = 0;
	return (get_a_task(scan));
}

t_scan		*next_scan(t_scan *scan)
{
	if (scan->cfg->speedup)
		ft_mutex_lock(&(scan->cfg->mutex));
	if (scan->task && !(scan->task->status & STATE_FULL))
		scan = get_a_scan(scan);
	else if (scan->job && !(scan->job->status & STATE_FULL))
		scan = get_a_task(scan);
	else
		scan = get_a_job(scan);
	if (scan->cfg->speedup)
		ft_mutex_unlock(&(scan->cfg->mutex));
	return (scan);
}