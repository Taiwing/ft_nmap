/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   update_job.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/24 02:26:25 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/24 03:23:46 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	print_job(t_job *job, t_nmap_config *cfg)
{
	//TODO: here flush job text buffer if needed
	ft_printf("Scan took %g seconds\n", time);
	ft_printf("IP address: %s\n", "lol.mdr.xd.ptdr"); //TEMP
	ft_printf("Open ports:");
	for (int i = 0, c = 0; i < cfg->nports; ++i)
	{
		//TODO: finish this
	}
}

static void	reset_job(t_job *job, t_nmap_config *cfg)
{
	ft_memdel((void **)&job->host);
	job->status = 0;
	job->ongoing = 0;
	job->done = 0;
	ft_bzero((void *)&job->start_ts, sizeof(struct timeval));
	ft_bzero((void *)&job->end_ts, sizeof(struct timeval));
	ft_bzero((void *)job->tasks, sizeof(t_task) * cfg->nports);
}

static void	flush_jobs(t_nmap_config *cfg)
{
	t_list	*lst;
	t_job	*next_job;

	next_job = (t_job *)cfg->jobs->content;
	while (next_job && (next_job->status & STATE_DONE))
	{
		lst = ft_lst_pop(&cfg->jobs, 0);
		print_job(next_job, cfg);
		reset_job(next_job, cfg);
		ft_lst_add(&cfg->empty_jobs, lst);
		next_job = cfg->jobs ? (t_job *)cfg->jobs->content : NULL;
	}
}

void		update_job(t_scan *scan)
{
	if (scan->cfg->speedup)
		ft_mutex_lock(&(scan->cfg->mutex));
	scan->task->scans[scan->type] |= STATE_DONE;
	scan->task->scans[scan->type] |= scan->result;
	scan->result = 0;
	if (++scan->task->done == scan->cfg->nscans)
	{
		scan->task->status |= STATE_DONE;
		if (++scan->job->done == scan->cfg->nports)
			scan->job->status |= STATE_DONE;
	}
	if (scan->job_ptr == scan->cfg->jobs)
	{
		flush_jobs(scan->cfg);
		scan->task = NULL;
		scan->task_id = 0;
		scan->job = NULL;
		scan->job_ptr = NULL;
	}
	if (scan->cfg->speedup)
		ft_mutex_unlock(&(scan->cfg->mutex));
}
