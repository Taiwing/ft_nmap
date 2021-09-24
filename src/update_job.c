/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   update_job.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/24 02:26:25 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/24 22:19:27 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

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
		ft_lstadd(&cfg->empty_jobs, lst);
		next_job = cfg->jobs ? (t_job *)cfg->jobs->content : NULL;
	}
}

// Port is set as open if one of the scans returns an open status
// TODO: this is very simple and should probably changed for something
// a little bit more subtle in function of the type of scan
static int	set_job_status(t_scan *scan)
{
	int		i;
	int		ret = 0;
	char	*err = NULL;
	uint8_t	status = STATE_CLOSED;

	scan->task->status |= STATE_DONE;
	for (i = 0; i < NB_SCANS; ++i)
		if ((scan->task->scans[i] & STATE_OPEN)
			&& !(scan->task->scans[i] & STATE_FILTERED))
			break;
	if (i < NB_SCANS)
		status = STATE_OPEN;
	scan->task->status |= status;
	if (++scan->job->done == scan->cfg->nports)
	{
		scan->job->status |= STATE_DONE;
		if (gettimeofday(&scan->job->end_ts, NULL) < 0)
		{
			ft_asprintf(&err, "gettimeofday: %s", strerror(errno));
			ft_exit(err, EXIT_FAILURE);
		}
		ret = 1;
	}
	ft_putchar('.');
	return (ret);
}

void		update_job(t_scan *scan)
{
	if (scan->cfg->speedup)
		ft_mutex_lock(&(scan->cfg->mutex));
	scan->task->scans[scan->type] |= STATE_DONE;
	scan->task->scans[scan->type] |= scan->result;
	scan->result = 0;
	if (++scan->task->done == scan->cfg->nscans)
		if (set_job_status(scan) && scan->job_ptr == scan->cfg->jobs)
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
