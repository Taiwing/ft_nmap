/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   update_job.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/24 02:26:25 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/18 06:45:52 by yforeau          ###   ########.fr       */
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
	t_job	*next;

	lst = NULL;
	next = (t_job *)cfg->jobs->content;
	while (next && (next->status & STATE_DONE))
	{
		if (lst)
			ft_printf("\n\n");
		lst = ft_lst_pop(&cfg->jobs, 0);
		print_job(next, cfg);
		reset_job(next, cfg);
		ft_lstadd(&cfg->empty_jobs, lst);
		next = cfg->jobs ? (t_job *)cfg->jobs->content : NULL;
	}
}

// Port is set as open if one of the scans returns an open status
// TODO: this is very simple and should probably changed for something
// a little bit more subtle in function of the type of scan
static int	set_job_status(t_scan *scan)
{
	int		i;
	int		ret = 0;
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
			ft_exit("gettimeofday", errno, EXIT_FAILURE);
		ret = 1;
	}
	return (ret);
}

void		update_job(t_scan *scan)
{
	static int	point_status = 0;

	if (scan->cfg->speedup)
		nmap_mutex_lock(&(scan->cfg->mutex));
	scan->task->scans[scan->type] |= STATE_DONE;
	scan->task->scans[scan->type] |= scan->result;
	scan->result = 0;
	if (++scan->task->done == scan->cfg->nscans)
	{
		ft_printf("%s.", point_status++ ? "" : "\n\n" );
		if (set_job_status(scan) && scan->job_ptr == scan->cfg->jobs)
		{
			point_status = 0;
			ft_putchar('\n');
			flush_jobs(scan->cfg);
			scan->job = NULL;
			scan->job_ptr = NULL;
		}
		scan->task = NULL;
		scan->task_id = 0;
	}
	if (scan->cfg->speedup)
		nmap_mutex_unlock(&(scan->cfg->mutex));
}