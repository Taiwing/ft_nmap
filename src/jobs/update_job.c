/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   update_job.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/24 02:26:25 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/15 10:35:17 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	reset_host_job(t_host_job *host_job, t_nmap_config *cfg)
{
	ft_memdel((void **)&host_job->host);
	host_job->status = 0;
	host_job->ongoing = 0;
	host_job->done = 0;
	ft_bzero((void *)&host_job->start_ts, sizeof(struct timeval));
	ft_bzero((void *)&host_job->end_ts, sizeof(struct timeval));
	ft_bzero((void *)host_job->port_jobs, sizeof(t_port_job) * cfg->nports);
}

static void	flush_host_jobs(t_nmap_config *cfg)
{
	t_list	*lst;
	t_host_job	*next;

	lst = NULL;
	next = (t_host_job *)cfg->host_jobs->content;
	while (next && (next->status & E_STATE_DONE))
	{
		if (lst)
			ft_printf("\n\n");
		lst = ft_lst_pop(&cfg->host_jobs, 0);
		print_host_job(next, cfg);
		reset_host_job(next, cfg);
		ft_lstadd(&cfg->empty_host_jobs, lst);
		next = cfg->host_jobs ? (t_host_job *)cfg->host_jobs->content : NULL;
	}
}

// Port is set as open if one of the scan_jobs returns an open status
// TODO: this is very simple and should probably changed for something
// a little bit more subtle in function of the type of scan_job
static int	set_job_status(t_scan_job *scan)
{
	int		i;
	int		ret = 0;
	uint8_t	status = E_STATE_CLOSED;

	scan->port_job->status |= E_STATE_DONE;
	for (i = 0; i < SCAN_COUNT; ++i)
		if ((scan->port_job->scan_jobs[i] & E_STATE_OPEN)
			&& !(scan->port_job->scan_jobs[i] & E_STATE_FILTERED))
			break;
	if (i < SCAN_COUNT)
		status = E_STATE_OPEN;
	scan->port_job->status |= status;
	if (++scan->host_job->done == scan->cfg->nports)
	{
		scan->host_job->status |= E_STATE_DONE;
		if (gettimeofday(&scan->host_job->end_ts, NULL) < 0)
			ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
		ret = 1;
	}
	return (ret);
}

void		update_job(t_scan_job *scan)
{
	static int	point_status = 0;

	if (scan->cfg->speedup)
		nmap_mutex_lock(&scan->cfg->global_mutex, &g_global_locked);
	scan->port_job->scan_jobs[scan->type] |= E_STATE_DONE;
	scan->port_job->scan_jobs[scan->type] |= scan->result;
	scan->result = 0;
	if (++scan->port_job->done == scan->cfg->nscans)
	{
		ft_printf("%s.", point_status++ ? "" : "\n\n" );
		if (set_job_status(scan) && scan->host_job_ptr == scan->cfg->host_jobs)
		{
			point_status = 0;
			ft_putchar('\n');
			flush_host_jobs(scan->cfg);
			scan->host_job = NULL;
			scan->host_job_ptr = NULL;
		}
		scan->port_job = NULL;
		scan->port_job_id = 0;
	}
	if (scan->cfg->speedup)
		nmap_mutex_unlock(&scan->cfg->global_mutex, &g_global_locked);
}
