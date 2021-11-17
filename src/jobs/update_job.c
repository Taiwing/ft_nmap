/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   update_job.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/24 02:26:25 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/17 12:28:51 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

// Port is set as open if one of the scan_jobs returns an open status
// TODO: this is very simple and should probably changed for something
// a little bit more subtle in function of the type of scan_job
static int	set_job_status(t_nmap_config *cfg, t_port_job *port_job)
{
	int		i;
	int		ret = 0;
	uint8_t	status = E_STATE_CLOSED;

	port_job->status |= E_STATE_DONE;
	for (i = 0; i < SCAN_COUNT; ++i)
		if ((port_job->scan_jobs[i] & E_STATE_OPEN)
			&& !(port_job->scan_jobs[i] & E_STATE_FILTERED))
			break;
	if (i < SCAN_COUNT)
		status = E_STATE_OPEN;
	port_job->status |= status;
	if (++cfg->host_job.done == cfg->nports)
	{
		cfg->host_job.status |= E_STATE_DONE;
		if (gettimeofday(&cfg->host_job.end_ts, NULL) < 0)
			ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
		ret = 1;
	}
	return (ret);
}

int			update_job(t_nmap_config *cfg, t_task *task)
{
	static atomic_int	point_status = 0;
	t_port_job			*port_job = NULL;
	int					ret = 0;

	port_job = cfg->host_job.port_jobs + task->probe->port_job_id;
	if (task->probe->done || cfg->host_job.done
		|| task->probe->host_job_id != cfg->host_job.host_job_id
		|| ++port_job->scan_locks[task->probe->scan_type] > 1)
		return ;
	task->probe.done = 1;
	port_job->scan_jobs[task->probe->scan_type] |= E_STATE_DONE | task->result;
	if (++port_job->done == cfg->nscans)
	{
		ft_printf("%s.", point_status++ ? "" : "\n\n" );
		if ((ret = set_job_status(cfg, port_job)))
		{
			point_status = 0;
			ft_putchar('\n');
			print_host_job(&cfg->host_job, cfg);
		}
	}
	return (ret);
}
