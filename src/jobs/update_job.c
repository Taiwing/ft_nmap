/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   update_job.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/24 02:26:25 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/05 16:26:07 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static int	set_job_status(t_nmap_config *cfg, t_port_job *port_job)
{
	int		i;
	int		ret = 0;
	uint8_t	status = E_STATE_OPEN | E_STATE_FILTERED;
	uint8_t	new_status = E_STATE_OPEN | E_STATE_FILTERED;

	port_job->status |= E_STATE_DONE;
	for (i = 0; i < SCAN_COUNT; ++i)
	{
		if (!(new_status = port_job->scan_status[i] & E_STATE_SCAN_MASK))
			continue ;
		if (new_status < status)
			status = new_status;
		if (status == E_STATE_OPEN)
			break ;
	}
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

int		update_job(t_nmap_config *cfg, t_scan_job *scan_job, uint8_t result)
{
	static atomic_int	point_status = 0;
	t_port_job			*port_job = NULL;
	int					ret = 0;

	port_job = cfg->host_job.port_jobs + scan_job->port_job_id;
	if (scan_job->retry < 0 || cfg->host_job.done == cfg->nports
		|| scan_job->host_job_id != cfg->host_job.host_job_id
		|| ++port_job->scan_locks[scan_job->type] > 1)
		return (ret);
	scan_job->retry = -1;
	port_job->scan_status[scan_job->type] |= E_STATE_DONE | result;
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
