/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   next_job.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/18 06:46:10 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/15 08:31:23 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static t_scan_job	*get_a_scan_job(t_scan_job *scan)
{
	int	i;

	for (i = scan->type; i < NB_SCANS; ++i)
		if (scan->cfg->scans[i] && !scan->port_job->scan_jobs[i])
			break;
	if (i == NB_SCANS)
		return (NULL);
	scan->type = i;
	scan->port_job->scan_jobs[i] = E_STATE_ONGOING;
	scan->port_job->status |= E_STATE_ONGOING;
	scan->host_job->status |= E_STATE_ONGOING;
	if (++scan->port_job->ongoing == scan->cfg->nscans)
	{
		scan->port_job->status |= E_STATE_FULL;
		if (++scan->host_job->ongoing == scan->cfg->nports)
			scan->host_job->status |= E_STATE_FULL;
	}
	return (scan);
}

static t_scan_job	*get_a_port_job(t_scan_job *scan)
{
	uint16_t	i;

	for (i = scan->port_job_id; i < scan->cfg->nports; ++i)
		if (!(scan->host_job->port_jobs[i].status & E_STATE_FULL))
			break;
	if (i == scan->cfg->nports)
		return (NULL);
	scan->port_job_id = i;
	scan->port_job = scan->host_job->port_jobs + i;
	scan->type = 0;
	return (get_a_scan_job(scan));
}

static t_scan_job	*get_a_host_job(t_scan_job *scan)
{
	t_host_job	*host_job = NULL;
	t_list	**lst = scan->host_job_ptr ?
		&scan->host_job_ptr : &scan->cfg->host_jobs;

	for (; *lst; lst = &((*lst)->next))
	{
		host_job = (t_host_job *)((*lst)->content);
		if (!(host_job->status & E_STATE_FULL))
			break;
	}
	scan->host_job = host_job;
	if (!*lst && !(*lst = init_new_host_job(scan)))
		return (NULL);
	scan->host_job_ptr = *lst;
	scan->port_job_id = 0;
	return (get_a_port_job(scan));
}

t_scan_job		*next_job(t_scan_job *scan)
{
	t_nmap_config	*cfg = scan->cfg;

	if (cfg->speedup)
		nmap_mutex_lock(&cfg->global_mutex, &g_global_locked);
	if (scan->port_job && !(scan->port_job->status & E_STATE_FULL))
		scan = get_a_scan_job(scan);
	else if (scan->host_job && !(scan->host_job->status & E_STATE_FULL))
		scan = get_a_port_job(scan);
	else
		scan = get_a_host_job(scan);
	if (cfg->speedup)
		nmap_mutex_unlock(&cfg->global_mutex, &g_global_locked);
	return (scan);
}
