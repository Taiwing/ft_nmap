/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   init_new_job.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/24 01:26:32 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/01 11:02:10 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	set_job_data(t_job *job, const char *host, t_nmap_config *cfg)
{
	job->host = ft_strdup(host);
	if (gettimeofday(&job->start_ts, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	job->family = job->host_ip.family;
	if (job->family == AF_INET)
		job->dev = !ip_cmp(&cfg->netinf.defdev_v4->ip, &job->host_ip) ||
			!ip_cmp(&cfg->netinf.loopback_v4->ip, &job->host_ip) ?
			cfg->netinf.loopback_v4 : cfg->netinf.defdev_v4;
	else
		job->dev = !ip_cmp(&cfg->netinf.defdev_v6->ip, &job->host_ip) ||
			!ip_cmp(&cfg->netinf.loopback_v6->ip, &job->host_ip) ?
			cfg->netinf.loopback_v6 : cfg->netinf.defdev_v6;
}

t_list	*init_new_job(t_scan *scan)
{
	t_list		*new;
	const char	*host;
	t_job		newjob = { 0 };
	t_job		*job = &newjob;

	if ((new = ft_lst_pop(&scan->cfg->empty_jobs, 0)))
		job = (t_job *)new->content;
	if (!(host = next_host(&job->host_ip, scan->cfg)))
	{
		ft_memdel((void **)&new);
		return (NULL);
	}
	set_job_data(job, host, scan->cfg);
	if (!new)
	{
		job->tasks = (t_task *)ft_memalloc(sizeof(t_task) * scan->cfg->nports);
		new = ft_lstnew((void *)job, sizeof(t_job));
		job = (t_job *)new->content;
	}
	scan->job = job;
	return (new);
}
