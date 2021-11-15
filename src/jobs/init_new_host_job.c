/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   init_new_host_job.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/15 08:10:47 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/15 12:00:11 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	set_host_job_data(t_host_job *host_job, const char *host,
		t_nmap_config *cfg)
{
	host_job->host_job_id = ft_lst_size(cfg->host_jobs);
	host_job->host = ft_strdup(host);
	if (gettimeofday(&host_job->start_ts, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	host_job->family = host_job->host_ip.family;
	if (host_job->family == AF_INET)
		host_job->dev = !ip_cmp(&cfg->netinf.defdev_v4->ip, &host_job->host_ip)
			|| !ip_cmp(&cfg->netinf.loopback_v4->ip, &host_job->host_ip) ?
			cfg->netinf.loopback_v4 : cfg->netinf.defdev_v4;
	else
		host_job->dev = !ip_cmp(&cfg->netinf.defdev_v6->ip, &host_job->host_ip)
			|| !ip_cmp(&cfg->netinf.loopback_v6->ip, &host_job->host_ip) ?
			cfg->netinf.loopback_v6 : cfg->netinf.defdev_v6;
}

t_list	*init_new_host_job(t_nmap_config *cfg)
{
	t_list		*new;
	const char	*host;
	t_host_job		newhost_job = { 0 };
	t_host_job		*host_job = &newhost_job;

	if ((new = ft_lst_pop(&cfg->empty_host_jobs, 0)))
		host_job = (t_host_job *)new->content;
	if (!(host = next_host(&host_job->host_ip, cfg)))
	{
		ft_memdel((void **)&new);
		return (NULL);
	}
	set_host_job_data(host_job, host, cfg);
	if (!new)
	{
		host_job->port_jobs = (t_port_job *)
			ft_memalloc(sizeof(t_port_job) * cfg->nports);
		new = ft_lstnew((void *)host_job, sizeof(t_host_job));
		host_job = (t_host_job *)new->content;
	}
	return (new);
}
