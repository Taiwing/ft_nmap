/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   init_new_job.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/24 01:26:32 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/24 01:58:08 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static const char	*get_target(t_nmap_config *cfg)
{
	char				*err = NULL;
	static const char	*ret = NULL;

	if (cfg->hosts && !(ret = parse_comma_list(cfg->hosts)))
		ft_asprintf(&err, "invalid list argument: '%s'", cfg->hosts);
	else if (cfg->hosts && !*ret)
		cfg->hosts = ret = NULL;
	if (!err && !cfg->hosts && cfg->hosts_file && cfg->hosts_fd < 0
		&& (cfg->hosts_fd = open(cfg->hosts_file, O_RDONLY)) < 0)
		ft_asprintf(&err, "open: %s", strerror(errno));
	else if (!err && !cfg->hosts && cfg->hosts_fd >= 0)
	{
		if (ret)
			ft_memdel((void *)&ret);
		if (get_next_line(cfg->hosts_fd, (char **)&ret) < 0)
			ft_asprintf(&err, "get_next_line: unknown error");
	}
	if (err)
		ft_exit(err, EXIT_FAILURE);
	return (ret);
}

t_list	*init_new_job(t_scan *scan)
{
	t_list		*new;
	t_job		*job;
	char		*err;
	const char	*target;
	t_job		newjob = { 0 };

	if (!(target = get_target(scan->cfg)))
		return (NULL);
	job = &newjob;
	if ((new = ft_lst_pop(&scan->cfg->empty_jobs, 0)))
		job = (t_job *)new->content;
	job->host = ft_strdup(target);
	if (gettimeofday(&job->start_ts, NULL) < 0)
	{
		ft_asprintf(&err, "gettimeofday: %s", strerror(errno));
		ft_exit(err, EXIT_FAILURE);
	}
	if (!new)
	{
		job->tasks = (t_task *)ft_memalloc(sizeof(t_task) * scan->cfg->nports);
		new = ft_lstnew((void *)job, sizeof(t_job));
		job = (t_job *)new->content;
	}
	scan->job = job;
	return (new);
}