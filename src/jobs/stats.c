/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   stats.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/06 19:07:52 by yforeau           #+#    #+#             */
/*   Updated: 2022/03/09 02:16:03 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

double	print_end_stats(void)
{
	double	total_time;

	if (gettimeofday(&g_cfg->end_ts, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	total_time = ts_msdiff(&g_cfg->end_ts, &g_cfg->start_ts) / 1000.0;
	ft_printf("\n--- ft_nmap done ---\n");
	if (g_cfg->ping_scan && g_cfg->skip_non_responsive)
		ft_printf("%d address%s scanned (%d host%s up) in %g seconds\n",
			g_cfg->host_count, g_cfg->host_count > 1 ? "es" : "",
			g_cfg->host_up, g_cfg->host_up > 1 ? "s" : "", total_time);
	else
		ft_printf("%d address%s scanned in %g seconds\n",
			g_cfg->host_count, g_cfg->host_count > 1 ? "es" : "", total_time);
	return (total_time);
}

#define	TIME_BUF_SIZE	256

double	print_update_stats(void)
{
	double			done;
	struct timeval	now, elapsed;
	char			buf[TIME_BUF_SIZE];
	int				scans_done = 0, scans_todo = 0;

	if (g_cfg->speedup)
		nmap_mutex_lock(&g_cfg->print_mutex, &g_print_locked);
	if (gettimeofday(&now, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	for (int i = 0; i < g_cfg->total_scan_count; ++i)
	{
		scans_done += g_cfg->scan_jobs[i]->total_tries -
			(g_cfg->scan_jobs[i]->tries < 0 ? 0 : g_cfg->scan_jobs[i]->tries);
		scans_todo += g_cfg->scan_jobs[i]->total_tries;
	}
	done = (double)scans_done / (double)scans_todo * 100.0;
	if (ft_timeval_sub(&elapsed, &now, &g_cfg->host_job.start_ts) < 0)
		ft_exit(EXIT_FAILURE, "ft_timeval_sub: %s", ft_strerror(ft_errno));
	if (timeval_to_str(buf, TIME_BUF_SIZE, &elapsed) < 0)
		ft_exit(EXIT_FAILURE, "timeval_to_str: error");
	ft_printf("Scanning %s: About %02.2f%% done; Time elapsed %s;\n",
		g_cfg->host_job.host, done, buf);
	if (g_cfg->speedup)
		nmap_mutex_unlock(&g_cfg->print_mutex, &g_print_locked);
	return (ts_msdiff(&now, &g_cfg->host_job.start_ts) / 1000.0);
}
