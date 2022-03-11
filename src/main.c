/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:25:47 by yforeau           #+#    #+#             */
/*   Updated: 2022/03/11 07:16:09 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	main_thread_cleanup(void)
{
	nmap_mutex_unlock(&g_cfg->print_mutex, &g_print_locked);
	nmap_mutex_unlock(&g_cfg->high_mutex, &g_high_locked);
	nmap_mutex_unlock(&g_cfg->low_mutex, &g_low_locked);
	nmap_mutex_unlock(&g_cfg->send_mutex, &g_send_locked);
	nmap_mutex_unlock(&g_cfg->rtt_mutex, &g_rtt_locked);
	wait_worker_threads(g_cfg);
	if (g_cfg->hosts_fd >= 0)
		close(g_cfg->hosts_fd);
	close_sockets(g_cfg);
}

static void	check_config(t_nmap_config *cfg)
{
	if (!*cfg->hosts && !cfg->hosts_file
		&& !cfg->adventure && !cfg->web_adventure)
		ft_exit(EXIT_FAILURE, "target host missing (use --help for more info)");
	if (!cfg->nports)
	{
		cfg->nports = MAX_PORTS;
		ft_memset((void *)(cfg->ports_to_scan + 1), 1, MAX_PORTS);
	}
	for (uint16_t i = 0, j = 0; j < cfg->nports; ++i)
		if (cfg->ports_to_scan[i])
			cfg->ports[j++] = i;
	if (!cfg->nscans)
		for (; cfg->nscans < SCAN_COUNT; ++cfg->nscans)
			cfg->scans[cfg->nscans] = 1;
	cfg->has_udp_scans = cfg->scans[E_UDP];
	cfg->has_tcp_scans = !!(cfg->nscans - cfg->has_udp_scans);
	cfg->total_scan_count = cfg->nports * cfg->nscans;
	if (ft_timeval_cmp(&cfg->rtt.min_timeout, &cfg->rtt.initial_timeout) > 0)
		ft_exit(EXIT_FAILURE, "min-rtt-timeout is greater"
			" than initial-rtt-timeout");
	if (ft_timeval_cmp(&cfg->rtt.initial_timeout, &cfg->rtt.max_timeout) > 0)
		ft_exit(EXIT_FAILURE, "initial-rtt-timeout is greater"
			" than max-rtt-timeout");
}

static void	init_config(t_nmap_config *cfg, int argc, char **argv)
{
	g_cfg = cfg;
	cfg->worker_main_config.task_list = &cfg->main_tasks;
	cfg->worker_thread_config.task_list = &cfg->thread_tasks;
	ft_exitmsg((char *)cfg->exec);
	ft_atexit(main_thread_cleanup);
	ft_first_exit();
	get_options(cfg, argc, argv);
	check_config(cfg);
	get_network_info(cfg);
	init_send_sockets(cfg);
	init_recv_sockets(cfg);
	if (cfg->scans[E_UDP])
		init_udp_payloads(cfg);
	if (cfg->ping_scan)
		ft_atexit(ft_scan_close_all);
	print_config(cfg);
}

t_nmap_config	*g_cfg = NULL;

int	main(int argc, char **argv)
{
	t_nmap_config	cfg = CONFIG_DEF;

	ft_strcpy(argv[0], ft_exec_name(argv[0]));
	init_config(&cfg, argc, argv);
	init_tasks(&cfg);
	if (gettimeofday(&cfg.start_ts, NULL) < 0)
		ft_exit(EXIT_FAILURE, "gettimeofday: %s", strerror(errno));
	worker(&cfg.worker_main_config);
	ft_exit(EXIT_SUCCESS, NULL);
	return (EXIT_SUCCESS);
}
