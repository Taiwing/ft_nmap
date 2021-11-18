/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:25:47 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/18 17:04:01 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	main_thread_cleanup(void)
{
	nmap_mutex_unlock(&g_cfg->print_mutex, &g_print_locked);
	nmap_mutex_unlock(&g_cfg->high_mutex, &g_high_locked);
	nmap_mutex_unlock(&g_cfg->low_mutex, &g_low_locked);
	alarm(0);
	if (g_cfg->ifap)
		freeifaddrs(g_cfg->ifap);
	wait_workers(g_cfg);
	if (g_cfg->hosts_fd >= 0)
		close(g_cfg->hosts_fd);
	close_sockets(g_cfg);
	if (g_cfg->descr)
	{
		pcap_close(g_cfg->descr);
		g_cfg->descr = NULL;
	}
}

static void	check_config(t_nmap_config *cfg)
{
	if (!cfg->hosts && !cfg->hosts_file)
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
}

static void	init_config(t_nmap_config *cfg, int argc, char **argv)
{
	g_cfg = cfg;
	ft_exitmsg((char *)cfg->exec);
	ft_atexit(main_thread_cleanup);
	ft_first_exit();
	get_options(cfg, argc, argv);
	check_config(cfg);
	get_network_info(cfg);
	init_sockets(cfg);
	open_device(cfg, HEADER_MAXSIZE, -1);
	set_alarm_handler();
	print_config(cfg);
}

t_nmap_config	*g_cfg = NULL;

int	main(int argc, char **argv)
{
	t_nmap_config	cfg = CONFIG_DEF;

	init_config(&cfg, argc, argv);
	init_tasks(&cfg);
	ft_exit(EXIT_SUCCESS, NULL);
	return (EXIT_SUCCESS);
}
