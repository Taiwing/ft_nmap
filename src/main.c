/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:25:47 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/30 12:55:30 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	cleanup(void)
{
	if (g_cfg->ifap)
		freeifaddrs(g_cfg->ifap);
	wait_workers(g_cfg);
	if (g_cfg->hosts_fd >= 0)
		close(g_cfg->hosts_fd);
	close_sockets(g_cfg);
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
		for (; cfg->nscans < NB_SCANS; ++cfg->nscans)
			cfg->scans[cfg->nscans] = 1;
}

t_nmap_config	*g_cfg = NULL;

int	main(int argc, char **argv)
{
	int				ret;
	t_nmap_config	cfg = CONFIG_DEF;
	t_scan			scan[MAX_SPEEDUP] = { [ 0 ... MAX_SPEEDUP - 1] = SCAN_DEF };

	(void)argc;
	g_cfg = &cfg;
	ft_exitmsg((char *)cfg.exec);
	ft_atexit(cleanup);
	ft_first_exit();
	get_options(&cfg, argc, argv);
	check_config(&cfg);
	get_network_info(&cfg);
	init_sockets(&cfg);
	print_config(&cfg);
	if (cfg.speedup && (ret = pthread_mutex_init(&cfg.global_mutex, NULL)))
		ft_exit(EXIT_FAILURE, "pthread_mutex_init: %s", strerror(ret));
	start_workers(&cfg, scan);
	wait_workers(&cfg);
	ft_exit(EXIT_SUCCESS, NULL);
	return (EXIT_SUCCESS);
}
