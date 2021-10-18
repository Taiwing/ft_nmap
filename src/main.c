/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:25:47 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/18 06:57:57 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	cleanup(void)
{
	wait_workers(g_cfg);
	if (g_cfg->hosts_fd >= 0)
		close(g_cfg->hosts_fd);
}

static void	check_config(t_nmap_config *cfg)
{
	if (!cfg->hosts && !cfg->hosts_file)
		ft_exit("target host missing (use --help for more info)",
			0, EXIT_FAILURE);
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
	t_scan			scan[MAX_SPEEDUP] = {
		[ 0 ... MAX_SPEEDUP - 1] = { 0, 0, NULL, 0, NULL, NULL, &cfg },
	};

	(void)argc;
	g_cfg = &cfg;
	ft_exitmsg((char *)cfg.exec);
	ft_atexit(cleanup);
	ft_first_exit();
	get_options(&cfg, argc, argv);
	check_config(&cfg);
	print_config(&cfg);
	if (cfg.speedup && (ret = pthread_mutex_init(&cfg.mutex, NULL)))
		ft_exit("pthread_mutex_init", ret, EXIT_FAILURE);
	start_workers(&cfg, scan);
	wait_workers(&cfg);
	ft_exit(NULL, 0, EXIT_SUCCESS);
	return (EXIT_SUCCESS);
}
