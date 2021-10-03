/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:25:47 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/03 16:28:04 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	cleanup(void)
{
	uint64_t	nthreads;

	//TEMP
	/*
	ft_printf("cleanup - worker %llu (%llx)!\n",
		ft_thread_self(), pthread_self());
	*/
	//TEMP
	if (g_cfg->speedup && (nthreads = ft_thread_count()))
	{
		nmap_mutex_unlock(&g_cfg->mutex);
		//TODO: probably send a signal to end threads (through ft_exit of course)
		// or just set g_thread_error to a non-zero value (if it is not already
		// the case)
		ft_set_thread_error(EXIT_FAILURE);//TEMP
		for (uint8_t i = 0; i < nthreads; ++i)
			ft_thread_join(g_cfg->thread + i, NULL);
	}
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

static void	start_workers(t_nmap_config *cfg)
{
	t_scan		scan[MAX_SPEEDUP] = {
		[ 0 ... MAX_SPEEDUP - 1] = { 0, 0, NULL, 0, NULL, NULL, cfg },
	};
	int			ret;

	if (!cfg->speedup)
	{
		if (next_scan(scan))
			worker((void *)(scan));
		return;
	}
	for (uint8_t i = 0; i < cfg->speedup && next_scan(&scan[i])
		&& !ft_thread_error(); ++i)
	{
		if ((ret = ft_thread_create(&cfg->thread[i], NULL,
			worker, (void *)(&scan[i]))))
			ft_exit("pthread_create", ret, EXIT_FAILURE);
	}
	ft_atexit(NULL);
	ft_exit(NULL, 0, ft_thread_error());
}

t_nmap_config	*g_cfg = NULL;

int	main(int argc, char **argv)
{
	int				ret;
	t_nmap_config	cfg = CONFIG_DEF;

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
	start_workers(&cfg);
	return (EXIT_SUCCESS);
}
