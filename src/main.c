/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:25:47 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/24 01:32:21 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	cleanup(t_nmap_config *cfg)
{
	if (cfg->hosts_fd >= 0)
		close(cfg->hosts_fd);
}

static void	check_config(t_nmap_config *cfg)
{
	if (!cfg->hosts && !cfg->hosts_file)
		ft_exit("target host missing (use --help for more info)", EXIT_FAILURE);
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

void		print_config(t_nmap_config *cfg)
{
	char	buf[64] = { 0 };

	for (int i = 0; i < NB_SCANS; ++i)
		if (cfg->scans[i])
			ft_strcat(ft_strcat(buf, " "), g_nmap_scan_strings[i]);
	ft_printf("--- Scan Configuration ---\n"
		"Number of ports to scan: %d\n"
		"Scans to be performed:%s\n"
		"Number of threads: %d\n",
		cfg->nports, buf, cfg->speedup);
}

static void	start_workers(t_nmap_config *cfg)
{
	pthread_t	thread[MAX_SPEEDUP] = { 0 };
	t_scan		scan[MAX_SPEEDUP] = { 0 };
	char		*err = NULL;
	int			ret;
	uint8_t		id;

	if (!cfg->speedup)
	{
		if (next_scan(scan + id))
			worker((void *)(scan + id));
		return;
	}
	for (id = 0; !err && id < cfg->speedup && next_scan(scan + id); ++id)
	{
		scan[id].id = id; //TEMP (maybe)
		if ((ret = pthread_create(thread + id, NULL,
			worker, (void *)(scan + id))))
			ft_asprintf(&err, "pthread_create: %s", strerror(ret));
	}
	for (uint8_t i = 0; !err && i < id; ++i)
		if ((ret = pthread_join(thread[i], NULL)))
			ft_asprintf(&err, "pthread_join: %s", strerror(ret));
	if (err)
		ft_exit(err, EXIT_FAILURE);
}

int	main(int argc, char **argv)
{
	int				ret;
	char			*err;
	const char		*target;
	t_nmap_config	cfg = CONFIG_DEF;
	void			cleanup_handler(void) { cleanup(&cfg); };

	(void)argc;
	ft_exitmsg((char *)cfg.exec);
	ft_atexit(cleanup_handler);
	get_options(&cfg, argc, argv);
	check_config(&cfg);
	print_config(&cfg);
	ft_printf("\nThis is %s!\n", cfg.exec);
	if (cfg.speedup && (ret = pthread_mutex_init(&cfg.mutex)))
	{
		ft_asprintf(&err, "pthread_mutex_init: %s", strerror(ret));
		ft_exit(err, EXIT_FAILURE);
	}
	start_workers(&cfg);
	/*
	while ((target = get_target(&cfg)))
		ft_printf("Scanning %s ...\n", target);
	*/
	ft_exit(NULL, EXIT_SUCCESS);
	return (EXIT_SUCCESS);
}
