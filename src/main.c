/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:25:47 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/23 21:22:54 by yforeau          ###   ########.fr       */
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

int	main(int argc, char **argv)
{
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
	while ((target = get_target(&cfg)))
		ft_printf("Scanning %s ...\n", target);
	//TEST
	pthread_t	thread[MAX_SPEEDUP];
	int			arg[MAX_SPEEDUP];
	uint64_t	exit_value[MAX_SPEEDUP] = { 0 };
	uint64_t	test = 0;
	int			ret = 0;
	pthread_mutex_t	local_mutex;
	char		*err = NULL;
	void		*retval = NULL;
	void		*thread_function(void *ptr) {
		int	id = *(int *)ptr;
		ft_mutex_lock(&local_mutex);
		if (!ft_rand_uint64(exit_value + id, 0, (uint64_t)cfg.speedup - 1))
			ft_exit("ft_rand_uint64: error\n", EXIT_FAILURE);
		ft_printf("Thread number %d (exit_value: %u)\n", id, exit_value[id]);
		if ((uint64_t)id == exit_value[id])
			ft_exit("WOOOOW!!!!", 123);
		ft_mutex_unlock(&local_mutex);
		sleep(exit_value[id]);
		pthread_exit((void *)(exit_value + id));
	};

	pthread_mutex_init(&local_mutex, NULL);
	for (int i = 0; i < cfg.speedup; ++i)
	{
		arg[i] = i;
		if ((ret = pthread_create(thread + i, NULL, thread_function, (void *)(arg + i))))
		{
			ft_asprintf(&err, "pthread_create: %s", strerror(ret));
			ft_exit(err, EXIT_FAILURE);
		}
	}
	for (int i = 0; i < cfg.speedup; ++i)
	{
		if ((ret = pthread_join(thread[i], &retval)))
		{
			ft_asprintf(&err, "pthread_join: %s", strerror(ret));
			ft_exit(err, EXIT_FAILURE);
		}
		if (retval == PTHREAD_CANCELED)
			ft_printf("Thread %d (%lu) canceled.\n", i, thread[i]);
		else
		{
			test = *(uint64_t *)retval;
			ft_mutex_lock(&local_mutex);
			ft_printf("Thread %d (%lu) exit_value: %d\n", i, thread[i], test);
			ft_mutex_unlock(&local_mutex);
		}
	}
	//TEST
	ft_exit(NULL, EXIT_SUCCESS);
	return (EXIT_SUCCESS);
}
