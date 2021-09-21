/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:25:47 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/21 12:21:14 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	cleanup(t_nmap_config *cfg)
{
	(void)cfg;
}

static void	check_config(t_nmap_config *cfg)
{
	if (!cfg->hosts && !cfg->hosts_file)
		ft_exit("target host missing (use --help for more info)", EXIT_FAILURE);
	if (!cfg->nb_ports)
	{
		cfg->nb_ports = MAX_PORTS;
		ft_memset((void *)(cfg->ports_to_scan + 1), 1, MAX_PORTS);
	}
	for (uint16_t i = 0, j = 0; (int)j < cfg->nb_ports; ++i)
		if (cfg->ports_to_scan[i])
			cfg->ports[j++] = i;
	if (!cfg->scans)
		cfg->scans = S_ALL;
	//TODO: set the scans in an array of scan function pointers
}

int			main(int argc, char **argv)
{
	t_nmap_config	cfg = CONFIG_DEF;
	void			cleanup_handler(void) { cleanup(&cfg); };

	(void)argc;
	ft_exitmsg((char *)cfg.exec);
	ft_atexit(cleanup_handler);
	get_options(&cfg, argc, argv);
	check_config(&cfg);
	ft_printf("This is %s!\n", cfg.exec);
	ft_exit(NULL, EXIT_SUCCESS);
	return (EXIT_SUCCESS);
}
