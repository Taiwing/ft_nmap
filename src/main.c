/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:25:47 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/21 17:40:56 by yforeau          ###   ########.fr       */
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

void		print_config(t_nmap_config *cfg)
{
	char	buf[64] = { 0 };

	for (int i = 0, scans = cfg->scans; scans; ++i)
	{
		if (scans & 0x01)
			ft_strcat(ft_strcat(buf, " "), g_nmap_scan_strings[i]);
		scans >>= 1;
	}
	ft_printf("--- Scan Configuration ---\n"
		"Number of ports to scan: %d\n"
		"Scans to be performed:%s\n"
		"Number of threads: %d\n",
		cfg->nb_ports, buf, cfg->speedup);
}

static const char	*get_target(t_nmap_config *cfg)
{
	char		*err = NULL;
	const char	*ret = NULL;

	if (cfg->hosts && !(ret = parse_comma_list(cfg->hosts)))
	{
		ft_asprintf(&err, "invalid list argument: '%s'", cfg->hosts);
		ft_exit(err, EXIT_FAILURE);
	}
	else if (cfg->hosts && !*ret)
		cfg->hosts = ret = NULL;
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
	ft_exit(NULL, EXIT_SUCCESS);
	return (EXIT_SUCCESS);
}
