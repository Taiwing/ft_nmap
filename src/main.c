/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 15:25:47 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/20 15:34:04 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void	cleanup(t_nmap_config *cfg)
{
	(void)cfg;
}

int			main(int argc, char **argv)
{
	t_nmap_config	cfg = CONFIG_DEF;
	void			cleanup_handler(void) { cleanup(&cfg); };

	(void)argc;
	ft_exitmsg((char *)cfg.exec);
	ft_atexit(cleanup_handler);
	ft_printf("This is %s!\n", cfg.exec);
	ft_exit(NULL, EXIT_SUCCESS);
	return (EXIT_SUCCESS);
}
