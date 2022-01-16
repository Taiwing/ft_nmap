/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ports.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/03 20:39:02 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/16 22:19:21 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void		parse_ports(t_nmap_config *cfg, char *str,
		t_setportf setport, void *data)
{
	const char	*portexp = NULL, *p = NULL;
	int			porta, portb;

	while ((portexp = parse_comma_list(str)) && *portexp)
	{
		p = portexp;
		portb = 0;
		porta = parse_int_prefix(p, 0, USHRT_MAX, "port");
		for (; *p && ft_isdigit(*p); ++p);
		if (*p && *p == '-')
		{
			portb = parse_int_prefix(++p, 0, USHRT_MAX, "port");
			if (portb <= porta)
				ft_exit(EXIT_FAILURE, "%s: second port must be greater than "
					"first port in range: '%s'", __func__, portexp);
		}
		for (; *p && ft_isdigit(*p); ++p);
		if (*p)
			break;
		setport(cfg, porta, portb, data);
	}
	if (!portexp || !p || *p)
		ft_exit(EXIT_FAILURE, "%s: invalid list argument: '%s'", __func__, str);
}
