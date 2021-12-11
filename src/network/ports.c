/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ports.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/03 20:39:02 by yforeau           #+#    #+#             */
/*   Updated: 2021/12/11 07:13:48 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

// This is largely big enough to detect overflow from integer string
#define	INTOPT_BUF	64

static void	intport(int *dest, const char *portexp, int min, int max)
{
	int		i, ret;
	char	buf[INTOPT_BUF + 1] = { 0 };

	ft_strncpy(buf, portexp, INTOPT_BUF);
	for (i = 0; buf[i] && ft_isdigit(buf[i]); ++i);
	if (i == INTOPT_BUF && ft_isdigit(portexp[i]))
		ft_exit(EXIT_FAILURE, "%s: invalid port: '%s'", __func__, portexp);
	buf[i] = 0;
	if ((ret = ft_secatoi(dest, min, max, buf)))
	{
		if (ret == FT_E_NOT_A_NUMBER)
			ft_exit(EXIT_FAILURE, "%s: invalid port: '%s'", __func__, portexp);
		else
			ft_exit(EXIT_FAILURE, "%s: invalid port: '%s': "
				"out of range: %d <= value <= %d", __func__, buf, min, max);
	}
}

void		parse_ports(t_nmap_config *cfg, char *str,
		t_setportf setport, void *data)
{
	const char	*portexp = NULL, *p = NULL;
	int			porta, portb;

	while ((portexp = parse_comma_list(str)) && *portexp)
	{
		p = portexp;
		portb = 0;
		intport(&porta, p, 0, USHRT_MAX);
		for (; *p && ft_isdigit(*p); ++p);
		if (*p && *p == '-')
		{
			intport(&portb, ++p, 0, USHRT_MAX);
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
		ft_exit(EXIT_FAILURE, "%s: invalid list argument: '%s'", str, __func__);
}

