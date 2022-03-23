/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   option_utils.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/20 23:12:12 by yforeau           #+#    #+#             */
/*   Updated: 2022/03/23 05:45:44 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void		usage(const char *exec, int exit_value)
{
	const t_opt	*opts = g_nmap_opt;
	const char	**help = g_nmap_help;
	const char	**usage = g_nmap_usage;

	ft_printf("Usage:\n");
	while (*usage)
	{
		ft_printf("\t%s %s\n", exec, *usage);
		++usage;
	}
	ft_printf("\nOptions:\n");
	while (opts->name && *help)
	{
		if (ft_isalnum(opts->val))
			ft_printf("\t-%c, --%s\n", opts->val, opts->name);
		else
			ft_printf("\t--%s\n", opts->name);
		ft_printf("\t\t%s\n", *help);
		++opts;
		++help;
	}
	ft_printf("\nDescription:\n%s", g_description);
	ft_exit(exit_value, NULL);
}

int			parse_int(const char *str, int min, int max, const char *type)
{
	int	result = 0;

	if (ft_secatoi(&result, min, max, str) < 0)
	{
		if (ft_errno == E_FTERR_NOT_A_NUMBER)
			ft_exit(EXIT_FAILURE, "invalid %s: '%s'", type, str);
		else
			ft_exit(EXIT_FAILURE, "invalid %s: '%s': "
				"out of range: %d <= value <= %d", type, str, min, max);
	}
	return (result);
}

// This is largely big enough to detect overflow from integer string
#define	PARSE_INT_BUF	64

int			parse_int_prefix(const char *str, int min, int max,
		const char *type)
{
	int		i;
	char	buf[PARSE_INT_BUF + 1] = { 0 };

	ft_strncpy(buf, str, PARSE_INT_BUF);
	for (i = 0; buf[i] && ft_isdigit(buf[i]); ++i);
	if (i == PARSE_INT_BUF && ft_isdigit(str[i]))
		ft_exit(EXIT_FAILURE, "invalid %s: '%s'", type, str);
	buf[i] = 0;
	return (parse_int(buf, min, max, type));
}

const char	*parse_comma_list(const char *str)
{
	static char			buf[MAX_LST_ELM_LEN + 1] = { 0 };
	static const char	*list = NULL;
	const char			*end = NULL;
	static const char	*p = NULL;
	size_t				len;

	if (str != list)
		list = p = str;
	else if (p && *p == ',' && p[1])
		++p;
	end = p;
	while (end && !ft_strchr(",", *end))
		++end;
	if (!p || ((!*p && p == list) || *p == ',')
		|| (len = end - p) > MAX_LST_ELM_LEN)
	{
		list = p = NULL;
		return (NULL);
	}
	ft_strncpy(buf, p, len);
	buf[len] = 0;
	p = end;
	return ((const char *)buf);
}

void		set_scan_ports(t_nmap_config *cfg, int porta, int portb, void *data)
{
	(void)data;
	do
	{
		if (!cfg->ports_to_scan[porta] && cfg->nports < MAX_PORTS)
			++cfg->nports;
		else if (!cfg->ports_to_scan[porta])
			ft_exit(EXIT_FAILURE, "%s: too many ports to scan, max is: %d",
				__func__, MAX_PORTS);
		cfg->ports_to_scan[porta] = 1;
		++porta;
	} while (porta <= portb);
}

void		scan_option(t_nmap_config *cfg, t_optdata *optd)
{
	const char	*arg = NULL;
	int			i, len;

	while ((arg = parse_comma_list(optd->optarg)) && *arg)
	{
		len = ft_strlen(arg);
		for (i = 0; i < SCAN_COUNT; ++i)
			if (!ft_ignore_case_strncmp(g_nmap_scan_strings[i], arg, len))
				break;
		if (i == SCAN_COUNT)
			ft_exit(EXIT_FAILURE, "invalid scan type: '%s'", arg);
		else if (!cfg->scans[i])
		{
			cfg->scans[i] = 1;
			++cfg->nscans;
		}
	}
	if (!arg || *arg)
		ft_exit(EXIT_FAILURE, "invalid list argument: '%s'", optd->optarg);
}
