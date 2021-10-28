/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_destinfo.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/27 20:28:02 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/28 07:49:03 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static int	handle_error(const char *target, t_nmap_config *cfg, int ret)
{
	switch (ret)
	{
		case EAI_FAMILY:
		case EAI_AGAIN:
		case EAI_FAIL:
			ft_dprintf(2, "%s: %s: %s\n", cfg->exec,
			target, gai_strerror(ret));
			break;
		default: ft_exit(EXIT_FAILURE, "%s: %s", target, gai_strerror(ret));
	}
	return (1);
}

int		get_destinfo(t_ip *dest_ip, const char *target, t_nmap_config *cfg)
{
	int					ret;
	struct addrinfo		hints = { 0 };
	struct addrinfo		*destinfo = NULL;

	hints.ai_family = cfg->ip_mode == E_IPV4 ? AF_INET
		: cfg->ip_mode == E_IPV6 ? AF_INET6 : AF_UNSPEC;
	if (!(ret = getaddrinfo(target, NULL, &hints, &destinfo))
		&& destinfo->ai_family != AF_INET && destinfo->ai_family != AF_INET6)
		ret = EAI_FAMILY;
	if (!ret)
		ft_memcpy((void *)dest_ip, (void *)destinfo->ai_addr,
			destinfo->ai_addrlen);
	if (destinfo)
		freeaddrinfo(destinfo);
	if (ret)
		return (handle_error(target, cfg, ret));
	return (0);
}
