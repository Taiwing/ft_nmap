/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   interfaces.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/22 12:06:23 by yforeau           #+#    #+#             */
/*   Updated: 2022/03/04 08:56:37 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void		err_check(t_netinfo *netinf, t_nmap_config *cfg,
		const char *fstr)
{
	const char	*type = cfg->ip_mode == E_IPV4 ? "any IPv4"
		: cfg->ip_mode == E_IPV6 ? "any IPv6" : "any";

	if ((!netinf->defdev_v4 && !netinf->defdev_v6)
		|| (cfg->ip_mode == E_IPV4 && !netinf->defdev_v4)
		|| (cfg->ip_mode == E_IPV6 && !netinf->defdev_v6))
	{
		ft_exit(EXIT_FAILURE, cfg->dev ?
			"%s: did not find %s interface named '%s'"
			: "%s: did not find %s interface",
			fstr, type, cfg->dev);
	}
	else if (cfg->ip_mode == E_IPALL && !netinf->defdev_v6)
		cfg->ip_mode = E_IPV4;
	else if (cfg->ip_mode == E_IPALL && !netinf->defdev_v4)
		cfg->ip_mode = E_IPV6;
}

static void		set_user_interface(t_netinfo *netinf,
	const char *dev, t_list *iflist)
{
	for (t_list *lst = iflist; lst; lst = lst->next)
	{
		t_ifinfo *ifinfo = lst->content;
		if (ft_strcmp((char *)dev, ifinfo->name))
			continue;
		ft_net_setiface(ifinfo->flags & IFF_LOOPBACK, ifinfo);
		if (ifinfo->ip.family == AF_INET)
		{
			ft_memcpy(&netinf->iface[0], ifinfo, sizeof(t_ifinfo));
			netinf->defdev_v4 = &netinf->iface[0];
		}
		else
		{
			ft_memcpy(&netinf->iface[1], ifinfo, sizeof(t_ifinfo));
			netinf->defdev_v6 = &netinf->iface[1];
		}
	}
}

void			get_network_info(t_nmap_config *cfg)
{
	t_list		*iflist = NULL;
	t_netinfo	*netinf = &cfg->netinf;

	if (!(iflist = ft_net_listiface()))
		ft_exit(EXIT_FAILURE, "%s: did not find any valid interface", __func__);
	if (ft_netconf_init(iflist) < 0)
		ft_exit(EXIT_FAILURE, "ft_netconf_init: %s", ft_strerror(ft_errno));
	if (!cfg->dev && !ft_net_getiface(&netinf->iface[0], AF_INET, 0))
		netinf->defdev_v4 = &netinf->iface[0];
	if (!cfg->dev && !ft_net_getiface(&netinf->iface[1], AF_INET6, 0))
		netinf->defdev_v6 = &netinf->iface[1];
	if (!ft_net_getiface(&netinf->iface[2], AF_INET, 1))
		netinf->loopback_v4 = &netinf->iface[2];
	if (!ft_net_getiface(&netinf->iface[3], AF_INET6, 1))
		netinf->loopback_v6 = &netinf->iface[3];
	if (cfg->dev)
		set_user_interface(netinf, cfg->dev, iflist);
	err_check(netinf, cfg, __func__);
	if (!netinf->loopback_v4)
		netinf->loopback_v4 = netinf->defdev_v4;
	if (!netinf->loopback_v6)
		netinf->loopback_v6 = netinf->defdev_v6;
}
