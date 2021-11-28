/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   interfaces.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/22 12:06:23 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/21 06:24:48 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void		add_interface(t_list **iflist, struct ifaddrs *ifap)
{
	t_ifinfo		interface = { 0 };

	interface.name = ft_strdup(ifap->ifa_name);
	interface.flags = ifap->ifa_flags;
	ft_memcpy(&interface.ip, ifap->ifa_addr,
		ifap->ifa_addr->sa_family == AF_INET ?
		sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
	ft_memcpy(&interface.netmask, ifap->ifa_netmask,
		ifap->ifa_netmask->sa_family == AF_INET ?
		sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
	ft_lst_push_back(iflist, &interface, sizeof(interface));
}

static t_list	*list_interfaces(t_nmap_config *cfg)
{
	t_list			*iflist = NULL;

	if (getifaddrs(&cfg->ifap) < 0)
		ft_exit(EXIT_FAILURE, "getifaddrs: %s", strerror(errno));
	for (struct ifaddrs *ifap = cfg->ifap; ifap; ifap = ifap->ifa_next)
		if ((ifap->ifa_flags & IFF_LOWER_UP) && (ifap->ifa_flags & IFF_UP)
			&& !(ifap->ifa_flags & IFF_DORMANT) && ifap->ifa_name
			&& ifap->ifa_addr && ifap->ifa_netmask
			&& (ifap->ifa_addr->sa_family == AF_INET
			|| ifap->ifa_addr->sa_family == AF_INET6)
			&& ifap->ifa_addr->sa_family == ifap->ifa_netmask->sa_family)
				add_interface(&iflist, ifap);
	freeifaddrs(cfg->ifap);
	cfg->ifap = NULL;
	return (iflist);
}

static void		check_interface(t_netinfo *netinf,
		t_ifinfo *ifinf, const char *dev)
{
	if (!netinf->loopback_v4 && ifinf->ip.family == AF_INET
		&& (ifinf->flags & IFF_LOOPBACK))
		netinf->loopback_v4 = ifinf;
	else if (!netinf->loopback_v6 && ifinf->ip.family == AF_INET6
		&& (ifinf->flags & IFF_LOOPBACK))
		netinf->loopback_v6 = ifinf;
	else if (!netinf->defdev_v4 && ifinf->ip.family == AF_INET
		&& (!dev || !ft_strcmp(dev, ifinf->name)))
		netinf->defdev_v4 = ifinf;
	else if (!netinf->defdev_v6 && ifinf->ip.family == AF_INET6
		&& (!dev || !ft_strcmp(dev, ifinf->name)))
		netinf->defdev_v6 = ifinf;
}

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

void			get_network_info(t_nmap_config *cfg)
{
	t_netinfo	*netinf = &cfg->netinf;

	if (!(netinf->iflist = list_interfaces(cfg)))
		ft_exit(EXIT_FAILURE, "%s: did not find any valid interface", __func__);
	for (t_list *lst = netinf->iflist; lst; lst = lst->next)
		check_interface(netinf, (t_ifinfo *)lst->content, cfg->dev);
	err_check(netinf, cfg, __func__);
	if (!netinf->loopback_v4)
		netinf->loopback_v4 = netinf->defdev_v4;
	if (!netinf->loopback_v6)
		netinf->loopback_v6 = netinf->defdev_v6;
}
