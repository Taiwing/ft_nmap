/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ip.c                                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/22 15:58:23 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/22 17:09:56 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

size_t		ip_size(const t_ip *ip)
{
	return (ip->family == AF_INET ? sizeof(struct in_addr)
		: ip->family == AF_INET6 ? sizeof(struct in6_addr) : 0);
}

uint8_t		*ip_addr(const t_ip *ip)
{
	return (ip->family == AF_INET ? (uint8_t *)&ip->v4.sin_addr
		: ip->family == AF_INET6 ? (uint8_t *)&ip->v6.sin6_addr : NULL);
}

int			ip_cmp(const t_ip *a, const t_ip *b)
{
	size_t	size = ip_size(a);

	if (size != ip_size(b))
		return ((int)size - (int)ip_size(b));
	return (ft_memcmp(ip_addr(a), ip_addr(b), size));
}

int			ip_apply_mask(t_ip *dest, const t_ip *mask)
{
	size_t	size;
	uint8_t	*d;
	uint8_t	*m;

	if ((size = ip_size(dest)) != ip_size(mask))
		return (1);
	if (!(d = ip_addr(dest)) || !(m = ip_addr(dest)))
		return (1);
	for (size_t i = 0; i < size; ++i)
		d[i] &= m[i];
	return (0);
}

int			ip_same_subnet(const t_ip *a, const t_ip *b, const t_ip *mask)
{
	t_ip	masked_a;
	t_ip	masked_b;

	if (a->family != b->family || mask->family != a->family)
		return (0);
	ft_memcpy(&masked_a, a, sizeof(masked_a));
	ft_memcpy(&masked_b, b, sizeof(masked_b));
	if (ip_apply_mask(&masked_a, mask) || ip_apply_mask(&masked_b, mask))
		return (0);
	return (!ip_cmp(&masked_a, &masked_b));
}

int			ip_is_local(const t_ip *ip, t_netinfo *netinf)
{
	for (t_list *lst = netinf->iflist; lst; lst = lst->next)
	{
		t_ifinfo *ifinf = (t_ifinfo *)lst->content;
		if (ip_same_subnet(ip, &ifinf->ip, &ifinf->netmask))
			return (1);
	}
	return (0);
}
