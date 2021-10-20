/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   init_network.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/20 14:30:11 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/20 14:54:31 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "test_pcap.h"

int	get_network(char *prog, char **dev, char *net, char *mask,
				bpf_u_int32 *netpp)
{
	int				ret;
	char			*ptr;
	struct in_addr	addr;
	bpf_u_int32		netp;
	bpf_u_int32		maskp;
	char			errbuf[PCAP_ERRBUF_SIZE];

	if (!(*dev = pcap_lookupdev(errbuf)))
	{
		dprintf(2, "%s: pcap_lookupdev: %s\n", prog, errbuf);
		return (EXIT_FAILURE);
	}
	if ((ret = pcap_lookupnet(*dev, &netp, &maskp, errbuf)) < 0)
	{
		dprintf(2, "%s: pcap_lookupnet: %s\n", prog, errbuf);
		return (EXIT_FAILURE);
	}
	addr.s_addr = netp;
	if (!(ptr = inet_ntoa(addr)))
	{
		dprintf(2, "%s: inet_ntoa: error\n", prog);
		return (EXIT_FAILURE);
	}
	strncpy(net, ptr, INET6_ADDRSTRLEN);
	addr.s_addr = maskp;
	if (!(ptr = inet_ntoa(addr)))
	{
		dprintf(2, "%s: inet_ntoa: error\n", prog);
		return (EXIT_FAILURE);
	}
	strncpy(mask, ptr, INET6_ADDRSTRLEN);
	*netpp = netp;
	return (EXIT_SUCCESS);
}

int	get_ips(struct sockaddr_in *ipv4, struct sockaddr_in6 *ipv6,
	char *dev, char *prog)
{
	struct ifaddrs	*ifap = NULL, *ifap_too = NULL;
	int				v4 = 0, v6 = 0;

	if (getifaddrs(&ifap) < 0)
	{
		dprintf(2, "%s: getifaddrs: %s\n", prog, strerror(errno));
		return (-1);
	}
	ifap_too = ifap;
	for (; ifap && (!v4 || !v6); ifap = ifap->ifa_next)
	{
		if (ifap->ifa_name && !strcmp(dev, ifap->ifa_name) && ifap->ifa_addr)
		{
			if (!v4 && ifap->ifa_addr->sa_family == AF_INET)
			{
				v4 = 1;
				memcpy(ipv4, ifap->ifa_addr, sizeof(struct sockaddr_in));
			}
			else if (!v6 && ifap->ifa_addr->sa_family == AF_INET6)
			{
				v6 = 2;
				memcpy(ipv6, ifap->ifa_addr, sizeof(struct sockaddr_in6));
			}
		}
	}
	freeifaddrs(ifap_too); //TODO: put in clean ft_atexit handler
	return (v4 + v6);
}
