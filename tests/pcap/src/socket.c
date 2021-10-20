/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   socket.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/20 14:39:24 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/20 14:54:53 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "test_pcap.h"

int	init_socket(int domain, int protocol, char *prog)
{
	int	sfd, one, ret;

	one = 1;
	if ((sfd = socket(domain, SOCK_RAW, protocol)) < 0)
	{
		dprintf(2, "%s: socket: %s\n", prog, strerror(errno));
		return (-1);
	}
	ret = -2;
	if (domain == AF_INET)
		ret = setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(int));
	else if (domain == AF_INET6)
		ret = setsockopt(sfd, IPPROTO_IPV6, IPV6_HDRINCL, &one, sizeof(int));
	if (ret == -2)
		dprintf(2, "%s: %s: domain must be AF_INET or AF_INET6\n",
			prog, __func__);
	else if (ret < 0)
		dprintf(2, "%s: setsockopt: %s\n", prog, strerror(errno));
	if (ret < 0)
	{
		close(sfd);
		return (ret);
	}
	return (sfd);
}
