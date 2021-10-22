/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   server.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/20 17:22:31 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/21 18:52:27 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "test_pcap.h"

pcap_t	*server_init(int timeout, char *dev, char *ip4, char *ip6,
		uint16_t sport, uint16_t dport, bpf_u_int32 netp, char *prog)
{
	pcap_t	*descr = NULL;
	char	filter[FILTER_MAXLEN] = { 0 };

	if (sport && dport)
	{
		snprintf(filter, FILTER_MAXLEN, "(dst port %1$hu && src port %2$hu) "
			"|| (icmp || icmp6)", sport, dport);
		printf("DEBUG: filter: %s\n", filter); //TEMP
	}
	printf("\n---- Initialize server ----\n");
	if (!(descr = open_device(dev, HEADER_SIZE_MAX, timeout, prog)))
		return (NULL);
	if (set_filter(descr, 3, ip4, ip6, filter, prog, netp))
	{
		pcap_close(descr);
		return (NULL);
	}
	return (descr);
}
