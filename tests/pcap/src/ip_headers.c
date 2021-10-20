/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ip_headers.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/20 14:43:09 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/20 14:54:59 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "test_pcap.h"

static void	init_ipv4_header(struct iphdr *ip, t_iph_args *args)
{
	struct sockaddr_in	*ptr;

	bzero(ip, sizeof(struct iphdr));
	ip->ihl = 5;
	ip->version = args->version;
	ip->ttl = args->hop_limit;
	ptr = (struct sockaddr_in *)args->srcip;
	memcpy(&ip->saddr, &ptr->sin_addr, sizeof(struct in_addr));
	ptr = (struct sockaddr_in *)args->dstip;
	memcpy(&ip->daddr, &ptr->sin_addr, sizeof(struct in_addr));
	ip->tot_len = args->layer5_len + sizeof(struct iphdr);
	ip->protocol = args->protocol;
	if (ip->protocol == IP_HEADER_ICMP)
		ip->tot_len += sizeof(struct icmphdr);
	else if (ip->protocol == IP_HEADER_TCP)
		ip->tot_len += sizeof(struct tcphdr);
	else if (ip->protocol == IP_HEADER_UDP)
		ip->tot_len += sizeof(struct udphdr);
	ip->tot_len = htons(ip->tot_len);
}

static void	init_ipv6_header(struct ipv6hdr *ip, t_iph_args *args)
{
	struct sockaddr_in6	*ptr;

	bzero(ip, sizeof(struct ipv6hdr));
	ip->version = args->version;
	ip->hop_limit = args->hop_limit;
	ptr = (struct sockaddr_in6 *)args->srcip;
	memcpy(&ip->saddr, &ptr->sin6_addr, sizeof(struct in6_addr));
	ptr = (struct sockaddr_in6 *)args->dstip;
	memcpy(&ip->daddr, &ptr->sin6_addr, sizeof(struct in6_addr));
	ip->payload_len = args->layer5_len;
	ip->nexthdr = args->protocol;
	if (ip->nexthdr == IP_HEADER_ICMP)
		ip->payload_len += sizeof(struct icmp6hdr);
	else if (ip->nexthdr == IP_HEADER_TCP)
		ip->payload_len += sizeof(struct tcphdr);
	else if (ip->nexthdr == IP_HEADER_UDP)
		ip->payload_len += sizeof(struct udphdr);
	ip->payload_len = htons(ip->payload_len);
}

int			init_ip_header(void *ipptr, t_iph_args *args)
{
	if ((args->version != 4 && args->version != 6)
		|| !args->dstip || !args->srcip)
		return (1);
	if (args->version == 4)
		init_ipv4_header((struct iphdr *)ipptr, args);
	else
		init_ipv6_header((struct ipv6hdr *)ipptr, args);
	return (0);
}
