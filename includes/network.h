/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   network.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/22 11:36:28 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/30 09:21:42 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef NETWORK_H
# define NETWORK_H

# include "libft.h"
# include <pcap.h>
# include <time.h>
# include <unistd.h>
# include <errno.h>
# include <stdlib.h>
# include <string.h>
# include <netinet/if_ether.h>
# include <netinet/ip.h>
# include <linux/ipv6.h>
# include <netinet/ip_icmp.h>
# include <linux/icmpv6.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <ifaddrs.h>
# include <net/if.h>

# define IPHDR_MAXSIZE		(sizeof(struct ipv6hdr))
# define LAYER4HDR_MAXSIZE	(sizeof(struct tcphdr))
# define PROBE_MAXSIZE		(IPHDR_MAXSIZE + LAYER4HDR_MAXSIZE)

# define HEADER_MAXSIZE	\
	(sizeof(struct ether_header) + sizeof(struct ipv6hdr)\
	+ sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr)\
	+ sizeof(struct tcphdr))
# define REPLY_MAXSIZE		(sizeof(struct pcap_pkthdr) + HEADER_MAXSIZE)

# define FILTER_BUFSIZE		1024

# define PORT_DEF			45654	//TODO: TBD, not sure we will keep this one

# define IP_HEADER_ICMP		0x01
# define IP_HEADER_TCP		0x06
# define IP_HEADER_UDP		0x11

# define FILTER_MAXLEN		1024

/*
** IP union (better than an unIP union I guess... ROFL) for v4 and v6
*/

typedef union			u_ip
{
	uint16_t			family;
	struct sockaddr_in	v4;
	struct sockaddr_in6	v6;
}						t_ip;

/*
** Interface info
*/

typedef struct		s_ifinfo
{
	char			*name;
	uint16_t		flags;
	t_ip			ip;
	t_ip			netmask;
}					t_ifinfo;

/*
** Network info: (built with getifaddrs())
**
** iflist: list of valid IPv4 or IPv6 network interfaces
** defdev_v4: IPv4 default interface
** defdev_v6: IPv6 default interface
** loopback_v4: IPv4 loopback interface for localhost scanning
** loopback_v6: IPv6 loopback interface for localhost scanning
*/

typedef struct		s_netinfo
{
	t_list			*iflist;
	t_ifinfo		*defdev_v4;
	t_ifinfo		*defdev_v6;
	t_ifinfo		*loopback_v4;
	t_ifinfo		*loopback_v6;
}					t_netinfo;

/*
** Arguments for header initialization functions
*/

typedef struct		s_iph_args
{
	uint8_t			version;
	t_ip			*dstip;
	t_ip			*srcip;
	uint16_t		protocol;
	uint8_t			hop_limit;
	uint16_t		layer5_len;
}					t_iph_args;

typedef struct		s_tcph_args
{
	void			*iphdr;
	uint8_t			version;
	uint16_t		srcp;
	uint16_t		dstp;
	uint32_t		seq;
	uint32_t		ack;
	uint8_t			flags;
	uint16_t		win;
	uint16_t		urp;
}					t_tcph_args;

/*
** IP utility functions
*/

size_t		ip_size(const t_ip *ip);
uint8_t		*ip_addr(const t_ip *ip);
int			ip_cmp(const t_ip *a, const t_ip *b);
int			ip_apply_mask(t_ip *dest, const t_ip *mask);
int			ip_same_subnet(const t_ip *a, const t_ip *b, const t_ip *mask);
int			ip_is_local(const t_ip *ip, t_netinfo *netinf);

/*
** IP headers
*/

int			init_ip_header(void *ipptr, t_iph_args *args);

/*
** Layer 4 Headers
*/

uint32_t	sum_bit16(uint16_t *data, size_t sz);
uint16_t	checksum(uint16_t *data, size_t sz);
int			transport_checksum(int version, void *iphdr,
				uint8_t *packet, uint16_t len);
int			init_udp_header(uint8_t *udp_packet, void *iphdr,
				uint16_t srcp, uint16_t dstp);
int			init_tcp_header(uint8_t *tcp_packet, t_tcph_args *args);

/*
** Print Headers
*/

int			print_ether_type(uint8_t *packet);
int			print_iphdr(void *iphdr, int domain, char *exec);
int			print_nexthdr(void *iphdr, int domain, uint16_t size, char *exec);
int			print_icmphdr(void *icmph, int domain, uint16_t size, char *exec);
void		print_udphdr(struct udphdr *udph);
void		print_tcphdr(struct tcphdr *tcph);
int			print_packet(void *packet, int domain, int size, char *exec);

#endif
