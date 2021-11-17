/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   network.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/22 11:36:28 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/17 11:59:15 by yforeau          ###   ########.fr       */
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

# define FILTER_BUFSIZE		1024

# define PORT_DEF			45654	//TODO: TBD, not sure we will keep this one

# define IP_HEADER_ICMP		0x01
# define IP_HEADER_TCP		0x06
# define IP_HEADER_UDP		0x11
# define IP_HEADER_ICMP6	0x3a

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
** Reply header types and unions
*/

enum e_iphdr	{ E_IH_NONE = 0, E_IH_V4, E_IH_V6 };
enum e_nexthdr	{ E_NH_NONE = 0, E_NH_ICMP, E_NH_ICMP6, E_NH_TCP, E_NH_UDP };

// The first header
typedef union		u_iphdr
{
	struct iphdr	v4;
	struct ipv6hdr	v6;
}					t_iphdr;

// The second header
typedef union		u_nexthdr
{
	struct tcphdr	tcp;
	struct udphdr	udp;
	struct icmphdr	icmp;
	struct icmp6hdr	icmp6;
}					t_nexthdr;

# define RAW_DATA_MAXSIZE	((sizeof(t_iphdr) + sizeof(t_nexthdr)) * 2)
# define HEADER_MAXSIZE		(sizeof(struct ether_header) + RAW_DATA_MAXSIZE)

/*
** t_packet:
**
** iphdr: type of the first ip header
** nexthdr: type of the next header
** nextiphdr: type of the second ip header
** lasthdr: type of nextiphdr's next header
** ip: pointer to ip header if not NONE
** next: pointer to next header
** nextip: pointer to second ip header if not NONE
** last: pointer to next header if any
** size: size of raw data (every headers)
** raw_data: where every headers are stored
** buf: static buffer if the storage is not extern
*/

typedef struct		s_packet
{
	enum e_iphdr	iphdr;
	enum e_nexthdr	nexthdr;
	enum e_iphdr	nextiphdr;
	enum e_nexthdr	lasthdr;
	t_iphdr			*ip;
	t_nexthdr		*next;
	t_iphdr			*nextip;
	t_nexthdr		*last;
	size_t			size;
	uint8_t			*raw_data;
	uint8_t			buf[RAW_DATA_MAXSIZE];
}					t_packet;

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

size_t		ip_sock_size(const t_ip *ip);
size_t		ip_size(const t_ip *ip);
uint8_t		*ip_addr(const t_ip *ip);
int			ip_cmp(const t_ip *a, const t_ip *b);
int			ip_apply_mask(t_ip *dest, const t_ip *mask);
int			ip_same_subnet(const t_ip *a, const t_ip *b, const t_ip *mask);
int			ip_is_local(const t_ip *ip, t_netinfo *netinf);

/*
** IP headers
*/

void		init_ip_header(void *ipptr, t_iph_args *args);

/*
** Layer 4 Headers
*/

uint32_t	sum_bit16(uint16_t *data, size_t sz);
uint16_t	checksum(uint16_t *data, size_t sz);
int			transport_checksum(int version, void *iphdr,
				uint8_t *packet, uint16_t len);
void		init_udp_header(uint8_t *udp_packet, void *iphdr,
				uint16_t srcp, uint16_t dstp);
void		init_tcp_header(uint8_t *tcp_packet, t_tcph_args *args);

/*
** Print Headers
*/

int			print_ether_type(uint8_t *packet);
int			print_iphdr(void *iphdr, int domain, char *exec);
int			print_nexthdr(void *iphdr, int domain, uint16_t size, char *exec);
int			print_icmphdr(void *icmph, int domain, uint16_t size, char *exec);
void		print_udphdr(struct udphdr *udph);
void		print_tcphdr(struct tcphdr *tcph);
int			print_packet(void *packet, int domain, size_t size, char *exec);

/*
** Packet
*/

void		reset_packet(t_packet *packet, uint8_t *datap);
void		init_packet(t_packet *packet, enum e_iphdr iph, uint8_t *datap);

#endif
