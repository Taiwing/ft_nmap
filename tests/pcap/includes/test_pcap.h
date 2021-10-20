/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   test_pcap.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/20 14:55:56 by yforeau           #+#    #+#             */
/*   Updated: 2021/10/20 14:57:31 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef TEST_PCAP_H
# define TEST_PCAP_H

# include <pcap.h>
# include <time.h>
# include <stdio.h>
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

# define MAX_HEADER_SIZE	\
	(sizeof(struct ether_header) + sizeof(struct ipv6hdr)\
	+ sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr)\
	+ sizeof(struct tcphdr))

# define PACKET_SIZE_MAX	(sizeof(struct pcap_pkthdr) + 1024)

# define PORT_DEF	45654

# define IP_HEADER_ICMP	0x01
# define IP_HEADER_TCP	0x06
# define IP_HEADER_UDP	0x11

typedef struct		s_iph_args
{
	uint8_t			version;
	struct sockaddr	*dstip;
	struct sockaddr	*srcip;
	uint16_t		protocol;
	uint8_t			hop_limit;
	uint16_t		layer5_len;
}					t_iph_args;

typedef struct	s_tcph_args
{
	void		*iphdr;
	uint8_t		version;
	uint16_t	srcp;
	uint16_t	dstp;
	uint32_t	seq;
	uint32_t	ack;
	uint8_t		flags;
	uint16_t	win;
	uint16_t	urp;
}				t_tcph_args;

/*
** Print
*/
int			print_ether_type(int *type, u_char *packet);
int			print_iphdr(void *iphdr, int domain, char *prog);
void		print_udphdr(struct udphdr *udph);
void		print_tcphdr(struct tcphdr *tcph);
int			print_ips(int ip, char *ip4, char *ip6, struct sockaddr_in *ipv4,
				struct sockaddr_in6 *ipv6, char *prog);

/*
** Init Network
*/
int			get_network(char *prog, char **dev, char *net, char *mask,
				bpf_u_int32 *netpp);
int			get_ips(struct sockaddr_in *ipv4, struct sockaddr_in6 *ipv6,
				char *dev, char *prog);

/*
** Grab Packet
*/
pcap_t		*open_device(char *prog, char *dev);
int			set_filter(pcap_t *descr, int ip, char *ip4, char *ip6,
				char *user_filter, char *prog, bpf_u_int32 netp);
int			grab_packet(char *prog, pcap_t *descr, u_char *packet);

/*
** Socket
*/
int			init_socket(int domain, int protocol, char *prog);

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

#endif
