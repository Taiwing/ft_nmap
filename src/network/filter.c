/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   filter.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/18 08:01:16 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/05 16:26:48 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

#define SET_FILTER_ERRBUF_SIZE	(PCAP_ERRBUF_SIZE + 128)

static void		set_filter_internal(char *filter, t_nmap_config *cfg)
{
	int					ret;
	struct bpf_program	fp = { 0 };
	char				errbuf[SET_FILTER_ERRBUF_SIZE + 1] = { 0 };
	//TODO: check the netp value, I'm not sure this is valid
	bpf_u_int32			netp = cfg->host_job.family == AF_INET ?
		PCAP_NETMASK_UNKNOWN : cfg->host_job.dev->netmask.v4.sin_addr.s_addr;

	if (cfg->debug)
		debug_listener_setup(cfg, filter);
	if (pcap_compile(cfg->descr, &fp, filter, 1, netp) == PCAP_ERROR)
	{
		ft_snprintf(errbuf, SET_FILTER_ERRBUF_SIZE,
			"pcap_compile: %s", pcap_geterr(cfg->descr));
		ft_exit(EXIT_FAILURE, errbuf);
	}
	ret = pcap_setfilter(cfg->descr, &fp);
	pcap_freecode(&fp);
	if (ret == PCAP_ERROR)
	{
		ft_snprintf(errbuf, SET_FILTER_ERRBUF_SIZE,
			"pcap_setfilter: %s", pcap_geterr(cfg->descr));
		ft_exit(EXIT_FAILURE, errbuf);
	}
}

#define HOST_FILTER			"(%1$s src host %2$s && %1$s dst host %3$s)"

#define LAYER4_PORT_FILTER	"(%1$s src port %2$hu && %1$s dst port %3$hu)"
#define ICMP_UDP_FILTER		"icmp[17] == "xstr(IP_HEADER_UDP)
#define ICMP_TCP_FILTER		"icmp[17] == "xstr(IP_HEADER_TCP)
#define ICMP_PORT_FILTER	"icmp[28:2] == %1$hu && icmp[30:2] == %2$hu"
#define ICMP6_UDP_FILTER	"ip6[54] == "xstr(IP_HEADER_UDP)
#define ICMP6_TCP_FILTER	"ip6[54] == "xstr(IP_HEADER_TCP)
#define ICMP6_PORT_FILTER	"ip6[88:2] == %1$hu && ip6[90:2] == %2$hu"

#define LAYER4_PORT_RANGE_FILTER	\
	"(%1$s src portrange %2$hu-%4$hu && %1$s dst portrange %3$hu-%5$hu)"
#define ICMP_PORT_RANGE_FILTER		\
	"(icmp[28:2] >= %1$hu && icmp[28:2] <= %3$hu "\
	"&& icmp[30:2] >= %2$hu && icmp[30:2] <= %4$hu)"
#define ICMP6_PORT_RANGE_FILTER		\
	"(ip6[88:2] >= %1$hu && ip6[88:2] <= %3$hu "\
	"&& ip6[90:2] >= %2$hu && ip6[90:2] <= %4$hu)"

#define HAS_UDP 1
#define HAS_TCP 2

static void set_icmp_port_filter(char *filter, char *buf, uint16_t args[7])
{
	uint16_t	is_range = args[0];
	uint16_t	family = args[1];
	uint16_t	layer4 = args[2];
	uint16_t	dstp[2] = { args[3], args[4] };
	uint16_t	srcp[2] = { args[5], args[6] };

	ft_snprintf(buf, FILTER_MAXLEN, layer4 == (HAS_UDP | HAS_TCP) ?
		"(%1$s || %2$s)" : layer4 == HAS_UDP ? "%1$s" : "%2$s",
		family == AF_INET ? ICMP_UDP_FILTER : ICMP6_UDP_FILTER,
		family == AF_INET ? ICMP_TCP_FILTER : ICMP6_TCP_FILTER);
	ft_strlcat(filter, " || (", FILTER_MAXLEN);
	ft_strlcat(filter, buf, FILTER_MAXLEN);
	ft_strlcat(filter, " && ", FILTER_MAXLEN);
	ft_snprintf(buf, FILTER_MAXLEN, !is_range ?
		(family == AF_INET ? ICMP_PORT_FILTER : ICMP6_PORT_FILTER) :
		(family == AF_INET ? ICMP_PORT_RANGE_FILTER : ICMP6_PORT_RANGE_FILTER),
		srcp[0], dstp[0], srcp[1], dstp[1]);
	ft_strlcat(filter, buf, FILTER_MAXLEN);
	ft_strlcat(filter, "))", FILTER_MAXLEN);
}

static void	build_port_filters(char *filter, uint16_t family,
		t_nmap_config *cfg, t_scan_job *scan_job)
{
	char		*layer4str = NULL;
	uint16_t	layer4 = HAS_UDP | HAS_TCP;
	char		buf[FILTER_MAXLEN + 1] = { 0 };
	uint16_t	nscan_jobs = cfg->nscans * cfg->nports;
	uint16_t	dstp[2] = {
		scan_job ? scan_job->dstp : cfg->ports[0], cfg->ports[cfg->nports - 1]
	};
	uint16_t	srcp[2] = {
		scan_job ? scan_job->srcp : PORT_DEF, PORT_DEF + nscan_jobs - 1
	};

	if (!cfg->scans[E_UDP] || (scan_job && scan_job->type != E_UDP))
		layer4 = HAS_TCP;
	else if (cfg->nscans == 1 || (scan_job && scan_job->type == E_UDP))
		layer4 = HAS_UDP;
	layer4str = layer4 == HAS_TCP ? "tcp" : layer4 == HAS_UDP ? "udp" : "";
	ft_snprintf(buf, FILTER_MAXLEN,
		scan_job ? LAYER4_PORT_FILTER : LAYER4_PORT_RANGE_FILTER,
		layer4str, dstp[0], srcp[0], dstp[1], srcp[1]);
	ft_strlcat(filter, " && (", FILTER_MAXLEN);
	ft_strlcat(filter, buf, FILTER_MAXLEN);
	set_icmp_port_filter(filter, buf, (uint16_t[7]){ !scan_job, family, layer4,
		dstp[0], dstp[1], srcp[0], srcp[1] });
}

void		set_filter(t_nmap_config *cfg, t_scan_job *scan_job)
{
	t_ip		*src = &cfg->host_job.dev->ip, *dst = &cfg->host_job.ip;
	uint16_t	family = cfg->host_job.family;
	char		srcbuf[INET6_ADDRSTRLEN + 1], dstbuf[INET6_ADDRSTRLEN + 1];
	char		filter[FILTER_MAXLEN + 1] = { 0 };

	ft_snprintf(filter, FILTER_MAXLEN, HOST_FILTER,
		family == AF_INET ? "ip" : "ip6",
		inet_ntop(family, ip_addr(dst), dstbuf, INET6_ADDRSTRLEN),
		inet_ntop(family, ip_addr(src), srcbuf, INET6_ADDRSTRLEN));
	build_port_filters(filter, family, cfg, scan_job);
	set_filter_internal(filter, cfg);
}
