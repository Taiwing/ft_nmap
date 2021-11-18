/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   listen.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/30 07:37:42 by yforeau           #+#    #+#             */
/*   Updated: 2021/11/18 08:01:07 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	open_device(t_nmap_config *cfg, int maxlen, int timeout)
{
	char	errbuf[PCAP_ERRBUF_SIZE];

	if (!(cfg->descr = pcap_open_live(NULL, maxlen, 0, timeout, errbuf)))
		ft_exit(EXIT_FAILURE, "pcap_open_live: %s\n", errbuf);
	if ((cfg->linktype = pcap_datalink(cfg->descr)) == PCAP_ERROR_NOT_ACTIVATED)
		ft_exit(EXIT_FAILURE, "%s: pcap_datalink failure", __func__);
	if (cfg->linktype != DLT_LINUX_SLL && cfg->linktype != DLT_LINUX_SLL2)
		ft_exit(EXIT_FAILURE, "%s: unsupported link layer type: %d", __func__,
			cfg->linktype);
	cfg->linkhdr_size = cfg->linktype == DLT_LINUX_SLL ?
		sizeof(struct sll_header) : sizeof(struct sll2_header);
}

int			ft_listen(t_packet *reply, pcap_t *descr,
				pcap_handler callback, int cnt)
{
	int	r;

	if ((r = pcap_dispatch(descr, cnt, callback,
			(uint8_t *)reply)) == PCAP_ERROR)
		ft_exit(EXIT_FAILURE, "pcap_dispatch: pcap error");
	else if (r == PCAP_ERROR_BREAK)
		return (-1);
	return (0);
}
