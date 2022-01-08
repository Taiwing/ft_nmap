/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   heatmap_report.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/08 04:50:11 by yforeau           #+#    #+#             */
/*   Updated: 2022/01/08 05:00:15 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void		heatmap_report(t_host_job *host_job, t_nmap_config *cfg)
{
	port_report(host_job, cfg);
	//TODO:
	//- build a 64x16 matrix for the standard 1024 port scan
	//- build intermediary matrices for smaller scan sweeps
	//- add port numbers on the sides as a reference
	//- if complete is set show an independant heatmap for each scan type
	//- otherwise if there is multiple scans, simply "add" the colors
}
