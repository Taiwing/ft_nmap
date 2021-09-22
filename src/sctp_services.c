/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sctp_services.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: yforeau <yforeau@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/09/22 10:06:44 by yforeau           #+#    #+#             */
/*   Updated: 2021/09/22 10:07:29 by yforeau          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

const char	*g_sctp_services[USHRT_MAX + 1][2] = {
	[7]		= { "echo", NULL },
	[9]		= { "discard", "sink null" },
	[20]	= { "ftp-data", "File Transfer [Default Data] | FTP" },
	[21]	= { "ftp", "File Transfer [Control] | File Transfer Protocol [Control]" },
	[22]	= { "ssh", "Secure Shell Login | The Secure Shell (SSH) Protocol" },
	[80]	= { "http", "www-http | www | World Wide Web HTTP" },
	[179]	= { "bgp", "Border Gateway Protocol" },
	[443]	= { "https", "http protocol over TLS/SSL" },
	[1167]	= { "cisco-ipsla", "Cisco IP SLAs Control Protocol" },
	[1812]	= { "radius", "RADIUS authentication protocol (RFC 2138)" },
	[1813]	= { "radacct", "radius-acct | RADIUS accounting protocol (RFC 2139) | RADIUS Accounting" },
	[2049]	= { "nfs", "shilp | Network File System | Network File System - Sun Microsystems" },
	[2225]	= { "rcip-itu", "Resource Connection Initiation Protocol" },
	[2427]	= { "mgcp-gateway", "Media Gateway Control Protocol Gateway" },
	[2904]	= { "m2ua", "SIGTRAN M2UA" },
	[2905]	= { "m3ua", "SIGTRAN M3UA" },
	[2944]	= { "megaco-h248", "Megaco H-248 (Text) | Megaco H-248 | Megaco-H.248 text" },
	[2945]	= { "h248-binary", "Megaco H-248 (Binary) | H248 Binary | Megaco/H.248 binary" },
	[3097]	= { "itu-bicc-stc", "ITU-T Q.1902.1/Q.2150.3" },
	[3565]	= { "m2pa", NULL },
	[3863]	= { "asap-sctp", "asap-udp | asap-tcp | RSerPool ASAP (SCTP) | asap tcp port | asap udp port | asap sctp" },
	[3864]	= { "asap-sctp-tls", "asap-tcp-tls | RSerPool ASAP/TLS (SCTP) | asap/tls tcp port | asap-sctp/tls" },
	[3868]	= { "diameter", NULL },
	[4739]	= { "ipfix", "IP Flow Info Export" },
	[4740]	= { "ipfixs", "IP Flow Info Export over DTLS | ipfix protocol over TLS | ipfix protocol over DTLS" },
	[5060]	= { "sip", "Session Initiation Protocol (SIP)" },
	[5061]	= { "sip-tls", "sips" },
	[5090]	= { "car", "Candidate AR" },
	[5091]	= { "cxtp", "Context Transfer Protocol" },
	[5672]	= { "amqp", NULL },
	[5675]	= { "v5ua", "V5UA application port" },
	[6704]	= { "frc-hp", "ForCES HP (High Priority) channel" },
	[6705]	= { "frc-mp", "ForCES MP (Medium Priority) channel" },
	[6706]	= { "frc-lp", "ForCES LP (Low priority) channel" },
	[7626]	= { "simco", "SImple Middlebox COnfiguration (SIMCO) | SImple Middlebox COnfiguration (SIMCO) Server" },
	[8471]	= { "pim-port", "PIM over Reliable Transport" },
	[9082]	= { "lcs-ap", "LCS Application Protocol" },
	[9084]	= { "aurora", "IBM AURORA Performance Visualizer" },
	[9899]	= { "sctp-tunneling", "SCTP Tunneling (misconfiguration) | SCTP TUNNELING" },
	[9900]	= { "iua", NULL },
	[9901]	= { "enrp-sctp", "enrp | ENRP server channel | enrp server channel" },
	[9902]	= { "enrp-sctp-tls", "ENRP/TLS server channel | enrp/tls server channel" },
	[11997]	= { "wmereceiving", "WorldMailExpress" },
	[11998]	= { "wmedistribution", "WorldMailExpress" },
	[11999]	= { "wmereporting", "WorldMailExpress" },
	[14001]	= { "sua", "De-Registered" },
	[20049]	= { "nfsrdma", "Network File System (NFS) over RDMA" },
	[29118]	= { "sgsap", "SGsAP in 3GPP" },
	[29168]	= { "sbcap", "SBcAP in 3GPP" },
	[29169]	= { "iuhsctpassoc", "HNBAP and RUA Common Association" },
	[36412]	= { "s1-control", "S1-Control Plane (3GPP)" },
	[36422]	= { "x2-control", "X2-Control Plane (3GPP)" },
};
