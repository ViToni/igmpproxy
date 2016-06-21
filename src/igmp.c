/*
**  igmpproxy - IGMP proxy based multicast router 
**  Copyright (C) 2005 Johnny Egeland <johnny@rlo.org>
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
**
**----------------------------------------------------------------------------
**
**  This software is derived work from the following software. The original
**  source code has been modified from it's original state by the author
**  of igmpproxy.
**
**  smcroute 0.92 - Copyright (C) 2001 Carsten Schill <carsten@cschill.de>
**  - Licensed under the GNU General Public License, version 2
**  
**  mrouted 3.9-beta3 - COPYRIGHT 1989 by The Board of Trustees of 
**  Leland Stanford Junior University.
**  - Original license can be found in the Stanford.txt file.
**
*/

/*
**  igmp.h - Recieves IGMP requests, and handle them 
**           appropriately...
*/

#include "igmpproxy.h"
#include "igmpv3.h"
 
// Globals                  
uint32_t    allhosts_group;         // All hosts addr in net order
uint32_t    allrouters_group;       // All routers addr in net order
uint32_t    allrouters_group_v3;    // All routers IGMPv3 addr in net order
uint32_t    v3_genqry_group;

extern int MRouterFD;

/* Prototypes */
void accepGroupReport_v3(
        uint32_t src,
        uint32_t dst,
        struct igmpv3_report *igmpv3, 
        int ipdatalen
);

/*
 * Open and initialize the igmp socket, and fill in the non-changing
 * IP header fields in the output packet buffer.
 */
void initIgmp(void) {
    struct ip *ip;

    recv_buf = malloc(RECV_BUF_SIZE);
    send_buf = malloc(RECV_BUF_SIZE);

    k_hdr_include(true);                // include IP header when sending
    k_set_rcvbuf(256*1024, 48*1024);    // lots of input buffering
    k_set_ttl(1);                       // restrict multicasts to one hop
    k_set_loop(false);                  // disable multicast loopback

    ip         = (struct ip *)send_buf;
    memset(ip, 0, sizeof(struct ip));
    /*
     * Fields zeroed that aren't filled in later:
     * - IP ID (let the kernel fill it in)
     * - Offset (we don't send fragments)
     * - Checksum (let the kernel fill it in)
     */
    ip->ip_v   = IPVERSION;
    ip->ip_hl  = (sizeof(struct ip) + 4) >> 2;  // +4 for Router Alert option
    ip->ip_tos = 0xc0;                          // Internet Control
    ip->ip_ttl = MAXTTL;                        // applies to unicasts only
    ip->ip_p   = IPPROTO_IGMP;

    allhosts_group      = htonl(INADDR_ALLHOSTS_GROUP);
    allrouters_group    = htonl(INADDR_ALLRTRS_GROUP);
    allrouters_group_v3 = htonl(INADDR_ALLRTRS_GROUP_V3);
    v3_genqry_group     = htonl(INADDR_V3_GENQRY_GROUP);
}


/**
 * Process a newly received IGMP packet that is sitting in the input
 * packet buffer.
 */
void acceptIgmp(const int recvlen) {
    register uint32_t src, dst, group;
    struct ip *ip;
    struct igmp *igmp;
    struct igmpv3_report *igmpv3;
    struct igmpv3_grec *grec;
    int ipdatalen, iphdrlen, ngrec, nsrcs, i;

    log_received_IGMP( recvlen );

    if (recvlen < sizeof(struct ip)) {
        my_log(LOG_WARNING, 0,
            "received packet too short (%u bytes) for IP header", recvlen);
        return;
    }

    ip        = (struct ip *)recv_buf;
    src       = ip->ip_src.s_addr;
    dst       = ip->ip_dst.s_addr;

    my_log(LOG_DEBUG, 0, "Received IGMP message from %s for %s",
            inetFmt( src, s1 ),
            inetFmt( dst, s2 )
    );

/*
    // filter local multicast
    if (
        (dst >= htonl(0xEFFFFFFA) && dst <= htonl(0xEFFFFFFF)) ||
        (dst >= htonl(0xE9E9E9E9)) ||
        (dst >= htonl(0xE0FFFFFA) && dst <= htonl(0xE0FFFFFF)) ||
        (dst == htonl(0xE0000016))
    )
    {
        my_log(LOG_DEBUG, 0, "The IGMP message from %s for %s was local multicast. Ignoring.",
                inetFmt(src, s1), inetFmt(dst, s2)
        );

        return;
    }
*/

    /* 
     * this is most likely a message from the kernel indicating that
     * a new src grp pair message has arrived and so, it would be 
     * necessary to install a route into the kernel for this.
     */
    if (ip->ip_p == 0) {
        if (src == 0 || dst == 0) {
            my_log(LOG_WARNING, 0, "kernel request not accurate");
        } else {
            struct IfDesc *checkVIF, *upVIF = NULL, *downVIF = NULL;
            
            // check all upstreams VIFs
            for(i=0; i<MAX_UPS_VIFS; i++) {
                if(-1 != upStreamIfIdx[i]) {
                    // Check if the source address matches a valid address on upstream vif.
                    checkVIF = getIfByIx( upStreamIfIdx[i] );
                    if(NULL == checkVIF) {
                        my_log(LOG_ERR, 0, "Upstream VIF was null.");
                        continue;
                    }
                    if(src == checkVIF->InAdr.s_addr) {
                        my_log(LOG_NOTICE, 0, "Route activation request from %s for %s is from myself. Ignoring.",
                            inetFmt(src, s1),
                            inetFmt(dst, s2)
                        );
                        return;
                    }
                    if(isAdressValidForIf(checkVIF, src)) {
                        upVIF = checkVIF;
                        my_log(LOG_TRACE, 0, "Route activation request from %s for %s is for upstream VIF [%d], IP: %s.",
                            inetFmt(src, s1), 
                            inetFmt(dst, s2),
                            upVIF->vifindex,
                            inetFmt(upVIF->InAdr.s_addr, s3)
                        );
                        break;
                    }
                }
            }

            if (NULL == upVIF) {
                my_log(LOG_WARNING, 0, "The source address %s for group %s, is not in a valid net for any upstream VIF.",
                        inetFmt(src, s1), 
                        inetFmt(dst, s2)
                );
            }

            downVIF = getIfByAddress(src);
            if (downVIF && downVIF->state & IF_STATE_DOWNSTREAM) {
                my_log(LOG_NOTICE, 0, "The source address %s for group %s is from downstream VIF #%d. Ignoring.",
                        inetFmt(src, s1), inetFmt(dst, s2), downVIF->vifindex
                );
                return;
            }

            downVIF = NULL;

            // now check all the downstream VIFs
            for ( int i = 0; i< MAX_IF; i++) {
                checkVIF = getIfByIx( i ); 
                if (checkVIF && checkVIF->state & IF_STATE_DOWNSTREAM) {
                    downVIF = checkVIF;
                    // Activate the route.
                    my_log(LOG_DEBUG, 0, "Route activate request from %s to %s on VIF #%d",
                            inetFmt(src,s1),
                            inetFmt(dst,s2), 
                            downVIF->vifindex 
                    );
                    activateRoute(dst, src, downVIF->vifindex);
                    return;
                }
            }

            if (NULL == downVIF) {
                 my_log(LOG_WARNING, 0, "The source address %s for group %s, is not in any valid net for downstream VIF.",
                     inetFmt(src, s1),
                     inetFmt(dst, s2)
                 );
                 return;
            }
        }
        return;
    }

    iphdrlen  = ip->ip_hl << 2;
    ipdatalen = ip_data_len(ip);

    if (iphdrlen + ipdatalen != recvlen) {
        my_log(LOG_WARNING, 0,
            "received packet from %s shorter (%u bytes) than hdr+data length (%u+%u)",
            inetFmt(src, s1), recvlen, iphdrlen, ipdatalen);
        return;
    }

    // IGMP starts after the IP header
    igmp = (struct igmp *)(recv_buf + iphdrlen);
    if ((ipdatalen < IGMP_MINLEN) ||
        (igmp->igmp_type == IGMP_V3_MEMBERSHIP_REPORT && ipdatalen <= IGMPV3_MINLEN)) {
        my_log(LOG_WARNING, 0,
            "received IP data field too short (%u bytes) for IGMP, from %s",
            ipdatalen,
            inetFmt(src, s1)
        );
        return;
    }

    my_log(LOG_NOTICE, 0, "RECV %s from %-15s to %s",
        igmp_packet_kind(igmp->igmp_type, igmp->igmp_code),
        inetFmt(src, s1),
        inetFmt(dst, s2)
    );

    switch (igmp->igmp_type) {
    case IGMP_V1_MEMBERSHIP_REPORT:
    case IGMP_V2_MEMBERSHIP_REPORT:
        group = igmp->igmp_group.s_addr;
        acceptGroupReport(src, group);
        return;

    case IGMP_V3_MEMBERSHIP_REPORT:
        igmpv3 = (struct igmpv3_report *)(igmp);
        accepGroupReport_v3(src, dst, igmpv3, ipdatalen);
        return;

    case IGMP_V2_LEAVE_GROUP:
        group = igmp->igmp_group.s_addr;
        acceptLeaveMessage(src, group);
        return;
    
    case IGMP_MEMBERSHIP_QUERY:
        my_log(LOG_DEBUG, 0,
            "Ignoring MEMBERSHIP_QUERY message from %s to %s",
            inetFmt(src, s1),
            inetFmt(dst, s2)
        );
        return;

    default:
        my_log(LOG_INFO, 0,
            "ignoring unknown IGMP message type %x from %s to %s",
            igmp->igmp_type,
            inetFmt(src, s1),
            inetFmt(dst, s2)
        );
        return;
    }
}

void accepGroupReport_v3(
        uint32_t src,
        uint32_t dst,
        struct igmpv3_report *igmpv3, 
        int ipdatalen
)
{
    register uint32_t group;
    struct igmpv3_grec *grec;
    int ngrec, nsrcs, i;

    grec = &igmpv3->igmp_grec[0];
    ngrec = ntohs(igmpv3->igmp_ngrec);
    while (ngrec--) {
        if ((uint8_t *)igmpv3 + ipdatalen < (uint8_t *)grec + sizeof(*grec)) {
            break;
        }
        group = grec->grec_mca.s_addr;
        nsrcs = ntohs(grec->grec_nsrcs);
        switch (grec->grec_type) {
            case IGMPV3_MODE_IS_INCLUDE:
            case IGMPV3_CHANGE_TO_INCLUDE:
                if (nsrcs == 0) {
                    
                    acceptLeaveMessage(src, group);
                    break;
                } /* else fall through */
            case IGMPV3_MODE_IS_EXCLUDE:
            case IGMPV3_CHANGE_TO_EXCLUDE:
            case IGMPV3_ALLOW_NEW_SOURCES:
                acceptGroupReport(src, group);
                break;
            case IGMPV3_BLOCK_OLD_SOURCES:
                break;
            default:
                my_log(LOG_INFO, 0,
                    "ignoring unknown IGMPv3 group record type %x from %s to %s for %s",
                    grec->grec_type, inetFmt(src, s1), inetFmt(dst, s2),
                    inetFmt(group, s3));
                break;
        }
        grec = (struct igmpv3_grec *)
            (&grec->grec_src[nsrcs] + grec->grec_auxwords * 4);
    }
}

/*
 * Construct an IGMP message in the output packet buffer.  The caller may
 * have already placed data in that buffer, of length 'datalen'.
 */
static void buildIgmp(uint32_t src, uint32_t dst, int type, int code, uint32_t group, int datalen) {
    struct ip *ip;
    struct igmp *igmp;
    struct igmpv3_query *igmp_qry;
    struct igmpv3_report *igmp_rep;
    extern int curttl;

    ip                      = (struct ip *)send_buf;
    ip->ip_src.s_addr       = src;
    ip->ip_dst.s_addr       = dst;

    ip_set_len(ip, IP_HEADER_RAOPT_LEN + IGMP_MINLEN + datalen);

    if (IN_MULTICAST(ntohl(dst))) {
        ip->ip_ttl = curttl;
    } else {
        ip->ip_ttl = MAXTTL;
    }

    /* Add Router Alert option */
    ((unsigned char*)send_buf+MIN_IP_HEADER_LEN)[0] = IPOPT_RA;
    ((unsigned char*)send_buf+MIN_IP_HEADER_LEN)[1] = 0x04;
    ((unsigned char*)send_buf+MIN_IP_HEADER_LEN)[2] = 0x00;
    ((unsigned char*)send_buf+MIN_IP_HEADER_LEN)[3] = 0x00;

    switch(type) {
    case IGMP_V3_MEMBERSHIP_REPORT:
        ip->ip_dst.s_addr           = allrouters_group_v3;
        ip->ip_len                  = IP_HEADER_RAOPT_LEN + IGMP_MINLEN + IGMP_GRPREC_HDRLEN + datalen;
        igmp_rep                    = (struct igmpv3_report *)(send_buf + IP_HEADER_RAOPT_LEN);
        igmp_rep->igmp_type         = type;
        igmp_rep->igmp_resv1        = 0;
        igmp_rep->igmp_cksum        = 0;
        igmp_rep->igmp_resv2        = 0;
        igmp_rep->igmp_ngrec        = 0x0100;

        igmp_rep->igmp_cksum        = inetChksum((u_short *)igmp_rep,
                                           IGMP_MINLEN + IGMP_GRPREC_HDRLEN + datalen);
        break;
    case IGMP_V3_MEMBERSHIP_QUERY:
        ip->ip_dst.s_addr           = allhosts_group;
        ip->ip_len                  = IP_HEADER_RAOPT_LEN + IGMP_MINLEN + IGMP_V3_QUERY_HDRLEN + datalen;
        igmp_qry                    = (struct igmpv3_query *)(send_buf + IP_HEADER_RAOPT_LEN);
        igmp_qry->igmp_type         = IGMP_MEMBERSHIP_QUERY;
        igmp_qry->igmp_code         = code;
        igmp_qry->igmp_cksum        = 0;
        igmp_qry->igmp_group.s_addr = group;
        igmp_qry->igmp_misc         = 0x2;  // S-flag=0 - Do not suppress router side processing  
                                            // QRV   =2 - Querier's Robustness Variable 
        igmp_qry->igmp_cksum        = inetChksum((u_short *)igmp_qry,
                                           IGMP_MINLEN + IGMP_V3_QUERY_HDRLEN + datalen);
        break;
    default:
        igmp                        = (struct igmp *)(send_buf + IP_HEADER_RAOPT_LEN);
        igmp->igmp_type             = type;
        igmp->igmp_code             = code;
        igmp->igmp_group.s_addr     = group;
        igmp->igmp_cksum            = 0;
        igmp->igmp_cksum            = inetChksum((unsigned short *)igmp,
                                            IP_HEADER_RAOPT_LEN + datalen);
        break;
    }
}

/* 
 * Call build_igmp() to build an IGMP message in the output packet buffer.
 * Then send the message from the interface with IP address 'src' to
 * destination 'dst'.
 */
void sendIgmp(uint32_t src, uint32_t dst, int type, int code, uint32_t group, int datalen) {
    struct sockaddr_in sdst;
    struct igmpv3_report *igmp_rep;
    int setloop = 0, setigmpsource = 0;

    // for leave build later
    if (type != IGMP_V2_LEAVE_GROUP) {
        buildIgmp(src, dst, type, code, group, datalen);
    }

    if (IN_MULTICAST(ntohl(dst))) {
        k_set_if(src);
        setigmpsource = 1;
        if (type != IGMP_DVMRP || dst == allhosts_group) {
            setloop = 1;
            k_set_loop(true);
        }
    }

    memset(&sdst, 0, sizeof(sdst));
    sdst.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
    sdst.sin_len = sizeof(sdst);
#endif

    switch(type) {
    case IGMP_V3_MEMBERSHIP_REPORT:
        sdst.sin_addr.s_addr = allrouters_group_v3;
        if (sendto(MRouterFD, send_buf,
                   IP_HEADER_RAOPT_LEN + IGMP_MINLEN + IGMP_GRPREC_HDRLEN + datalen, 0,
                  (struct sockaddr *)&sdst, sizeof(sdst)) < 0
        ) {
            if (errno == ENETDOWN) {
                my_log(LOG_ERR, errno, "Sender VIF was down.");
            } else {
                my_log(LOG_INFO, errno,
                    "sendto to %s on %s",
                    inetFmt(allrouters_group_v3, s1), 
                    inetFmt(src, s2)
                );
           }
        }
        else {
            my_log(LOG_DEBUG, 0, "SENT %s from %-15s to %s",
                igmp_packet_kind(type, code), src == INADDR_ANY ? "INADDR_ANY" :
                inetFmt(src, s1), 
                inetFmt(allrouters_group_v3, s2)
            );
        }
        break;
    case IGMP_V3_MEMBERSHIP_QUERY:
        sdst.sin_addr.s_addr = allhosts_group;
        if (sendto(MRouterFD, send_buf,
                   IP_HEADER_RAOPT_LEN + IGMP_MINLEN + IGMP_V3_QUERY_HDRLEN + datalen, 0,
                  (struct sockaddr *)&sdst, sizeof(sdst)) < 0) {
            if (errno == ENETDOWN) {
                my_log(LOG_ERR, errno, "Sender VIF was down.");
            } else {
                my_log(LOG_INFO, errno,
                    "sendto to %s on %s",
                    inetFmt(allhosts_group, s1), inetFmt(src, s2));
            }
        }
        else {
            my_log(LOG_DEBUG, 0, "SENT %s from %-15s to %s",
                igmp_packet_kind(type, code), src == INADDR_ANY ? "INADDR_ANY" :
                inetFmt(src, s1), inetFmt(allhosts_group, s2));
       }
        break;
    case IGMP_V2_LEAVE_GROUP:
        sdst.sin_addr.s_addr = allrouters_group_v3;

        /* we have to send V3 leave as well */
        buildIgmp(src, allrouters_group_v3, IGMP_V3_MEMBERSHIP_REPORT, code, group, datalen);
        igmp_rep                  = (struct igmpv3_report *)(send_buf + IP_HEADER_RAOPT_LEN);
        igmp_rep->igmp_cksum        = inetChksum((u_short *)igmp_rep, /* recalculate checksum */
                                               IGMP_MINLEN + IGMP_GRPREC_HDRLEN + datalen);

        if (sendto(MRouterFD, send_buf,
                   IP_HEADER_RAOPT_LEN + IGMP_MINLEN + IGMP_GRPREC_HDRLEN + datalen, 0,
                   (struct sockaddr *)&sdst, sizeof(sdst)) < 0) {
            if (errno == ENETDOWN) {
                my_log(LOG_ERR, errno, "Sender VIF was down.");
            }
            else {
                my_log(LOG_INFO, errno,
                    "sendto to %s on %s",
                    inetFmt(allrouters_group_v3, s1),
                    inetFmt(src, s2)
                );
            }
        }
        else{
            my_log(LOG_DEBUG, 0, "SENT %s from %-15s to %s",
              "V3 report with leave", src == INADDR_ANY ? "INADDR_ANY" :
              inetFmt(src, s1), inetFmt(allrouters_group_v3, s2));
        }
        break;
    default:
        sdst.sin_addr.s_addr = dst;
        if (sendto(MRouterFD, send_buf,
                   IP_HEADER_RAOPT_LEN + IGMP_MINLEN + datalen, 0,
                   (struct sockaddr *)&sdst, sizeof(sdst)) < 0) {
            if (errno == ENETDOWN) {
                my_log(LOG_ERR, errno, "Sender VIF was down.");
            } else {
                my_log(LOG_INFO, errno,
                    "sendto to %s on %s",
                    inetFmt(dst, s1), inetFmt(src, s2));
            }
        }
        else{
            my_log(LOG_DEBUG, 0, "SENT %s from %-15s to %s",
                igmp_packet_kind(type, code), src == INADDR_ANY ? "INADDR_ANY" :
                inetFmt(src, s1), inetFmt(dst, s2));
        }
    }

    if(setigmpsource) {
        if (setloop) {
            k_set_loop(false);
        }
        // Restore original...
        k_set_if(INADDR_ANY);
    }

    my_log(LOG_DEBUG, 0, "SENT %s from %-15s to %s",
            igmp_packet_kind(type, code), src == INADDR_ANY ? "INADDR_ANY" :
            inetFmt(src, s1), inetFmt(dst, s2));
}
