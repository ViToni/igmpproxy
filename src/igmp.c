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
**  - Original license can be found in the "doc/mrouted-LINCESE" file.
**
*/
/**
*   igmp.h - Recieves IGMP requests, and handle them 
*            appropriately...
*/

#include <sys/param.h>

#include "defs.h"
 
// Globals                  
uint32     allhosts_group;          /* All hosts addr in net order */
uint32     allrouters_group;        /* All hosts addr in net order */
uint32     allrouters_group_v3;
uint32     v3_genqry_group;
              
extern int MRouterFD;

/*
 * Open and initialize the igmp socket, and fill in the non-changing
 * IP header fields in the output packet buffer.
 */
void initIgmp() {
    struct ip *ip;

    recv_buf = malloc(RECV_BUF_SIZE);
    send_buf = malloc(RECV_BUF_SIZE);

    k_hdr_include(TRUE);    /* include IP header when sending */
    k_set_rcvbuf(256*1024,48*1024); /* lots of input buffering        */
    k_set_ttl(1);       /* restrict multicasts to one hop */
    k_set_loop(FALSE);      /* disable multicast loopback     */

    ip         = (struct ip *)send_buf;
    bzero(ip, sizeof(struct ip));
    /*
     * Fields zeroed that aren't filled in later:
     * - IP ID (let the kernel fill it in)
     * - Offset (we don't send fragments)
     * - Checksum (let the kernel fill it in)
     */
    ip->ip_v   = IPVERSION;
    ip->ip_hl  = (sizeof(struct ip) + 4) >> 2; /* +4 for Router Alert option */
    ip->ip_tos = 0xc0;      /* Internet Control */
    ip->ip_ttl = MAXTTL;    /* applies to unicasts only */
    ip->ip_p   = IPPROTO_IGMP;

    allhosts_group   = htonl(INADDR_ALLHOSTS_GROUP);
    allrouters_group = htonl(INADDR_ALLRTRS_GROUP);
    allrouters_group_v3  = htonl(INADDR_ALLRTRS_GROUP_V3);
    v3_genqry_group      = htonl(INADDR_V3_GENQRY_GROUP);
}

/**
*   Finds the textual name of the supplied IGMP request.
*/
char *igmpPacketKind(u_int type, u_int code) {
    static char unknown[20];

    switch (type) {
    case IGMP_MEMBERSHIP_QUERY:     return  "Membership query  ";
    case IGMP_V1_MEMBERSHIP_REPORT:  return "V1 member report  ";
    case IGMP_V2_MEMBERSHIP_REPORT:  return "V2 member report  ";
    case IGMP_V2_LEAVE_GROUP:        return "Leave message     ";
    case IGMP_V3_MEMBERSHIP_REPORT:  return "V3 member report  ";
    case IGMP_V3_MEMBERSHIP_QUERY:   return "V3 membership query ";
    
    default:
        sprintf(unknown, "unk: 0x%02x/0x%02x    ", type, code);
        return unknown;
    }
}


/**
 * Process a newly received IGMP packet that is sitting in the input
 * packet buffer.
 */
void acceptIgmp(int recvlen) {
    register uint32 src, dst, group;
    struct ip *ip;
    struct igmp *igmp;
    struct igmpv3 *igmp_v3;
    struct igmp_grouprec* igmp_gr;

    int ipdatalen, iphdrlen, igmpdatalen;

    if (recvlen < (int) sizeof(struct ip)) {
        log(LOG_WARNING, 0,
            "received packet too short (%u bytes) for IP header", recvlen);
        return;
    }

    ip        = (struct ip *)recv_buf;
    src       = ip->ip_src.s_addr;
    dst       = ip->ip_dst.s_addr;

    IF_DEBUG log(LOG_DEBUG, 0, "Got a IGMP request to process...");

    /* 
     * this is most likely a message from the kernel indicating that
     * a new src grp pair message has arrived and so, it would be 
     * necessary to install a route into the kernel for this.
     */
    if (ip->ip_p == 0) {
        if (src == 0 || dst == 0) {
            log(LOG_WARNING, 0, "kernel request not accurate");
        }
        else {
            struct IfDesc *checkVIF;
           int downIf = -1;
            
            // Check if the source address matches a valid address on upstream vif.
            checkVIF = getIfByIx( upStreamVif );
            if(checkVIF == 0) {
                log(LOG_ERR, 0, "Upstream VIF was null.");
                return;
            } 
            else if(src == checkVIF->InAdr.s_addr) {
                log(LOG_NOTICE, 0, "Route activation request from %s for %s is from myself. Ignoring.",
                    inetFmt(src, s1), inetFmt(dst, s2));
                return;
            }
            else if(!isAdressValidForIf(checkVIF, src)) {
               unsigned Ix;
               struct IfDesc *Dp;
               for ( Ix = 0; (Dp = getIfByIx( Ix )); Ix++ ) {
                   if ((Dp->state == IF_STATE_DOWNSTREAM) &&isAdressValidForIf(Dp, src)) {
                       downIf = Ix;
                       break;
                   }
               }
               
               if (downIf == -1) {
                log(LOG_WARNING, 0, "The source address %s for group %s, is not in any valid net for upstream VIF.",
                    inetFmt(src, s1), inetFmt(dst, s2));
                return;
               } else {
                   log(LOG_NOTICE, 0, "The source address %s for group %s, is valid DOWNSTREAM VIF #%d.",
                       inetFmt(src, s1), inetFmt(dst, s2), downIf);
               }
            }
            
            // Activate the route.
            IF_DEBUG log(LOG_DEBUG, 0, "Route activate request from %s to %s, downIf %d",
                         inetFmt(src,s1), inetFmt(dst,s2), downIf);
            activateRoute(dst, src, downIf);
            

        }
        return;
    }

    log(LOG_DEBUG, 0, "Packet from %s: proto: %d hdrlen: %d iplen: %d or %d", 
                   inetFmt(src, s1), ip->ip_p, ip->ip_hl << 2, ip->ip_len, ntohs(ip->ip_len));

    iphdrlen  = ip->ip_hl << 2;
#ifdef RAW_INPUT_IS_RAW
    ipdatalen = ntohs(ip->ip_len) - iphdrlen;
#else
    ipdatalen = ip->ip_len;
#endif    

    if (iphdrlen + ipdatalen != recvlen) {
        log(LOG_WARNING, 0,
            "received packet from %s shorter (%u bytes) than hdr+data length (%u+%u)",
            inetFmt(src, s1), recvlen, iphdrlen, ipdatalen);
        return;
    }

    igmp        = (struct igmp *)(recv_buf + iphdrlen);
    igmp_v3     = (struct igmpv3 *)(recv_buf + iphdrlen);

    if (igmp->igmp_type == IGMP_V3_MEMBERSHIP_REPORT){
      igmp_gr     = (struct igmp_grouprec*)((char*)igmp_v3+8); /*  Start of group record */
      group       = igmp_gr->ig_group.s_addr;
    }else
      group       = igmp->igmp_group.s_addr;

    igmpdatalen = ipdatalen - IGMP_MINLEN;
    if (igmpdatalen < 0) {
        log(LOG_WARNING, 0,
            "received IP data field too short (%u bytes) for IGMP, from %s",
            ipdatalen, inetFmt(src, s1));
        return;
    }

    log(LOG_NOTICE, 0, "RECV %s from %-15s to %s (ip_hl %d, data %d)",
        igmpPacketKind(igmp->igmp_type, igmp->igmp_code),
        inetFmt(src, s1), inetFmt(dst, s2), iphdrlen, ipdatalen);

   switch (igmp->igmp_type) {
    case IGMP_V1_MEMBERSHIP_REPORT:
    case IGMP_V2_MEMBERSHIP_REPORT:
        acceptGroupReport(src, group);
        return;
    case IGMP_V3_MEMBERSHIP_REPORT:
        if ( ((u_char*)igmp_v3)[8] == (u_char)4 ){       /* Change To Exclude Mode - join */
          acceptGroupReport(src, group);
        }else if ( ((u_char*)igmp_v3)[8] == (u_char)3 )  /* Change To Include Mode - leave */
          acceptLeaveMessage(src, group);
        else
          log(LOG_WARNING, 0, "unknown Mode in V3 report (%u)", (u_char*)igmp_v3+8);
        return;
    
    case IGMP_V2_LEAVE_GROUP:
        acceptLeaveMessage(src, group);
        return;
    
    case IGMP_MEMBERSHIP_QUERY:
        log(LOG_INFO, 0, "ignoring membership query");
        return;

    default:
        log(LOG_INFO, 0,
            "ignoring unknown IGMP message type %x from %s to %s",
            igmp->igmp_type, inetFmt(src, s1),
            inetFmt(dst, s2));
        return;
    }
}


/*
 * Construct an IGMP message in the output packet buffer.  The caller may
 * have already placed data in that buffer, of length 'datalen'.
 */
void buildIgmp(uint32 src, uint32 dst, int type, int code, uint32 group, int datalen) {
    struct ip *ip;
    struct igmp *igmp;
    struct igmpv3 *igmp_v3;
    struct igmp_report *igmp_rep;
    extern int curttl;

    ip                      = (struct ip *)send_buf;
    ip->ip_src.s_addr       = src;
    ip->ip_dst.s_addr       = dst;
    ip->ip_len              = IP_HEADER_RAOPT_LEN + IGMP_MINLEN + datalen;
#ifdef RAW_OUTPUT_IS_RAW
    ip->ip_len              = htons(ip->ip_len);
#endif
    if (IN_MULTICAST(ntohl(dst))) {
        ip->ip_ttl = curttl;
    } else {
        ip->ip_ttl = MAXTTL;
    }

    // Add Router Alert option
    ((char*)send_buf+MIN_IP_HEADER_LEN)[0] = IPOPT_RA;
    ((char*)send_buf+MIN_IP_HEADER_LEN)[1] = 0x04;
    ((char*)send_buf+MIN_IP_HEADER_LEN)[2] = 0x00;
    ((char*)send_buf+MIN_IP_HEADER_LEN)[3] = 0x00;

    if (type == IGMP_V3_MEMBERSHIP_REPORT){
      ip->ip_dst.s_addr       = allrouters_group_v3;
      ip->ip_len              = IP_HEADER_RAOPT_LEN + IGMP_MINLEN + IGMP_GRPREC_HDRLEN + datalen;
      igmp_rep                    = (struct igmp_report *)(send_buf + IP_HEADER_RAOPT_LEN);
      igmp_rep->ir_type         = type;
      igmp_rep->ir_rsv1         = 0;
      igmp_rep->ir_cksum        = 0;
      igmp_rep->ir_rsv2         = 0;
      igmp_rep->ir_numgrps      = 0x0100;

#if __FreeBSD_version < 800000
      igmp_rep->ir_groups[0].ig_type         = (u_char)4;  /* Change To Exclude Mode */
      igmp_rep->ir_groups[0].ig_datalen      = (u_char)0;  /* length of auxiliary data */
      igmp_rep->ir_groups[0].ig_numsrc       = (u_short)0; /* number of sources */
      igmp_rep->ir_groups[0].ig_group.s_addr = group;      /*  group address being reported */
#endif

      igmp_rep->ir_cksum        = inetChksum((u_short *)igmp_rep,
                                           IGMP_MINLEN + IGMP_GRPREC_HDRLEN + datalen);
    }else if (type == IGMP_V3_MEMBERSHIP_QUERY){
      ip->ip_dst.s_addr          = allhosts_group;
      ip->ip_len                 = IP_HEADER_RAOPT_LEN + IGMP_MINLEN + IGMP_V3_QUERY_HDRLEN + datalen;
      igmp_v3                    = (struct igmpv3 *)(send_buf + IP_HEADER_RAOPT_LEN);
      igmp_v3->igmp_type         = IGMP_MEMBERSHIP_QUERY;
      igmp_v3->igmp_code         = code;
      igmp_v3->igmp_cksum        = 0;
      igmp_v3->igmp_group.s_addr = group;
      igmp_v3->igmp_misc         = 0x2; /* S-flag=0 - Do not suppress router side processing */  
                                        /* QRV   =2 - Querier's Robustness Variable */ 
      igmp_v3->igmp_cksum        = inetChksum((u_short *)igmp_v3,
                                           IGMP_MINLEN + IGMP_V3_QUERY_HDRLEN + datalen);

    }else{
      igmp                    = (struct igmp *)(send_buf + IP_HEADER_RAOPT_LEN);
      igmp->igmp_type         = type;
      igmp->igmp_code         = code;
      igmp->igmp_group.s_addr = group;
      igmp->igmp_cksum        = 0;
      igmp->igmp_cksum        = inetChksum((u_short *)igmp,
                                           IGMP_MINLEN + datalen);
    }
}

/* 
 * Call build_igmp() to build an IGMP message in the output packet buffer.
 * Then send the message from the interface with IP address 'src' to
 * destination 'dst'.
 */
void sendIgmp(uint32 src, uint32 dst, int type, int code, uint32 group, int datalen) {
    struct sockaddr_in sdst;
    struct igmp_report *igmp_rep;
    int setloop = 0, setigmpsource = 0;

    if (type != IGMP_V2_LEAVE_GROUP) /* for leave buld later */
      buildIgmp(src, dst, type, code, group, datalen);

    if (IN_MULTICAST(ntohl(dst))) {
        k_set_if(src);
        setigmpsource = 1;
        if (type != IGMP_DVMRP || dst == allhosts_group) {
            setloop = 1;
            k_set_loop(TRUE);
        }
    }

    bzero(&sdst, sizeof(sdst));
    sdst.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
    sdst.sin_len = sizeof(sdst);
#endif
    if ( type == IGMP_V3_MEMBERSHIP_REPORT ){
        sdst.sin_addr.s_addr = allrouters_group_v3;
        if (sendto(MRouterFD, send_buf,
                   IP_HEADER_RAOPT_LEN + IGMP_MINLEN + IGMP_GRPREC_HDRLEN + datalen, 0,
                  (struct sockaddr *)&sdst, sizeof(sdst)) < 0) {
            if (errno == ENETDOWN)
                log(LOG_ERR, errno, "Sender VIF was down.");
            else
                log(LOG_INFO, errno,
                    "sendto to %s on %s",
                    inetFmt(allrouters_group_v3, s1), inetFmt(src, s2));
        }
        else{
	    IF_DEBUG log(LOG_DEBUG, 0, "SENT %s from %-15s to %s",
                igmpPacketKind(type, code), src == INADDR_ANY ? "INADDR_ANY" :
                inetFmt(src, s1), inetFmt(allrouters_group_v3, s2));
        }
    }else if ( type == IGMP_V3_MEMBERSHIP_QUERY ){
        sdst.sin_addr.s_addr = allhosts_group;
        if (sendto(MRouterFD, send_buf,
                   IP_HEADER_RAOPT_LEN + IGMP_MINLEN + IGMP_V3_QUERY_HDRLEN + datalen, 0,
                  (struct sockaddr *)&sdst, sizeof(sdst)) < 0) {
            if (errno == ENETDOWN)
                log(LOG_ERR, errno, "Sender VIF was down.");
            else
                log(LOG_INFO, errno,
                    "sendto to %s on %s",
                    inetFmt(allhosts_group, s1), inetFmt(src, s2));
        }
        else{
	    IF_DEBUG log(LOG_DEBUG, 0, "SENT %s from %-15s to %s",
                igmpPacketKind(type, code), src == INADDR_ANY ? "INADDR_ANY" :
                inetFmt(src, s1), inetFmt(allhosts_group, s2));
       }
    }else if (type == IGMP_V2_LEAVE_GROUP){
        /* we have to send V3 leave as well */
        buildIgmp(src, allrouters_group_v3, IGMP_V3_MEMBERSHIP_REPORT, code, group, datalen);
        sdst.sin_addr.s_addr = allrouters_group_v3;
        igmp_rep                       = (struct igmp_report *)(send_buf + IP_HEADER_RAOPT_LEN);
#if __FreeBSD_version < 750000
        igmp_rep->ir_groups[0].ig_type = (u_char)3;                 /* Change To Include Mode - leave */
#endif
        igmp_rep->ir_cksum        = inetChksum((u_short *)igmp_rep, /* recalculate checksum */
                                               IGMP_MINLEN + IGMP_GRPREC_HDRLEN + datalen);

        if (sendto(MRouterFD, send_buf,
                   IP_HEADER_RAOPT_LEN + IGMP_MINLEN + IGMP_GRPREC_HDRLEN + datalen, 0,
                   (struct sockaddr *)&sdst, sizeof(sdst)) < 0) {
          if (errno == ENETDOWN)
            log(LOG_ERR, errno, "Sender VIF was down.");
          else
            log(LOG_INFO, errno,
                "sendto to %s on %s",
                inetFmt(allrouters_group_v3, s1), inetFmt(src, s2));
        }
        else{
	  IF_DEBUG log(LOG_DEBUG, 0, "SENT %s from %-15s to %s",
              "V3 report with leave", src == INADDR_ANY ? "INADDR_ANY" :
              inetFmt(src, s1), inetFmt(allrouters_group_v3, s2));
        }
    }else{
        sdst.sin_addr.s_addr = dst;
        if (sendto(MRouterFD, send_buf,
                   IP_HEADER_RAOPT_LEN + IGMP_MINLEN + datalen, 0,
                   (struct sockaddr *)&sdst, sizeof(sdst)) < 0) {
            if (errno == ENETDOWN)
                log(LOG_ERR, errno, "Sender VIF was down.");
            else
                log(LOG_INFO, errno,
                    "sendto to %s on %s",
                    inetFmt(dst, s1), inetFmt(src, s2));
        }
        else{
	    IF_DEBUG log(LOG_DEBUG, 0, "SENT %s from %-15s to %s",
                igmpPacketKind(type, code), src == INADDR_ANY ? "INADDR_ANY" :
                inetFmt(src, s1), inetFmt(dst, s2));
        }
    }

    if(setigmpsource) {
        if (setloop) {
            k_set_loop(FALSE);
        }
        // Restore original...
        k_set_if(INADDR_ANY);
    }

}

