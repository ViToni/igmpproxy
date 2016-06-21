#define _LINUX_IN_H

#include <linux/types.h>
#include <linux/mroute.h>
#include <linux/sockios.h>
#include <netinet/ip.h>
#include <netinet/igmp.h>
#include <sys/types.h>
#include <ifaddrs.h>

#define IGMP_V3_MEMBERSHIP_REPORT 0x22

#ifndef IGMP_MEMBERSHIP_QUERY
#define IGMP_MEMBERSHIP_QUERY IGMP_HOST_MEMBERSHIP_QUERY
#endif

#define IGMP_V3_MEMBERSHIP_QUERY    0x111 /* it's fake but we have to differentiate between V2 and V3 queries */
#define IGMP_V3_QUERY_HDRLEN        4

#ifndef IGMP_V1_MEMBERSHIP_REPORT
#define IGMP_V1_MEMBERSHIP_REPORT IGMP_v1_HOST_MEMBERSHIP_REPORT
#endif

#ifndef IGMP_V2_MEMBERSHIP_REPORT
#define IGMP_V2_MEMBERSHIP_REPORT IGMP_v2_HOST_MEMBERSHIP_REPORT
#endif

#ifndef IGMP_V3_MEMBERSHIP_REPORT
#define IGMP_V3_MEMBERSHIP_REPORT IGMP_v3_HOST_MEMBERSHIP_REPORT
#endif

#ifndef IGMP_V2_LEAVE_GROUP
#define IGMP_V2_LEAVE_GROUP IGMP_HOST_LEAVE_MESSAGE
#endif


#ifndef INADDR_ALLRTRS_GROUP
// address for multicast mtrace msg
#define INADDR_ALLRTRS_GROUP        ((in_addr_t) 0xe0000002)    // 224.0.0.2
#endif

#define INADDR_ALLRTRS_GROUP_V3     ((in_addr_t) 0xe0000016)    // 224.0.0.22
#define INADDR_V3_GENQRY_GROUP      ((in_addr_t) 0x00000000)    // 0.0.0.0

#define IGMP_GRPREC_HDRLEN          8

static inline unsigned short ip_data_len(const struct ip *ip)
{
    return ntohs(ip->ip_len) - (ip->ip_hl << 2);
}

static inline void ip_set_len(struct ip *ip, unsigned short len)
{
    ip->ip_len = htons(len);
}
