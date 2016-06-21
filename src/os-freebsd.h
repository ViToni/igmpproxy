#include <net/route.h>
#include <netinet/in_systm.h>
#include <netinet/ip_mroute.h>
#include <netinet/ip.h>
#include <netinet/igmp.h>
#include <ifaddrs.h>

#if __FreeBSD_version >= 800069 && defined BURN_BRIDGES \
    || __FreeBSD_version >= 800098
#define IGMP_MEMBERSHIP_QUERY IGMP_HOST_MEMBERSHIP_QUERY
#define IGMP_V1_MEMBERSHIP_REPORT IGMP_v1_HOST_MEMBERSHIP_REPORT
#define IGMP_V2_MEMBERSHIP_REPORT IGMP_v2_HOST_MEMBERSHIP_REPORT
#define IGMP_V2_LEAVE_GROUP IGMP_HOST_LEAVE_MESSAGE
#endif

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
#define INADDR_ALLRTRS_GROUP     ((in_addr_t) 0xe0000002)    // 224.0.0.2
#endif

#define INADDR_ALLRTRS_GROUP_V3     ((in_addr_t) 0xe0000016)    // 224.0.0.22
//#define INADDR_ALLIGMPV3_GROUP      ((in_addr_t) 0xe0000016)    // 224.0.0.22
#define INADDR_V3_GENQRY_GROUP      ((in_addr_t) 0x00000000)    // 0.0.0.0


static inline unsigned short ip_data_len(const struct ip *ip)
{
#if __FreeBSD_version >= 1100030
    return ntohs(ip->ip_len) - (ip->ip_hl << 2);
#elif __FreeBSD_version >= 900044
    return ip->ip_len - (ip->ip_hl << 2);
#else
    return ip->ip_len;
#endif
}

static inline void ip_set_len(struct ip *ip, unsigned short len)
{
#if __FreeBSD_version >= 1100030
    ip->ip_len = htons(len);
#else
    ip->ip_len = len;
#endif
}
