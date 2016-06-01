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

#include "defs.h"
#ifdef __FreeBSD__
#include <ifaddrs.h>
#else
#include <linux/sockios.h>
#endif

struct IfDesc IfDescVc[ MAX_IF ], *IfDescEp = IfDescVc;

/*
** Builds up a vector with the interface of the machine. Calls to the other functions of 
** the module will fail if they are called before the vector is build.
**          
*/
void buildIfVc() {
    struct ifaddrs *ifap, *ifa;
    struct IfDesc *ifp;
    struct SubnetList *net;

    if (getifaddrs(&ifap) < 0)
       log( LOG_ERR, errno, "getifaddrs" );

    /* loop over interfaces and copy interface info to IfDescVc
     */
    {
        // Temp keepers of interface params...
        uint32 addr, subnet, mask;

        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
            char FmtBu[ 32 ];

           if (IfDescEp >= &IfDescVc[ MAX_IF ]) {
               log(LOG_WARNING, 0, "Too many interfaces, skipping %d", ifa->ifa_name);
                continue;
            }

            /* ignore non-IP interfaces
             */
            if ( ifa->ifa_addr->sa_family != AF_INET )
                continue;

           if ((ifp = getIfByName(ifa->ifa_name)) == NULL) {

               strlcpy( IfDescEp->Name, ifa->ifa_name, sizeof( IfDescEp->Name ) );

               log(LOG_DEBUG, 0, "Adding Physical Index value of IF '%s' is %d",
                   IfDescEp->Name, if_nametoindex(IfDescEp->Name));
            
               // Set the index to -1 by default.
               IfDescEp->index = -1;

               // Get the interface adress...
               IfDescEp->InAdr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;

            /* get if flags
            **
            ** typical flags:
            ** lo    0x0049 -> Running, Loopback, Up
            ** ethx  0x1043 -> Multicast, Running, Broadcast, Up
            ** ipppx 0x0091 -> NoArp, PointToPoint, Up 
            ** grex  0x00C1 -> NoArp, Running, Up
            ** ipipx 0x00C1 -> NoArp, Running, Up
            */

               IfDescEp->Flags = ifa->ifa_flags;

            // Set the default params for the IF...
            IfDescEp->state         = IF_STATE_DOWNSTREAM;
            IfDescEp->robustness    = DEFAULT_ROBUSTNESS;
            IfDescEp->threshold     = DEFAULT_THRESHOLD;   /* ttl limit */
            IfDescEp->ratelimit     = DEFAULT_RATELIMIT; 
               IfDescEp->allowednets   = NULL;
               ifp = IfDescEp++;
           }

            // Insert the verified subnet as an allowed net...
            addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
            mask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
            subnet = addr & mask;
            
            net = (struct SubnetList *)malloc(sizeof(struct SubnetList));
            if(net == NULL) log(LOG_ERR, 0, "Out of memory !");
            
            // Create the network address for the IF..
            net->next = ifp->allowednets;
            net->subnet_mask = mask;
            net->subnet_addr = subnet;
            ifp->allowednets = net;

            // Debug log the result...
            IF_DEBUG log( LOG_DEBUG, 0, "buildIfVc: Interface %s Addr: %s, Flags: 0x%04x, Network: %s",
                 ifp->Name,
                 fmtInAdr( FmtBu, ifp->InAdr ),
                 ifp->Flags,
                 inetFmts(subnet,mask, s1));

    }

    }
    freeifaddrs(ifap);
}

/*
** Returns a pointer to the IfDesc of the interface 'IfName'
**
** returns: - pointer to the IfDesc of the requested interface
**          - NULL if no interface 'IfName' exists
**          
*/
struct IfDesc *getIfByName( const char *IfName ) {
    struct IfDesc *Dp;

    for ( Dp = IfDescVc; Dp < IfDescEp; Dp++ )
        if ( ! strcmp( IfName, Dp->Name ) )
            return Dp;

    return NULL;
}

/*
** Returns a pointer to the IfDesc of the interface 'Ix'
**
** returns: - pointer to the IfDesc of the requested interface
**          - NULL if no interface 'Ix' exists
**          
*/
struct IfDesc *getIfByIx( unsigned Ix ) {
    struct IfDesc *Dp = &IfDescVc[ Ix ];
    return Dp < IfDescEp ? Dp : NULL;
}

/**
*   Returns a pointer to the IfDesc whose subnet matches
*   the supplied IP adress. The IP must match a interfaces
*   subnet, or any configured allowed subnet on a interface.
*/
struct IfDesc *getIfByAddress( uint32 ipaddr ) {

    struct IfDesc       *Dp;
    struct SubnetList   *currsubnet;

    for ( Dp = IfDescVc; Dp < IfDescEp; Dp++ ) {
        // Loop through all registered allowed nets of the VIF...
        for(currsubnet = Dp->allowednets; currsubnet != NULL; currsubnet = currsubnet->next) {
            // Check if the ip falls in under the subnet....
            if((ipaddr & currsubnet->subnet_mask) == currsubnet->subnet_addr) {
                return Dp;
            }
        }
    }
    return NULL;
}


/**
*   Returns a pointer to the IfDesc whose subnet matches
*   the supplied IP adress. The IP must match a interfaces
*   subnet, or any configured allowed subnet on a interface.
*/
struct IfDesc *getIfByVifIndex( unsigned vifindex ) {
    struct IfDesc       *Dp;
    if(vifindex>0) {
        for ( Dp = IfDescVc; Dp < IfDescEp; Dp++ ) {
            if(Dp->index == vifindex) {
                return Dp;
            }
        }
    }
    return NULL;
}


/**
*   Function that checks if a given ipaddress is a valid
*   address for the supplied VIF.
*/
int isAdressValidForIf( struct IfDesc* intrface, uint32 ipaddr ) {
    struct SubnetList   *currsubnet;
    
    if(intrface == NULL) {
        return 0;
    }
    // Loop through all registered allowed nets of the VIF...
    for(currsubnet = intrface->allowednets; currsubnet != NULL; currsubnet = currsubnet->next) {

        /*
        IF_DEBUG log(LOG_DEBUG, 0, "Testing %s for subnet %s, mask %s: Result net: %s",
            inetFmt(ipaddr, s1),
            inetFmt(currsubnet->subnet_addr, s2),
            inetFmt(currsubnet->subnet_mask, s3),
            inetFmt((ipaddr & currsubnet->subnet_mask), s4)
            );
            */

        // Check if the ip falls in under the subnet....
        if((ipaddr & currsubnet->subnet_mask) == currsubnet->subnet_addr) {
            return 1;
        }
    }
    return 0;
}


