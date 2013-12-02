/**********************************************************************
 * Copyright (C) (2004) (Jack Louis) <jack@dyadsecurity.com>          *
 *                                                                    *
 * This program is free software; you can redistribute it and/or      *
 * modify it under the terms of the GNU General Public License        *
 * as published by the Free Software Foundation; either               *
 * version 2 of the License, or (at your option) any later            *
 * version.                                                           *
 *                                                                    *
 * This program is distributed in the hope that it will be useful,    *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      *
 * GNU General Public License for more details.                       *
 *                                                                    *
 * You should have received a copy of the GNU General Public License  *
 * along with this program; if not, write to the Free Software        *
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.          *
 **********************************************************************/
#include <config.h>

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>

#ifdef WITH_IF_DL
#include <net/if_dl.h>
#endif

#include <arch.h>

#include <settings.h>
#include <xmalloc.h>
#include <output.h>

#define ROUTE_FILE "/proc/net/route"

#if defined(HAVE_PROC_NET_ROUTE)
int get_default_route_interface(char **dev_name) {
	FILE *route_file=NULL;
	char devname[32], fbuf[128];
	int ret=0, flags=0, refcnt=0, use=0, metric=0, mtu=0;
	uint32_t mask=0, gateway=0, dest=0;

	route_file=fopen(ROUTE_FILE, "r");
	if (route_file == NULL) {
		MSG(M_ERR, "open route file fails: %s", strerror(errno));
		return -1;
	}

	if (fgets(fbuf, sizeof(fbuf) -1, route_file) == NULL) {
		MSG(M_ERR, "cant read route file: %s", strerror(errno));
		return -1;
	}

	while (1) {
		if (fgets(fbuf, sizeof(fbuf) -1, route_file) == NULL) break;


		memset(devname, 0, sizeof(devname));
		if (strlen(fbuf) < 5) continue;
		if (sscanf(fbuf, "%31s %x %x %d %d %d %d %x %d", devname, &dest, &gateway, &flags, &refcnt, &use, &metric, &mask, &mtu) >5) {
		/*                 If  DstGw Fl RC U  M  Mask Mtu Window IRTT */
			struct in_addr ia;
			char dest_s[32], gw_s[32], mask_s[32], min_d[32], max_d[32];

			ia.s_addr=dest;
			snprintf(dest_s, sizeof(dest_s) -1, "%s", inet_ntoa(ia));
			ia.s_addr=gateway;
			snprintf(gw_s, sizeof(gw_s) -1, "%s", inet_ntoa(ia));
			ia.s_addr=mask;
			snprintf(mask_s, sizeof(mask_s) -1, "%s", inet_ntoa(ia));
			ia.s_addr=htonl(s->_low_ip);
			sprintf(min_d, "%s", inet_ntoa(ia));
			ia.s_addr=htonl(s->_high_ip);
			sprintf(max_d, "%s", inet_ntoa(ia));

			/*
			 * route matching, take the first route we find by interface 
			 * this isnt well tested ;] im in a hurry right now, but it should work with
			 * split default routes like with freeswan's 0.0.0.0/1 and 128.0.0.0/1 def routes and
			 * it should also find local interfaces for networks unless you go nuts and get the netmask wrong
			 * XXX we need to mark distance to find out if we need to do arp scanning first XXX
			 */

			if (htonl(dest) == (s->_high_ip & htonl(mask)) && htonl(dest) == (s->_low_ip & htonl(mask))) {
				if (s->verbose > 2) MSG(M_VERB, "NETWORK Default Interface is: Ifname `%s' Dest `%s' Gateway `%s' mask `%s' mtu `%d'", devname, dest_s, gw_s, mask_s, mtu);
				*dev_name=(char *)xmalloc(strlen(devname) + 1);
				sprintf(*dev_name, "%s", devname);
				ret=1;
				break;
			}
			if (s->verbose > 2) {
				MSG(M_VERB, "route for interface `%s' dest `%s' gateway `%s' mask `%s' metric %d doesnt match what i want with min host %s and max host %s", devname, dest_s, gw_s, mask_s, metric, min_d, max_d);
			}
		}
		else {
			MSG(M_ERR, "I shouldn't have told you that, I should not have told you that");
			return -1;
		}
	}
	fclose(route_file);

	return ret;
}

#else

#include <pcap.h>
/* heh, ok its crunch time, lets hear it for pcap everyone! */

int get_default_route_interface(char **dev_name) {
	char errbuf[PCAP_ERRBUF_SIZE];
                                                                                
	memset(errbuf, 0, sizeof(errbuf));
	*dev_name=pcap_lookupdev(errbuf);
	if (*dev_name == NULL) {
		MSG(M_ERR, "pcap_lookupdev fails: `%s'", errbuf);
		return -1;
	}
	return 1;
}
#endif

#ifdef SOLARIS
#include <sys/sockio.h>

int get_interface_info(const char *dev, interface_info_t *ii) {
	int st=-1;
	struct ifreq ifr;

	assert(dev != NULL && ii != NULL);

	memset(&ifr, 0, sizeof(ifr));

	st=socket(AF_INET, SOCK_DGRAM, 0);
	if (st < 0) {
		MSG(M_ERR, "create socket fails: %s", strerror(errno));
		return -1;
	}

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name) -1, "%s", dev);
	/* network address */
	if (ioctl(st, SIOCGIFADDR, &ifr) < 0) {
		MSG(M_ERR, "SIOCGIFADDR: %s, does the interface have a working configuration?", strerror(errno));
		return -1;
	}
	if (ifr.ifr_addr.sa_family == AF_INET) {
		union {
			struct sockaddr *ptr;
			struct sockaddr_in *si;
		} s_u;
		struct in_addr ia;

		s_u.ptr=&ifr.ifr_addr;
		ia.s_addr=s_u.si->sin_addr.s_addr;
		memcpy(&ii->myaddr, &ifr.ifr_addr, sizeof(ii->myaddr));

		snprintf(ii->myaddr_s, sizeof(ii->myaddr_s) -1, "%s", inet_ntoa(ia));
	}
	else {
		snprintf(ii->myaddr_s, sizeof(ii->myaddr_s) -1, "Unknown");
	}

	snprintf(ii->hwaddr_s, sizeof(ii->hwaddr_s) -1, "00:00:00:00:00:00");

	/* mtu */
	if (ioctl(st, SIOCGIFMTU, &ifr) < 0) {
		MSG(M_ERR, "SIOCGIFMTU: %s", strerror(errno));
		return -1;
	}
#ifndef ifr_mtu
#define ifr_mtu ifr_metric
#endif
	ii->mtu=(uint16_t)ifr.ifr_mtu;

	close(st);
	return 1;
}
#elif !defined(SIOCGIFHWADDR) && !defined(SIOCIFMAC)
/*
 * enter plan b, getifaddrs
 * funny enough, it doesnt return link layer stuff on linux :]
 * of course we havent even started the fun stuff yet, solaris is next!
 */
  #ifndef HAVE_GETIFADDRS
   #warning you are trying to mess me up arent you....
  #endif
  #ifndef WITH_IF_DL
   #warning you have ifaddrs defined but you lack the header if_dl.h, recheck config.h and read the comments please
  #endif

int get_interface_info(const char *interface_str, interface_info_t *ii) {
	struct ifaddrs *ifa=NULL, *walk=NULL;

	assert(ii != NULL && interface_str != NULL);
	memset(ii, 0, sizeof(interface_info_t));

	if (getifaddrs(&ifa) < 0) {
		perror("getifaddrs");
		exit(1);
	}

	for (walk=ifa; walk != NULL ; walk=walk->ifa_next) {

		if (strcmp(walk->ifa_name, interface_str) != 0) {
			continue;
		}

		/* obviously, the best thing to do in this case is to HARD CODE IN THE MTU OF THE INTERFACE CAUSE I DONT CARE ANYMORE */
		ii->mtu=1500;

		if (walk->ifa_addr->sa_family == AF_INET) {
			union {
				struct sockaddr *ptr;
				struct sockaddr_in *si;
			} s_u;
			struct in_addr ia;

			s_u.ptr=walk->ifa_addr;
			ia.s_addr=s_u.si->sin_addr.s_addr;

			memcpy(&ii->myaddr, s_u.si, sizeof(ii->myaddr));
			snprintf(ii->myaddr_s, sizeof(ii->myaddr_s) -1, "%s", inet_ntoa(ia));
		}
		else if (walk->ifa_addr->sa_family == AF_LINK) {
			union {
				struct sockaddr *ptr;
				struct sockaddr_dl *mo;
			} s_u;
			int j=0;

			/*
			 * but what if the interface has more than one hardware address? we will get the last one... plus
			 * WHO DOES THAT SORT OF THING?
			 */
			s_u.ptr=walk->ifa_addr;
			if (s_u.mo->sdl_alen != THE_ONLY_SUPPORTED_HWADDR_LEN) {
				//printf("Consider ripping interface `%s' from your machine, as its link layer address isnt what this lazy programmer is looking for\n", walk->ifa_name);
				continue; /* not supported here!, pound sand you evil interface */
			}

			memcpy(&ii->hwaddr[0], LLADDR(s_u.mo), THE_ONLY_SUPPORTED_HWADDR_LEN);

			snprintf(ii->hwaddr_s, sizeof(ii->hwaddr_s) -1, "%.02x:%.02x:%.02x:%.02x:%.02x:%.02x", ii->hwaddr[0], ii->hwaddr[1],
			ii->hwaddr[2], ii->hwaddr[3], ii->hwaddr[4], ii->hwaddr[5]);
		}
	}

	freeifaddrs(ifa);

	return 1;
}

#else
 #ifndef SIOCIFMAC
  #ifndef SIOCGIFHWADDR
   #error wow, this isnt going to work, im so sorry
  #endif
  #define SIOCGIFMAC SIOCGIFHWADDR
 #endif

/* old and busted ioctl interface */
int get_interface_info(const char *dev, interface_info_t *ii) {
	int st=-1;
	struct ifreq ifr;

	assert(dev != NULL && ii != NULL);

	memset(&ifr, 0, sizeof(ifr));

	st=socket(AF_INET, SOCK_DGRAM, 0);
	if (st < 0) {
		MSG(M_ERR, "create socket fails: %s", strerror(errno));
		return -1;
	}

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name) -1, "%s", dev);
	/* network address */
	if (ioctl(st, SIOCGIFADDR, &ifr) < 0) {
		MSG(M_ERR, "SIOCGIFADDR: %s, does the interface have a working configuration?", strerror(errno));
		return -1;
	}
	if (ifr.ifr_addr.sa_family == AF_INET) {
		union {
			struct sockaddr *ptr;
			struct sockaddr_in *si;
		} s_u;
		struct in_addr ia;

		s_u.ptr=&ifr.ifr_addr;
		ia.s_addr=s_u.si->sin_addr.s_addr;
		memcpy(&ii->myaddr, &ifr.ifr_addr, sizeof(ii->myaddr));

		snprintf(ii->myaddr_s, sizeof(ii->myaddr_s) -1, "%s", inet_ntoa(ia));
	}
	else {
		snprintf(ii->myaddr_s, sizeof(ii->myaddr_s) -1, "Unknown");
	}

	/* link address */
	if (ioctl(st, SIOCGIFHWADDR, &ifr) < 0) {
		MSG(M_ERR, "ioctl SIOCGIFHWADDR fails: %s", strerror(errno));
		return -1;
	}
	memcpy(&ii->hwaddr, &ifr.ifr_hwaddr.sa_data, THE_ONLY_SUPPORTED_HWADDR_LEN);

	snprintf(ii->hwaddr_s, sizeof(ii->hwaddr_s) -1, "%.02x:%.02x:%.02x:%.02x:%.02x:%.02x", ii->hwaddr[0], ii->hwaddr[1],
	ii->hwaddr[2], ii->hwaddr[3], ii->hwaddr[4], ii->hwaddr[5]);

	/* mtu */
	if (ioctl(st, SIOCGIFMTU, &ifr) < 0) {
		MSG(M_ERR, "SIOCGIFMTU: %s", strerror(errno));
		return -1;
	}
#ifndef ifr_mtu
#define ifr_mtu ifr_metric
#endif
	ii->mtu=(uint16_t)ifr.ifr_mtu;

	close(st);
	return 1;
}
#endif

#ifdef WITH_SELINUX
void drop_privs(void) {
	return;
}
#else
void drop_privs(void) {
	struct passwd *pw_ent=NULL;
	uid_t myuid;
	gid_t mygid;

	pw_ent=getpwnam(NOPRIV_USER);
	assert(pw_ent != NULL);

	myuid=pw_ent->pw_uid;
	mygid=pw_ent->pw_gid;

	/* XXX audit open fd's */

	if (chdir(CHROOT_DIR) < 0) {
		MSG(M_ERR, "chdir to `%s' fails: %s", CHROOT_DIR, strerror(errno));
		abort();
	}

	if (chroot(CHROOT_DIR) < 0) {
		MSG(M_ERR, "chroot to `%s' fails: %s", CHROOT_DIR, strerror(errno));
		abort();
	}

	if (chdir("/") < 0) {
		MSG(M_ERR, "chdir to / fails: %s", strerror(errno));
		abort();
	}

	assert(setregid(mygid, mygid) == 0);
	assert(setreuid(myuid, myuid) == 0);
	/* XXX double check this accually worked */

	return;
}
#endif
