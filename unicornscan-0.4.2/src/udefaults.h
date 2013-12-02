
#ifndef TARGETNAME
#define TARGETNAME "unicornscan"
#endif

/*
 * used to find out when spawned processes or connected drones have given us a foul taste for execution, 
 * causing us to cease our existance on this cruel world
 */
#define MAX_ERRORS 32

/* umm yah, you can change this, it doesnt matter, think firewalls */
#define IPC_BINDPORT_START	8000

#define DEF_SENDER	"127.0.0.1:12322"
#define DEF_LISTENER	"127.0.0.1:12323"

#ifndef PREFIX
#error PREFIX NOT DEFINED
#endif /* PREFIX */

#ifndef PATH_MAX
#define PATH_MAX 512
#endif

#define MAX_CONNS	32	/* MAX amount of ipc or pollable connections	*/
#define IPC_DSIZE	65536	/* MAX amount of bytes for an ipc message chunk	*/

#define MODULE_DIR	PREFIX "/libexec/" TARGETNAME "/modules"
#define PORT_NUMBERS	PREFIX "/share/" TARGETNAME "/port-numbers"
#define CONF_FILE	PREFIX "/share/" TARGETNAME "/unicorn.conf"
#define OUI_CONF	PREFIX "/share/" TARGETNAME "/oui.conf"

#define CLEAR(m) memset(&m, 0, sizeof(m))
