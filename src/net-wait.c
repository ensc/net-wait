#include <assert.h>
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <poll.h>

#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/icmp6.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "../ensc-lib/list.h"

#ifndef IFF_LOWER_UP
#  define IFF_LOWER_UP			1<<16
#endif

#define SOLICIT_DELAY_NS	((uint64_t)(1 * 1000 * 1000 * 1000))

enum {
	CMD_HELP = 0x8000,
	CMD_ALL,
	CMD_ANY,
	CMD_EXEC,
	CMD_SOLICIT,
	CMD_TIMEOUT,
	CMD_ONLY_IP4,
	CMD_ONLY_IP6,
};

static struct option const CMDLINE_OPTIONS_LINK[] = {
	{ "help",	no_argument,		0, CMD_HELP },
	{ "all",	no_argument,		0, CMD_ALL },
	{ "any",	no_argument,		0, CMD_ANY },
	{ "exec",	required_argument,	0, CMD_EXEC },
	{ "solicit",	no_argument,		0, CMD_SOLICIT },
	{ "timeout",	required_argument,	0, CMD_TIMEOUT },
	{ }
};

static struct option const CMDLINE_OPTIONS_ADDR[] = {
	{ "help",	no_argument,		0, CMD_HELP },
	{ "all",	no_argument,		0, CMD_ALL },
	{ "any",	no_argument,		0, CMD_ANY },
	{ "exec",	required_argument,	0, CMD_EXEC },
	{ "only-ip4",	no_argument,		0, CMD_ONLY_IP4 },
	{ "only-ip6",	no_argument,		0, CMD_ONLY_IP6 },
	{ "timeout",	required_argument,	0, CMD_TIMEOUT },
	{ }
};

enum op_type {
	OP_TYPE_AND,
	OP_TYPE_OR,
	OP_TYPE_NOT,
	OP_TYPE_LINK,
	OP_TYPE_ADDR,
};

enum op_result {
	OP_RESULT_UNDECIDED,
	OP_RESULT_TRUE,
	OP_RESULT_FALSE,
};

enum event_flag {
	EVENT_FLAG_ADDR_UP,
	EVENT_FLAG_LINK_UP,
};

struct device {
	char const		*name;
	int			if_idx;

	/* bitmask of 'enum event_flag' bits */
	unsigned long		events;

	/* bitmask of 'enum event_flag' bits */
	unsigned long		state;

	uint64_t		next_solicit_ns;

	struct list_head	head_solicit;
	struct list_head	head_exec;
};

struct op_node {
	enum op_type	type;
	enum op_result	result;

	union {
		struct {
			struct op_node	*a;
			struct op_node	*b;
		}	and_or;

		struct {
			struct op_node	*a;
		}	not;

		struct {
			struct device	*dev;
			bool		run_solicit;
		}	link;

		struct {
			struct device	*dev;
			bool		ip4;
			bool		ip6;
		}	addr;
	};
};

struct run_environment {
	char const		*exec_prog;
	signed long		timeout_ms;
	struct op_node		*root;

	bool			need_link;
	bool			need_addr4;
	bool			need_addr6;

	int			fd_nl;
	int			fd_tm;

	bool			do_req_link;
	bool			do_req_addr4;
	bool			do_req_addr6;

	bool			expect_done;

	struct list_head	pending_solicit;
	struct list_head	pending_exec;

	unsigned int		verbosity;

	/* safe mode; invalidate cached if_idx values on DELLINK */
	bool			handle_del_link;

	uint64_t		now;
};

static void show_help(void)
{
	printf("Usage: net-wait COMMAND [ OPTIONS ] [ SELECTORS ]\n"
	       "where: COMMAND := { help | link | addr }\n"
	       "       OPTIONS := { --all | --any  | --exec <prog> |\n"
	       "                    --solicit | --only-ip4 | --only-ip6 }\n"
	       "                    --timeout <ms> }\n"
	       "");
}

static bool streq(char const *a, char const *b)
{
	return strcmp(a, b) == 0;
}

static void xclose(int fd)
{
	if (fd != -1)
		close(fd);
}

static uint64_t get_now(void)
{
	/* program is single threaded; no need for locking... */
	static time_t		REL_TV_SEC = -1;

	struct timespec		ts;
	uint64_t		res;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	/* avoid theoretically possible overflows by making tv_sec relative to
	 * program start time */
	if (unlikely(REL_TV_SEC == -1))
		REL_TV_SEC = ts.tv_sec;

	assert(ts.tv_sec >= 0);

	res  = (ts.tv_sec - REL_TV_SEC);
	res *= 1000000000ull;
	res += ts.tv_nsec;

	/* '0' is magic */
	if (unlikely(res == 0))
		res = 1;

	return res;
}

static void device_schedule_solicit(struct device *dev,
				    struct run_environment *env,
				    bool force)
{
	if (!force && dev->next_solicit_ns != 0 && dev->next_solicit_ns > env->now)
		return;

	list_add_tail(&dev->head_solicit, &env->pending_solicit);
	dev->next_solicit_ns = env->now + SOLICIT_DELAY_NS;

	/* '0' is magic */
	if (unlikely(dev->next_solicit_ns == 0))
		dev->next_solicit_ns = 1;
}

static struct device *devices_find(struct device *devices, char const *name)
{
	for (size_t i = 0; devices[i].name != NULL; ++i) {
		if (streq(devices[i].name, name))
			return &devices[i];
	}

	return NULL;
}

static struct device *devices_register(size_t cnt, char *argv[])
{
	/* allocate room for one more element which acts as end-of-array
	 * marker */
	struct device	*res = calloc(cnt + 1, sizeof res[0]);

	for (size_t i = 0; i < cnt; ++i) {
		char const	*name = argv[i];

		for (size_t j = 0;; ++j) {
			/* calloc() above initialized 'name' of every array
			 * member to NULL */
			if (res[j].name == NULL) {
				res[j] = (struct device) {
					.name		= name,
					.if_idx		= -1,
				};
				break;
			}

			/* device already registered */
			if (streq(res[j].name, name))
				break;
		}
	}

	/* TODO: shrink 'res'? */

	return res;
}

static void run_solicit(struct run_environment *env, char const *if_name)
{
	static int const		ZERO = 0;
	static int const		HOPS = 255;

	struct ifreq			ifr = {};
	int				fd;
	int				rc;
	unsigned int			if_idx = if_nametoindex(if_name);
	struct sockaddr_in6		mcast_router = {
		.sin6_family		= AF_INET6,
		.sin6_addr		= {
			/* ff02::2 */
			.s6_addr	= { 0xff, 0x02, 0x00, 0x00,
					    0x00, 0x00, 0x00, 0x00,
					    0x00, 0x00, 0x00, 0x00,
					    0x00, 0x00, 0x00, 0x02 },
		},
		.sin6_scope_id		= if_idx,
	};
	struct {
		struct nd_router_solicit	hdr;
		unsigned char			ll_addr[2];
		unsigned char			mac[6];
	} __attribute__((__packed__))		msg = {
		.hdr = {
			.nd_rs_hdr		= {
				.icmp6_type	= ND_ROUTER_SOLICIT,
				.icmp6_code	= 0,
			},
		},
		.ll_addr	= { 1, 1 },
	};

	if (env->verbosity >= 2)
		printf("SOLICIT: sending on %s\n", if_name);

	strncpy(ifr.ifr_ifrn.ifrn_name, if_name,
		sizeof ifr.ifr_ifrn.ifrn_name);

	fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
	if (fd < 0) {
		perror("socket(<solicit>)");
		goto out;
	}

	rc = ioctl(fd, SIOCGIFHWADDR, &ifr);
	if (rc < 0) {
		perror("ioctl(SIOCGIFHWADDR)");
		goto out;
	}

	setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &HOPS, sizeof HOPS);
	setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &ZERO, sizeof ZERO);
	setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
		   &if_idx, sizeof if_idx);

	memcpy(msg.mac, &ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);

	rc = sendto(fd, &msg, sizeof msg, 0, &mcast_router,
		    sizeof mcast_router);
	if (rc < 0) {
		perror("sendot(<solicit>)");
		goto out;
	}

out:
	xclose(fd);
}

static void create_tree(struct op_node **root, enum op_type type,
			struct op_node leafs[], size_t num_leafs,
			struct op_node ops[], size_t num_ops)
{
	assert(num_ops + 1 == num_leafs);

	if (num_ops == 0) {
		*root = &leafs[0];
	} else {
		*root = &ops[num_ops - 1];
		**root = (struct op_node) {
			.type		= type,
			.result		= OP_RESULT_UNDECIDED,
		};

		--num_ops;

		create_tree(&(*root)->and_or.a, type,
			    &leafs[0], (num_leafs + 1) / 2,
			    &ops[0],   (num_ops + 1) / 2);

		create_tree(&(*root)->and_or.b, type,
			    &leafs[(num_leafs + 1) / 2], num_leafs / 2,
			    &ops[(num_ops + 1) / 2],     num_ops / 2);
	};
}

static void tree_remove_ifidx(struct op_node *node)
{
	switch (node->type) {
	case OP_TYPE_AND:
	case OP_TYPE_OR:
		tree_remove_ifidx(node->and_or.a);
		tree_remove_ifidx(node->and_or.b);
		break;

	case OP_TYPE_NOT:
		tree_remove_ifidx(node->not.a);
		break;

	case OP_TYPE_LINK:
		node->link.dev->if_idx = -1;
		break;

	case OP_TYPE_ADDR:
		node->addr.dev->if_idx = -1;
		break;
	}
}

static void tree_analyze_needs(struct op_node *node,
			       struct run_environment *env)
{
	/* we know that we need every information about every type; no need to
	 * traverse tree further */
	if (env->need_addr4 && env->need_addr6 && env->need_link)
		return;

	/* result is known; type of subtree does not matter */
	if (node->result != OP_RESULT_UNDECIDED)
		return;

	switch (node->type) {
	case OP_TYPE_AND:
	case OP_TYPE_OR:
		tree_analyze_needs(node->and_or.a, env);
		tree_analyze_needs(node->and_or.b, env);
		break;
	case OP_TYPE_NOT:
		tree_analyze_needs(node->and_or.a, env);
		break;

	case OP_TYPE_LINK:
		/* running ROUTER SOLICIT requires link level address */
		if (node->link.run_solicit)
			env->need_addr6 = true;
		else
			env->need_link = true;

		if (env->exec_prog)
			env->need_link = true;

		if (env->handle_del_link)
			env->need_link = true;

		break;

	case OP_TYPE_ADDR:
		env->need_addr4 |= node->addr.ip4;
		env->need_addr6 |= node->addr.ip6;

		if (env->handle_del_link)
			env->need_link = true;

		break;
	}
}

static bool check_addr(struct ifaddrmsg const *msg,
		       struct op_node const *node)
{
	/* ignore link-local addresses */
	if (msg->ifa_scope == RT_SCOPE_LINK)
		return false;

	if ((msg->ifa_flags & IFA_F_TENTATIVE) != 0)
		return false;

	if (node->addr.ip4 && msg->ifa_family == AF_INET)
		return true;

	if (node->addr.ip6 && msg->ifa_family == AF_INET6)
		return true;

	return false;
}

static bool is_netdev(struct op_node *node, unsigned int if_idx)
{
	int		*n_idx;
	char const	*n_dev;

	switch (node->type) {
	case OP_TYPE_LINK:
		n_dev = node->link.dev->name;
		n_idx = &node->link.dev->if_idx;
		break;

	case OP_TYPE_ADDR:
		n_dev = node->addr.dev->name;
		n_idx = &node->addr.dev->if_idx;
		break;

	default:
		n_dev = NULL;
		n_idx = NULL;
		break;
	}

	if (!n_dev)
		return false;

	if (*n_idx == -1) {
		unsigned int		tmp = if_nametoindex(n_dev);

		if (tmp != 0)
			*n_idx = tmp;
	}

	return (*n_idx != -1 && (unsigned int)(*n_idx) == if_idx);
}

static void tree_addr_up(struct op_node *node, struct run_environment *env,
			 struct ifaddrmsg const *msg)
{
	int		if_idx = msg->ifa_index;
	struct device	*dev;

	/* result is known; type of subtree does not matter */
	if (node->result != OP_RESULT_UNDECIDED)
		return;

	switch (node->type) {
	case OP_TYPE_AND:
		tree_addr_up(node->and_or.a, env, msg);
		if (node->and_or.a->result == OP_RESULT_FALSE) {
			node->result = OP_RESULT_FALSE;
			break;
		}

		tree_addr_up(node->and_or.b, env, msg);
		if (node->and_or.b->result == OP_RESULT_FALSE) {
			node->result = OP_RESULT_FALSE;
			break;
		}

		if (node->and_or.a->result == OP_RESULT_TRUE &&
		    node->and_or.b->result == OP_RESULT_TRUE)  {
			node->result = OP_RESULT_TRUE;
			break;
		}

		break;

	case OP_TYPE_OR:
		tree_addr_up(node->and_or.a, env, msg);
		if (node->and_or.a->result == OP_RESULT_TRUE) {
			node->result = OP_RESULT_TRUE;
			break;
		}

		tree_addr_up(node->and_or.b, env, msg);
		if (node->and_or.b->result == OP_RESULT_TRUE) {
			node->result = OP_RESULT_TRUE;
			break;
		}

		if (node->and_or.a->result == OP_RESULT_FALSE &&
		    node->and_or.b->result == OP_RESULT_FALSE)  {
			node->result = OP_RESULT_FALSE;
			break;
		}
		break;

	case OP_TYPE_NOT:
		tree_addr_up(node->and_or.a, env, msg);

		if (node->and_or.a->result == OP_RESULT_FALSE)
			node->result = OP_RESULT_TRUE;
		else if (node->and_or.a->result == OP_RESULT_FALSE)
			node->result = OP_RESULT_FALSE;

		break;

	case OP_TYPE_ADDR:
		if (!is_netdev(node, if_idx))
			break;

		if (!check_addr(msg, node))
			break;

		dev = node->addr.dev;

		if (env->verbosity >= 2)
			printf("ADDING ADDR on %s\n", dev->name);

		node->result = OP_RESULT_TRUE;

		if (env->exec_prog)
			list_add_tail(&dev->head_exec, &env->pending_exec);

		break;

	case OP_TYPE_LINK:
		if (!is_netdev(node, if_idx))
			break;

		dev = node->link.dev;

		if (env->verbosity >= 4)
			printf("  LINK[%s] DETAILS: scope=%d, flags=%x\n",
			       dev->name, msg->ifa_scope, msg->ifa_flags);

		if (!node->link.run_solicit ||
		    msg->ifa_scope != RT_SCOPE_LINK ||
		    (msg->ifa_flags & IFA_F_PERMANENT) == 0)
			break;

		if ((msg->ifa_flags & IFA_F_TENTATIVE) != 0)
			break;

		if (env->verbosity >= 2)
			printf("ADDING LINK %s\n", dev->name);

		node->result = OP_RESULT_TRUE;
		device_schedule_solicit(dev, env, true);

		break;
	}
}

static void tree_link_up(struct op_node *node, struct run_environment *env,
			 struct ifinfomsg const *msg)
{
	int		if_idx = msg->ifi_index;
	struct device	*dev;

	/* result is known; type of subtree does not matter */
	if (node->result != OP_RESULT_UNDECIDED)
		return;

	switch (node->type) {
	case OP_TYPE_AND:
		tree_link_up(node->and_or.a, env, msg);
		if (node->and_or.a->result == OP_RESULT_FALSE) {
			node->result = OP_RESULT_FALSE;
			break;
		}

		tree_link_up(node->and_or.b, env, msg);
		if (node->and_or.b->result == OP_RESULT_FALSE) {
			node->result = OP_RESULT_FALSE;
			break;
		}

		if (node->and_or.a->result == OP_RESULT_TRUE &&
		    node->and_or.b->result == OP_RESULT_TRUE)  {
			node->result = OP_RESULT_TRUE;
			break;
		}

		break;

	case OP_TYPE_OR:
		tree_link_up(node->and_or.a, env, msg);
		if (node->and_or.a->result == OP_RESULT_TRUE) {
			node->result = OP_RESULT_TRUE;
			break;
		}

		tree_link_up(node->and_or.b, env, msg);
		if (node->and_or.b->result == OP_RESULT_TRUE) {
			node->result = OP_RESULT_TRUE;
			break;
		}

		if (node->and_or.a->result == OP_RESULT_FALSE &&
		    node->and_or.b->result == OP_RESULT_FALSE)  {
			node->result = OP_RESULT_FALSE;
			break;
		}
		break;

	case OP_TYPE_NOT:
		tree_link_up(node->and_or.a, env, msg);

		if (node->and_or.a->result == OP_RESULT_FALSE)
			node->result = OP_RESULT_TRUE;
		else if (node->and_or.a->result == OP_RESULT_FALSE)
			node->result = OP_RESULT_FALSE;

		break;

	case OP_TYPE_ADDR:
		/* no change */
		break;

	case OP_TYPE_LINK:
		if (!is_netdev(node, if_idx))
			break;

		/* running ROUTER SOLICIT requires a link level address; link
		 * status does not matter */
		if (node->link.run_solicit)
			break;

		dev = node->link.dev;

		if (env->verbosity >= 2)
			printf("ADDING LINK %s\n", dev->name);

		node->result = OP_RESULT_TRUE;

		if (env->exec_prog)
			list_add_tail(&dev->head_exec, &env->pending_exec);

		break;
	}
}

static int request_nl_info(struct run_environment *env)
{
	if (env->do_req_link) {
		static struct {
			struct nlmsghdr	nh;
			struct rtgenmsg	if_msg;
			unsigned char	pad[NLMSG_ALIGNTO];
		} const			req = {
			.nh	= {
				.nlmsg_len	= NLMSG_LENGTH(sizeof req.if_msg),
				.nlmsg_flags	= NLM_F_REQUEST | NLM_F_DUMP,
				.nlmsg_type	= RTM_GETLINK,
				.nlmsg_seq	= 1,
			},

			.if_msg	= {
				.rtgen_family	= AF_UNSPEC,
			},
		};
		ssize_t			l;

		_Static_assert(offsetof(__typeof__(req), if_msg) == NLMSG_HDRLEN,
			       "bad NLMSG alignment");

		_Static_assert(sizeof req >= NLMSG_LENGTH(sizeof req.if_msg),
			       "bad NLMSG padding");


		l = send(env->fd_nl, &req, req.nh.nlmsg_len, 0);
		if (l < 0) {
			perror("send(<RTM_GETLINK>)");
			return -1;
		}

		env->do_req_link = false;

		return 1;
	}

	if (env->do_req_addr6) {
		static struct {
			struct nlmsghdr  nh;
			struct ifaddrmsg if_msg;
		} const			req = {
			.nh	= {
				.nlmsg_len	= NLMSG_LENGTH(sizeof req.if_msg),
				.nlmsg_flags	= NLM_F_REQUEST | NLM_F_DUMP,
				.nlmsg_type	= RTM_GETADDR,
				.nlmsg_seq	= 2,
			},

			.if_msg	= {
				.ifa_family	= AF_INET6,
				.ifa_flags	= 0,
			},
		};
		ssize_t			l;

		_Static_assert(offsetof(__typeof__(req), if_msg) == NLMSG_HDRLEN,
			       "bad NLMSG alignment");

		_Static_assert(sizeof req >= NLMSG_LENGTH(sizeof req.if_msg),
			       "bad NLMSG padding");

		l = send(env->fd_nl, &req, req.nh.nlmsg_len, 0);
		if (l < 0) {
			perror("send(<RTM_GETADDR6>)");
			return -1;
		}

		env->do_req_addr6 = false;

		return 1;
	}

	if (env->do_req_addr4) {
		static struct {
			struct nlmsghdr  nh;
			struct ifaddrmsg if_msg;
		} const			req = {
			.nh	= {
				.nlmsg_len	= NLMSG_LENGTH(sizeof req.if_msg),
				.nlmsg_flags	= NLM_F_REQUEST | NLM_F_DUMP,
				.nlmsg_type	= RTM_GETADDR,
				.nlmsg_seq	= 3,
			},

			.if_msg	= {
				.ifa_family	= AF_INET,
				.ifa_flags	= 0,
			},
		};
		ssize_t			l;

		l = send(env->fd_nl, &req, req.nh.nlmsg_len, 0);
		if (l < 0) {
			perror("send(<RTM_GETADDR4>)");
			return -1;
		}

		env->do_req_addr4 = false;

		return 1;
	}

	return 0;
}

static int handle_error(struct nlmsgerr const *msg, size_t len)
{
	if (msg->error)
		fprintf(stderr, "request failed: %s", strerror(-msg->error));

	return 0;
}

static int handle_newaddr(struct run_environment *env,
			  struct ifaddrmsg const *msg, size_t len)
{
	char		ifbuf[IF_NAMESIZE];

	if (env->verbosity >= 4)
		printf("ADDR: %s: %04x\n",
		       if_indextoname(msg->ifa_index, ifbuf), msg->ifa_flags);

	tree_addr_up(env->root, env, msg);

	return 0;
}

static int handle_newlink(struct run_environment *env,
			  struct ifinfomsg const *msg, size_t len)
{
	static unsigned int const	UP_MSK = (IFF_UP | IFF_LOWER_UP | IFF_RUNNING);
	char				ifbuf[IF_NAMESIZE];

	if (env->verbosity >= 4)
		printf("LINK: %s: %04x\n",
		       if_indextoname(msg->ifi_index, ifbuf), msg->ifi_flags);

	if ((msg->ifi_flags & UP_MSK) != UP_MSK) {
		if (env->verbosity >= 3) {
			printf("non-up: %s: %04x\n",
			       if_indextoname(msg->ifi_index, ifbuf),
			       msg->ifi_flags);
		}

		return 0;
	}

	tree_link_up(env->root, env, msg);

	return 0;
}

static int handle_nl_in(struct run_environment *env)
{
	unsigned char		rcv_buf[1024 * 1024];
	ssize_t			l;
	int			rc;

	l = recv(env->fd_nl, rcv_buf, sizeof rcv_buf, 0);
	if (l < 0) {
		perror("recv(<NETLINK>)");
		return -1;
	}

	if (l == sizeof rcv_buf) {
		fprintf(stderr, "too much data\n");
		return -1;
	}

	rc = 0;
	for (struct nlmsghdr *nh = (void *)rcv_buf;
	     NLMSG_OK(nh, l);
	     nh = NLMSG_NEXT(nh, l)) {
		void const	*nh_data = NLMSG_DATA(nh);
		size_t		nh_len = NLMSG_PAYLOAD(nh, l);

		switch (nh->nlmsg_type) {
		case NLMSG_DONE:
			env->expect_done = false;
			rc = 0;
			break;

		case NLMSG_ERROR:
			rc = handle_error(nh_data, nh_len);
			break;

		case RTM_NEWADDR:
			rc = handle_newaddr(env, nh_data, nh_len);
			break;

		case RTM_NEWLINK:
			rc = handle_newlink(env, nh_data, nh_len);
			break;

		case RTM_DELLINK:
			tree_remove_ifidx(env->root);
			break;

		case RTM_DELADDR:
			/* TODO: invalidate tree results? */
			rc = 0;
			break;

		default:
			fprintf(stderr,
				"unexpected type %d, data=%p+%zu\n",
				nh->nlmsg_type, nh_data, nh_len);
			rc = 0;
			break;
		}
	}

	return rc;
}

static void run_all_solicit(struct run_environment *env)
{
	while (!list_empty(&env->pending_solicit)) {
		struct device	*dev =
			list_first_entry(&env->pending_solicit,
					 struct device, head_solicit);

		list_del(&dev->head_solicit);

		run_solicit(env, dev->name);
	}
}

static int monitor_nl(struct run_environment *env)
{
	int			res = EX_OK;;
	bool			pending_req = true;

	env->do_req_addr4 = env->need_addr4;
	env->do_req_addr6 = env->need_addr6;
	env->do_req_link  = env->need_link;

	while (env->root->result == OP_RESULT_UNDECIDED || env->expect_done) {
		struct pollfd		fds[2] = {
			[0] = {
				.fd	= env->fd_nl,
				.events	= (((pending_req && !env->expect_done)
					    ? POLLOUT : 0) | POLLIN),
			},
			[1] = {
				.fd	= env->fd_tm,
				.events	= POLLIN,
			}
		};
		int			rc;

		rc = poll(fds, env->fd_tm == -1 ? 1 : 2, -1);

		env->now = get_now();

		if (fds[0].revents & POLLIN) {
			rc = handle_nl_in(env);
			if (rc < 0) {
				res = EX_IOERR;
				break;
			}
		} else if (fds[0].revents & POLLOUT) {
			rc = request_nl_info(env);
			if (rc < 0) {
				res = EX_IOERR;
				break;
			}

			env->expect_done = rc > 0;

			pending_req = rc > 0;
		} else if (fds[1].revents & POLLIN) {
			fprintf(stderr,
				"timeout; addresses/links might not be up yet\n");
			res = EX_NOINPUT;
			break;
		}

		if (env->verbosity >= 5)
			printf("expect_done=%d, solicit=%d, exec=%d, res=%d\n",
			       env->expect_done,
			       !list_empty(&env->pending_solicit),
			       !list_empty(&env->pending_exec),
			       env->root->result);

		if (!env->expect_done && !list_empty(&env->pending_solicit))
			run_all_solicit(env);
	}

	if (env->root->result == OP_RESULT_FALSE)
		res = EX_UNAVAILABLE;

	return res;
}

static int run_tree(struct run_environment *env)
{
	struct sockaddr_nl	sa;
	int			rc;

	env->need_link = false;
	env->need_addr4 = false;
	env->need_addr6 = false;

	tree_analyze_needs(env->root, env);

	env->need_addr4 = true;
	env->need_addr6 = true;

	if (!env->need_addr4 && !env->need_addr6 && !env->need_link)
		/* TODO: check result true/false? */
		return 0;

	if (env->timeout_ms < 0) {
		env->fd_tm = -1;
	} else {
		struct itimerspec	tm = {
			.it_value	= {
				.tv_sec	= env->timeout_ms / 1000,
				.tv_nsec = (env->timeout_ms % 1000) * 1000000,
			},
		};

		env->fd_tm = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
		if (env->fd_tm < 0) {
			perror("timerfd_create()");
			return EX_OSERR;
		}

		rc = timerfd_settime(env->fd_tm, 0, &tm, NULL);
		if (rc < 0) {
			perror("timerfd_settime()");
			return EX_OSERR;
		}
	}


	env->fd_nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (env->fd_nl < 0) {
		perror("socket(<AF_NETLINK>)");
		return EX_OSERR;
	}

	sa = (struct sockaddr_nl) {
		.nl_family	= AF_NETLINK,
		.nl_groups	= ((env->need_link  ? RTMGRP_LINK : 0) |
				   (env->need_addr4 ? RTMGRP_IPV4_IFADDR : 0) |
				   (env->need_addr6 ? RTMGRP_IPV6_IFADDR : 0)),
	};

	rc = bind(env->fd_nl, (void *)&sa, sizeof sa);
	if (rc < 0) {
		perror("bind(<AF_NETLINK>)");
		return EX_OSERR;
	}

	return monitor_nl(env);
}

static int run_wait_link(size_t argc, char *argv[])
{
	bool		is_all = false;
	bool		is_any = false;
	bool		do_solicit = false;

	struct run_environment	env = {
		.exec_prog		= NULL,
		.timeout_ms		= -1,
		.fd_nl			= -1,
		.fd_tm			= -1,
		.pending_solicit	= DECLARE_LIST(&env.pending_solicit),
		.pending_exec		= DECLARE_LIST(&env.pending_exec),
	};

	struct device	*devices;
	struct op_node	*nodes;
	int		rc;

	while (1) {
		int		c = getopt_long(argc, argv, "v",
						CMDLINE_OPTIONS_LINK, 0);

		if (c == -1)
			break;

		switch (c) {
		case 'v':
			env.verbosity += 1;
			break;

		case CMD_HELP:
			show_help();
			return EX_OK;

		case CMD_ALL:
			is_all = true;
			break;

		case CMD_ANY:
			is_any = true;
			break;

		case CMD_EXEC:
			env.exec_prog = optarg;
			break;

		case CMD_SOLICIT:
			do_solicit = true;
			break;

		case CMD_TIMEOUT:
			env.timeout_ms = atol(optarg);
			break;

		default:
			fprintf(stderr, "try --help form more information\n");
			return EX_USAGE;
		}
	}

	if (is_any && is_all) {
		fprintf(stderr, "both --all and --any specified\n");
		return EX_USAGE;
	}

	if (!is_any && !is_all)
		/* default to --all */
		is_all = true;

	if ((size_t)optind == argc) {
		fprintf(stderr, "no devices given\n");
		return EX_USAGE;
	}

	devices = devices_register(argc - optind, argv + optind);
	if (!devices) {
		perror("failed to register devices");
		return EX_OSERR;
	}

	/* allocate memory for nodes (nodes with devices) and the and/or
	 * operators between them */
	nodes = calloc((argc - optind) + (argc - optind - 1), sizeof nodes[0]);
	if (!nodes) {
		free(devices);
		perror("calloc()");
		return EX_OSERR;
	}

	for (size_t i = optind; i < argc; ++i) {
		struct device	*dev = devices_find(devices, argv[i]);

		assert(dev);

		nodes[i - optind] = (struct op_node) {
			.type		= OP_TYPE_LINK,
			.result		= OP_RESULT_UNDECIDED,
			.link		= {
				.dev		= dev,
				.run_solicit	= do_solicit,
			},
		};
	}

	create_tree(&env.root, is_all ? OP_TYPE_AND : OP_TYPE_OR,
		    &nodes[0], argc - optind,
		    &nodes[argc - optind], argc - optind - 1);

	rc = run_tree(&env);

	xclose(env.fd_nl);
	xclose(env.fd_tm);
	free(nodes);
	free(devices);

	return rc;
}

static int run_wait_addr(size_t argc, char *argv[])
{
	bool		is_all = false;
	bool		is_any = false;
	bool		only_ip4 = false;
	bool		only_ip6 = false;

	struct run_environment	env = {
		.exec_prog		= NULL,
		.timeout_ms		= -1,
		.fd_nl			= -1,
		.fd_tm			= -1,
		.pending_solicit	= DECLARE_LIST(&env.pending_solicit),
		.pending_exec		= DECLARE_LIST(&env.pending_exec),
		.now			= get_now(),
	};

	struct device	*devices;
	struct op_node	*nodes;
	int		rc;

	while (1) {
		int		c = getopt_long(argc, argv, "v",
						CMDLINE_OPTIONS_ADDR, 0);

		if (c == -1)
			break;

		switch (c) {
		case 'v':
			env.verbosity += 1;
			break;

		case CMD_HELP:
			show_help();
			return EX_OK;

		case CMD_ALL:
			is_all = true;
			break;

		case CMD_ANY:
			is_any = true;
			break;

		case CMD_EXEC:
			env.exec_prog = optarg;
			break;

		case CMD_ONLY_IP4:
			only_ip4 = true;
			break;

		case CMD_ONLY_IP6:
			only_ip6 = true;
			break;

		case CMD_TIMEOUT:
			env.timeout_ms = atol(optarg);
			break;

		default:
			fprintf(stderr, "try --help form more information\n");
			return EX_USAGE;
		}
	}

	if (is_any && is_all) {
		fprintf(stderr, "both --all and --any specified\n");
		return EX_USAGE;
	}

	if (!is_any && !is_all)
		/* default to --all */
		is_all = true;

	if ((size_t)optind == argc) {
		fprintf(stderr, "no devices given\n");
		return EX_USAGE;
	}

	devices = devices_register(argc - optind, argv + optind);
	if (!devices) {
		perror("failed to register devices");
		return EX_OSERR;
	}

	/* allocate memory for nodes (nodes with devices) and the and/or
	 * operators between them */
	nodes = calloc((argc - optind) + (argc - optind - 1), sizeof nodes[0]);
	if (!nodes) {
		free(devices);
		perror("calloc()");
		return EX_OSERR;
	}

	for (size_t i = optind; i < argc; ++i) {
		struct device	*dev = devices_find(devices, argv[i]);

		assert(dev);

		nodes[i - optind] = (struct op_node) {
			.type		= OP_TYPE_ADDR,
			.result		= OP_RESULT_UNDECIDED,
			.addr		= {
				.dev		= dev,
				.ip4		= !only_ip6,
				.ip6		= !only_ip4,
			},
		};
	}

	create_tree(&env.root, is_all ? OP_TYPE_AND : OP_TYPE_OR,
		    &nodes[0], argc - optind,
		    &nodes[argc - optind], argc - optind - 1);

	rc = run_tree(&env);

	xclose(env.fd_nl);
	xclose(env.fd_tm);
	free(nodes);
	free(devices);

	return rc;
}

int main(int argc, char *argv[])
{
	if (argc <= 1) {
		fprintf(stderr, "missing command; see --help\n");
		return EX_USAGE;
	}

	if (streq(argv[1], "help") || streq(argv[1], "--help")) {
		show_help();
		return EX_OK;
	}

	if (streq(argv[1], "link"))
		return run_wait_link(argc - 1, &argv[1]);
	else if (streq(argv[1], "addr"))
		return run_wait_addr(argc - 1, &argv[1]);
	else {
		fprintf(stderr, "bad command; see --help\n");
		return EX_USAGE;
	}
}
