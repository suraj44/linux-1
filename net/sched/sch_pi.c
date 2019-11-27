// SPDX-License-Identifier: GPL-2.0-only
/* Author: Suraj Singh <suraj1998@gmail.com>
 *
 * References:
 * Original Paper: https://ieeexplore.ieee.org/abstract/document/1258913
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>

#define MAX_PROB 0xffffffffffffffff
#define PI_SCALE 1000000000000000000
#define KNRC_SCALE 10000
#define KC_SCALE 2
#define RTT_SCALE 10000
#define BETA_SCALE 2
#define THNRC_SCALE 1000000000000
#define PARAM_SCALE 1000000

/* parameters used */
struct pi_params {
	u32 qref;	/* user specified target delay in pschedtime */
	u32 tupdate;		/* timer frequency (in jiffies) */
	u32 limit;		/* number of packets that can be enqueued */
	u64 alpha;		/* alpha and beta are between 0 and 32 */
	u64 beta;		/* and are used for shift relative to 1 */
	bool ecn;		/* true if ecn is enabled */
	bool bytemode;		/* to scale drop early prob based on pkt size */
};

/* variables used */
struct pi_vars {
	u64 prob;		/* probability but scaled by u64 limit. */
	u32 qlen_old;		/* in bytes */
	u32 departed_packets;
	u32 old_thc;
	u32 rtt;
	u32 kc;
	u32 knrc;
	u64 kp;
	u64 ki;
	u64 old_thnrc;
	u32 beta;
};

/* statistics gathering */
struct pi_stats {
	u32 qlen;
	u32 packets_in;		/* total number of packets enqueued */
	u32 dropped;		/* packets dropped due to pi_action */
	u32 overlimit;		/* dropped due to lack of space in queue */
	u32 maxq;		/* maximum queue size */
	u32 ecn_mark;		/* packets marked with ECN */
};

/* private data for the Qdisc */
struct pi_sched_data {
	struct pi_params params;
	struct pi_vars vars;
	struct pi_stats stats;
	struct timer_list adapt_timer;
	struct Qdisc *sch;
};

static void pi_params_init(struct pi_params *params)
{
	params->alpha = 18220000000000;
	params->beta = 18160000000000;
	params->tupdate = usecs_to_jiffies(8 * USEC_PER_MSEC);	/* 6.25 ms */
	params->limit = 1000;	/* default of 1000 packets */
	params->qref = 50;	/* reference queue length in packets*/
	params->ecn = false;
	params->bytemode = false;
}

static void pi_vars_init(struct pi_vars *vars)
{	
	vars->prob = 0;
	vars->qlen_old = 0;
	vars->departed_packets = 0;
	vars->old_thc = 0;
	vars->rtt = 23;
	vars->kc = 1;
	vars->knrc = 3;
	vars->kp = 18220; // initial tuned values
	vars->ki = 18160;
	vars->old_thnrc =0; // estimated N/RC
	vars->beta = 1;
}

static bool drop_early(struct Qdisc *sch, u32 packet_size)
{
	struct pi_sched_data *q = qdisc_priv(sch);
	u64 rnd;
	u64 local_prob = q->vars.prob;
	u32 mtu = psched_mtu(qdisc_dev(sch));

	if (q->params.bytemode && packet_size <= mtu)
		local_prob = (u64)packet_size * div_u64(local_prob, mtu);
	else
		local_prob = q->vars.prob;

	prandom_bytes(&rnd, 8);
	if (rnd < local_prob) {
		return true;
	}

	return false;
}

static int pi_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			     struct sk_buff **to_free)
{
	struct pi_sched_data *q = qdisc_priv(sch);
	bool enqueue = false;

	if (unlikely(qdisc_qlen(sch) >= sch->limit)) {
		q->stats.overlimit++;
		goto out;
	}

	if (!drop_early(sch, skb->len)) {
		enqueue = true;
	} else if (q->params.ecn && (q->vars.prob <= MAX_PROB / 10) &&
		   INET_ECN_set_ce(skb)) {
		/* If packet is ecn capable, mark it if drop probability
		 * is lower than 10%, else drop it.
		 */
		q->stats.ecn_mark++;
		enqueue = true;
	}

	/* we can enqueue the packet */
	if (enqueue) {
		q->stats.packets_in++;
		if (qdisc_qlen(sch) > q->stats.maxq)
			q->stats.maxq = qdisc_qlen(sch);

		return qdisc_enqueue_tail(skb, sch);
	}

out:
	q->stats.dropped++;
	return qdisc_drop(skb, sch, to_free);
}

static const struct nla_policy pi_policy[TCA_PI_MAX + 1] = {
	[TCA_PI_QREF] = {.type = NLA_U32},
	[TCA_PI_LIMIT] = {.type = NLA_U32},
	[TCA_PI_W] = {.type = NLA_U32},
	[TCA_PI_A] = {.type = NLA_U64},
	[TCA_PI_B] = {.type = NLA_U64},
	[TCA_PI_ECN] = {.type = NLA_U32},
	[TCA_PI_BYTEMODE] = {.type = NLA_U32}
};

static int pi_change(struct Qdisc *sch, struct nlattr *opt,
		      struct netlink_ext_ack *extack)
{
	struct pi_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_PI_MAX + 1];
	unsigned int qlen, dropped = 0;
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested_deprecated(tb, TCA_PIE_MAX, opt, pi_policy,
					  NULL);
	if (err < 0)
		return err;

	sch_tree_lock(sch);

	/* qref is in packets*/
	if (tb[TCA_PI_QREF]) {
		q->params.qref = nla_get_u32(tb[TCA_PI_QREF]);
	}

	/* tupdate is in jiffies */
	if (tb[TCA_PI_W])
		q->params.tupdate =
			usecs_to_jiffies(nla_get_u32(tb[TCA_PI_W]));

	if (tb[TCA_PIE_LIMIT]) {
		u32 limit = nla_get_u32(tb[TCA_PI_LIMIT]);

		q->params.limit = limit;
		sch->limit = limit;
	}

	if (tb[TCA_PI_A])
		q->params.alpha = nla_get_u32(tb[TCA_PI_A]);

	if (tb[TCA_PI_B])
		q->params.beta = nla_get_u32(tb[TCA_PI_B]);

	if (tb[TCA_PI_ECN])
		q->params.ecn = nla_get_u32(tb[TCA_PI_ECN]);

	if (tb[TCA_PI_BYTEMODE])
		q->params.bytemode = nla_get_u32(tb[TCA_PI_BYTEMODE]);


	/* Drop excess packets if new limit is lower */
	qlen = sch->q.qlen;
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = __qdisc_dequeue_head(&sch->q);

		dropped += qdisc_pkt_len(skb);
		qdisc_qstats_backlog_dec(sch, skb);
		rtnl_qdisc_drop(skb, sch);
	}
	qdisc_tree_reduce_backlog(sch, qlen - sch->q.qlen, dropped);

	sch_tree_unlock(sch);
	return 0;
}


static void calculate_probability(struct Qdisc *sch)
{
	struct pi_sched_data *q = qdisc_priv(sch);
	u32 qlen = qdisc_qlen(sch);	/* queue size in packets */
	u32 qlen_old = q->vars.qlen_old;
	s64 delta = 0;		/* determines the new probability value */
	u64 oldprob;
	u64 alpha, beta;
	u32 stpi  = 1;

	if(stpi) {
		u32 kc = q->vars.kc, knrc = q->vars.knrc; // will be scaled to 0.5

		u32 router_busy_time = jiffies_to_usecs(q->params.tupdate) / USEC_PER_MSEC;

		u32 capacity = 8 * q->vars.departed_packets * router_busy_time;

		u32 thc;
		if(q->vars.old_thc >  0)
			thc = kc * capacity /KC_SCALE + ((KC_SCALE - kc) * q->vars.old_thc) / KC_SCALE;
		else
			thc = capacity;


		u32 rtt;
		u64 thnrc = q->vars.old_thnrc;
		if(q->vars.prob > 0) {
			// if (capacity > 0) 
			// 	rtt = int_sqrt((MAX_PROB/q->vars.prob)*2)*5/capacity;
			// else
				rtt = q->vars.rtt;

			thnrc = (knrc * 10 *THNRC_SCALE) / (KNRC_SCALE*14*int_sqrt(MAX_PROB/q->vars.prob)) + ((KNRC_SCALE - knrc) * q->vars.old_thnrc) / KNRC_SCALE;

			if(thc != 0) { // prevent divide by 0 error 
				q->vars.kp = (((2*q->vars.beta*11)/10)*(((u64)thnrc*RTT_SCALE*PARAM_SCALE)))/(((u64)thc*rtt*THNRC_SCALE*BETA_SCALE));
				q->vars.ki = (2*thnrc*q->vars.kp*RTT_SCALE)/(rtt*THNRC_SCALE);
			}

			if(q->vars.kp ==0 && q->vars.ki ==0) {
				q->vars.kp = 18160; // initialized values
				q->vars.ki = 18220;
			}
		} 
		printk("kp %llu ki %llu \n", q->vars.kp, q->vars.ki);

		q->params.alpha = q->vars.kp; // to show self tuned values in the watch command
		q->params.beta = q->vars.ki; 
		u64 kp = q->vars.kp * (MAX_PROB/(PARAM_SCALE));
		u64 ki = q->vars.ki * (MAX_PROB/(PARAM_SCALE));

		delta = delta + (kp * (s32)(qlen - q->params.qref));
		delta = delta + (ki * (s32)(qlen_old - q->params.qref));

		if(delta < 0)
			q->vars.prob = 0;
		else
			q->vars.prob = delta;

		q->vars.old_thnrc = thnrc;
		q->vars.old_thc = thc;

	} else {
		alpha = ((u64)q->params.alpha * (MAX_PROB / PI_SCALE));
		beta = ((u64)q->params.beta * (MAX_PROB / PI_SCALE));

		delta = delta + (alpha * (s32)(qlen - q->params.qref));
		delta = delta -(beta * (s32)(qlen_old - q->params.qref));

		oldprob = q->vars.prob;

		q->vars.prob += delta;

		if (delta > 0) {
			/* prevent overflow */
			if (q->vars.prob < oldprob) {
				q->vars.prob = MAX_PROB;
			}
		} else {
			/* prevent underflow */
			if (q->vars.prob > oldprob)
				q->vars.prob = 0;
		}
	}

	q->vars.qlen_old = qlen;
	q->vars.departed_packets = 0; 


}

static void pi_timer(struct timer_list *t)
{
	struct pi_sched_data *q = from_timer(q, t, adapt_timer);
	struct Qdisc *sch = q->sch;
	spinlock_t *root_lock = qdisc_lock(qdisc_root_sleeping(sch));

	spin_lock(root_lock);
	calculate_probability(sch);

	/* reset the timer to fire after 'tupdate'. tupdate is in jiffies. */
	if (q->params.tupdate)
		mod_timer(&q->adapt_timer, jiffies + q->params.tupdate);
	spin_unlock(root_lock);
}

static int pi_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
	struct pi_sched_data *q = qdisc_priv(sch);

	pi_params_init(&q->params);
	pi_vars_init(&q->vars);
	sch->limit = q->params.limit;

	q->sch = sch;
	timer_setup(&q->adapt_timer, pi_timer, 0);

	if (opt) {
		int err = pi_change(sch, opt, extack);

		if (err)
			return err;
	}

	mod_timer(&q->adapt_timer, jiffies + HZ / 2);
	return 0;
}

static int pi_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct pi_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (!opts)
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_PI_QREF, q->params.qref) ||
	    nla_put_u32(skb, TCA_PI_LIMIT, sch->limit) ||
	    nla_put_u32(skb, TCA_PI_W,
			jiffies_to_usecs(q->params.tupdate)) ||
	    nla_put_u64_64bit(skb, TCA_PI_A, q->params.alpha, 0) ||
	    nla_put_u64_64bit(skb, TCA_PI_B, q->params.beta, 0) ||
	    nla_put_u32(skb, TCA_PI_ECN, q->params.ecn) ||
	    nla_put_u32(skb, TCA_PI_BYTEMODE, q->params.bytemode))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -1;
}

static int pi_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct pi_sched_data *q = qdisc_priv(sch);
	struct tc_pi_xstats st = { // Need to verify if all params are needed
		.prob		= q->vars.prob,
		.qlen		= q->stats.qlen,
		.packets_in	= q->stats.packets_in,
		.overlimit	= q->stats.overlimit,
		.maxq		= q->stats.maxq,
		.dropped	= q->stats.dropped,
		.ecn_mark	= q->stats.ecn_mark,
	};

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static struct sk_buff *pi_qdisc_dequeue(struct Qdisc *sch)
{
	struct sk_buff *skb = qdisc_dequeue_head(sch);

	if (!skb)
		return NULL;


	struct pi_sched_data *q = qdisc_priv(sch);
	q->vars.departed_packets++;
	// pi_process_dequeue(sch, skb);
	return skb;
}

static void pi_reset(struct Qdisc *sch)
{
	struct pi_sched_data *q = qdisc_priv(sch);

	qdisc_reset_queue(sch);
	pi_vars_init(&q->vars);
}

static void pi_destroy(struct Qdisc *sch)
{
	struct pi_sched_data *q = qdisc_priv(sch);

	q->params.tupdate = 0;
	del_timer_sync(&q->adapt_timer);
}

static struct Qdisc_ops pi_qdisc_ops __read_mostly = {
	.id = "pi",
	.priv_size	= sizeof(struct pi_sched_data),
	.enqueue	= pi_qdisc_enqueue,
	.dequeue	= pi_qdisc_dequeue,
	.peek		= qdisc_peek_dequeued,
	.init		= pi_init,
	.destroy	= pi_destroy,
	.reset		= pi_reset,
	.change		= pi_change,
	.dump		= pi_dump,
	.dump_stats	= pi_dump_stats,
	.owner		= THIS_MODULE,
};

static int __init pi_module_init(void)
{
	return register_qdisc(&pi_qdisc_ops);
}

static void __exit pi_module_exit(void)
{
	unregister_qdisc(&pi_qdisc_ops);
}

module_init(pi_module_init);
module_exit(pi_module_exit);

MODULE_DESCRIPTION("Proportional Integral (PI) scheduler");
MODULE_AUTHOR("Suraj Singh");
MODULE_LICENSE("GPL");

