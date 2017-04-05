#ifndef RTT_H
#define RTT_H

#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

struct rtt_info {
  uint32_t	rtt_rtt;	/* most recent measured RTT, in milliseconds */
  uint32_t	rtt_srtt;	/* smoothed RTT estimator, in milliseconds */
  uint32_t	rtt_rttvar;	/* smoothed mean deviation, in milliseconds */
  uint32_t	rtt_rto;	/* current RTO to use, in milliseconds */
  int		rtt_nrexmt;	/* # times retransmitted: 0, 1, 2, ... */
  uint64_t	rtt_base;	/* # millisec since 1/1/1970 at start */
};

//#define	RTT_RXTMIN      1000	/* min retransmit timeout value, in milliseconds */
//#define	RTT_RXTMAX      3000	/* max retransmit timeout value, in milliseconds */
#define	RTT_RXTMIN      800	/* min retransmit timeout value, in milliseconds */
#define	RTT_RXTMAX      2000
#define	RTT_MAXNREXMT 	12	/* max # times to retransmit */

				/* function prototypes */
void	 rtt_debug(struct rtt_info *);
void	 rtt_init(struct rtt_info *);
void	 rtt_newpack(struct rtt_info *);
int	 	 rtt_start(struct rtt_info *);
void	 rtt_stop(struct rtt_info *, uint32_t);
int	 	 rtt_timeout(struct rtt_info *);
uint32_t rtt_ts(struct rtt_info *);

extern int	rtt_d_flag;	/* can be set to nonzero for addl info */

#endif