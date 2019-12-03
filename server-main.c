#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_distributor.h>
#include <rte_debug.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#include "SimpleDNS.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define SCHED_RX_RING_SZ 8192
#define SCHED_TX_RING_SZ 65536
#define BURST_SIZE 32
#define BURST_SIZE_TX 32

#define RTE_LOGTYPE_DISTRAPP RTE_LOGTYPE_USER1

struct rte_mempool *mbuf_pool;
struct rte_distributor *d;
struct rte_ring *dist_tx_ring;
struct rte_ring *rx_dist_ring;

volatile uint8_t quit_signal;
volatile uint8_t quit_signal_rx;
volatile uint8_t quit_signal_dist;
volatile uint8_t quit_signal_work;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_LEN,
	},
};

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

/*
 * Swap len bytes from addr1 and addr2.
 * Only for len <= 8.
 */
inline void memswap(void *addr1, void *addr2, size_t len){
	uint8_t tmp_buf[8];
	memcpy(tmp_buf, addr1, len);
	memcpy(addr1, addr2, len);
	memcpy(addr2, tmp_buf, len);
}

/*
 * Receive packets and push into rx_queue.
 */
static int
lcore_rx(__attribute__((unused)) void *arg)
{
	const uint16_t port = 0;
	struct rte_mbuf *bufs[BURST_SIZE];
	struct rte_ring *out_ring = rx_dist_ring;

	if (rte_eth_dev_socket_id(port) > 0 &&
			(uint32_t)rte_eth_dev_socket_id(port) != rte_socket_id()){
		printf("WARNING, port %"PRIu16" is on remote NUMA node to "
					"TX thread.\n\tPerformance will not "
					"be optimal.\n", port);
	}

	printf("Core %"PRIu32": Doing packet RX.\n", rte_lcore_id());
	
	while(!quit_signal_rx){
		const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
		uint16_t sent = rte_ring_enqueue_burst(out_ring,
					(void *)bufs, nb_rx, NULL);
		if (unlikely(sent < nb_rx)) {
			RTE_LOG_DP(DEBUG, DISTRAPP,
				"%s:Packet loss due to full ring\n", __func__);
			while (sent < nb_rx){
				rte_pktmbuf_free(bufs[sent++]);
			}
		}
	}
	/* set worker & tx threads quit flag */
	printf("Core %"PRIu32": Exiting RX task.\n", rte_lcore_id());
	quit_signal = 1;
	return 0;
}

/*
 * Distribute packets in rx_queue, 
 * and push returned pakets into tx_queue.
 */
static int
lcore_distributor(__attribute__((unused)) void *arg)
{
	struct rte_ring *in_r = rx_dist_ring;
	struct rte_ring *out_r = dist_tx_ring;
	struct rte_mbuf *bufs[BURST_SIZE * 2];

	printf("Core %"PRIu32": Doing packet ditributing.\n", rte_lcore_id());
	while (!quit_signal_dist) {
		const uint16_t nb_rx = rte_ring_dequeue_burst(in_r,
				(void *)bufs, BURST_SIZE, NULL);
		if (nb_rx) {
			/* Distribute the packets */
			rte_distributor_process(d, bufs, nb_rx);
			/* Handle Returns */
			const uint16_t nb_ret =
				rte_distributor_returned_pkts(d,
					bufs, BURST_SIZE*2);

			if (unlikely(nb_ret == 0)){
				continue;
			}

			uint16_t sent = rte_ring_enqueue_burst(out_r,
					(void *)bufs, nb_ret, NULL);
			if (unlikely(sent < nb_ret)) {
				RTE_LOG(DEBUG, DISTRAPP,
					"%s:Packet loss due to full out ring\n",
					__func__);
				while (sent < nb_ret)
					rte_pktmbuf_free(bufs[sent++]);
			}
		}
	}
	printf("Core %"PRIu32": Exiting distributor task.\n", rte_lcore_id());
	quit_signal_work = 1;

	rte_distributor_flush(d);
	/* Unblock any returns so workers can exit */
	rte_distributor_clear_returns(d);
	quit_signal_rx = 1;
	return 0;
}

/*
 * Send packets in tx_queue.
 */
static int
lcore_tx(__attribute__((unused)) void *arg)
{
	struct rte_mbuf *bufs[BURST_SIZE_TX * 2];
	uint32_t mbuf_cnt = 0;
	const uint16_t port = 0;

	if (rte_eth_dev_socket_id(port) > 0 &&
			(uint32_t)rte_eth_dev_socket_id(port) != rte_socket_id()){
		printf("WARNING, port %"PRIu16" is on remote NUMA node to "
					"TX thread.\n\tPerformance will not "
					"be optimal.\n", port);
	}

	printf("Core %"PRIu32" doing packet TX.\n", rte_lcore_id());
	while (!quit_signal) {
		const uint16_t nb_rx = rte_ring_dequeue_burst(dist_tx_ring,
				(void *)(bufs + mbuf_cnt), BURST_SIZE_TX, NULL);
		mbuf_cnt += nb_rx;
		/* if we get no traffic, flush anything we have */
		if (unlikely(nb_rx == 0 || mbuf_cnt > BURST_SIZE_TX)) {
			uint32_t nb_tx = rte_eth_tx_burst(port, 0, bufs, mbuf_cnt);
			while(unlikely(nb_tx < mbuf_cnt)){
				rte_pktmbuf_free(bufs[nb_tx++]);
			}
			continue;
		}
	}
	printf("\nCore %"PRIu32": exiting tx task.\n", rte_lcore_id());
	return 0;
}

/*
 * In this function we complete the headers of a answer packet(buf1), 
 * basing on information from the query packet(buf2).
 */
static void
build_packet(uint8_t *buf, uint16_t pkt_size)
{
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	struct udp_hdr *udp_hdr = (struct udp_hdr *)(ip_hdr + 1);
	uint8_t *pkt_end = buf + pkt_size;
	//Part 4. in place update.
	
	//ether_hdr
	uint8_t *d_addr = eth_hdr->d_addr.addr_bytes;
	uint8_t *s_addr = eth_hdr->s_addr.addr_bytes;
	memswap(d_addr, s_addr, 6);

	//ipv4
	uint32_t tmp_ip_addr;
	ip_hdr->total_length = htons((uint16_t)(pkt_end - (uint8_t*)ip_hdr));
	ip_hdr->packet_id = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live = 255;
	ip_hdr->hdr_checksum = 0;
	tmp_ip_addr = ip_hdr->src_addr;
	ip_hdr->src_addr = ip_hdr->dst_addr;
	ip_hdr->dst_addr = tmp_ip_addr;
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
	
	//udp
	uint16_t tmp_port;
	tmp_port = udp_hdr->src_port;
	udp_hdr->src_port = udp_hdr->dst_port;
	udp_hdr->dst_port = tmp_port;
	udp_hdr->dgram_len = htons((uint16_t)(pkt_end - (uint8_t*)udp_hdr));
	udp_hdr->dgram_cksum = 0;

	udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr, udp_hdr);
}

/*
 * unpacket, and use SimpleDNS to resolve requests.
 */
static int
lcore_worker(const uint32_t *worker_id)
{
	const uint32_t id = *worker_id;
	struct rte_mbuf *buf[8] __rte_cache_aligned;
	uint32_t num = 0;
	uint32_t ret_num = 0;
	
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udp_hdr;
	uint8_t *buffer = NULL;
	struct Message msg;
	memset(&msg, 0, sizeof(msg));

	printf("Core %"PRIu32": Acting as worker core.\n", rte_lcore_id());
	while (!quit_signal_work) {
		num = rte_distributor_get_pkt(d, id, buf, buf, ret_num);
		ret_num = 0;
		/* Do a little bit of work for each packet */
		for (uint32_t i = 0; i < num; i++) {
			uint8_t *data_addr = rte_pktmbuf_mtod(buf[i], uint8_t *);
			eth_hdr = (struct ether_hdr *)data_addr;
			ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
			udp_hdr = (struct udp_hdr *)(ip_hdr + 1);
			buffer = (uint8_t *)(udp_hdr + 1);
			if(unlikely(eth_hdr->ether_type != htons(0x800))){
				rte_pktmbuf_free(buf[i]);
				continue;
			}
			if(unlikely(ip_hdr->next_proto_id != 0x11)){
				rte_pktmbuf_free(buf[i]);
				continue;
			}
			if(unlikely(udp_hdr->dst_port != htons(9000u))){
				rte_pktmbuf_free(buf[i]);
				continue;
			}

			//Only allow UDP packet to port 9000
			int hdr_len = (int)(buffer - data_addr);
			int nbytes = buf[i]->data_len - hdr_len;
			
			/*********preparation (begin)**********/
			free_questions(msg.questions);
			free_resource_records(msg.answers);
			free_resource_records(msg.authorities);
			free_resource_records(msg.additionals);
			memset(&msg, 0, sizeof(struct Message));
			/*********preparation (end)**********/
			
			/*********read input (begin)**********/
			if (decode_msg(&msg, buffer, nbytes) != 0) {
				rte_pktmbuf_free(buf[i]);
				continue;
			}
#ifdef _DEBUG
			/* Print query */
			print_query(&msg);
#endif
			resolver_process(&msg);

#ifdef _DEBUG
			/* Print response */
			print_query(&msg);
#endif
			/*********read input (end)**********/
			
			/*********write output (begin)**********/
			uint8_t *p = buffer;
			if (encode_msg(&msg, &p) != 0) {
				rte_pktmbuf_free(buf[i]);
				continue;
			}
			uint32_t buflen = p - buffer;
			/*********write output (end)**********/
			
			//Part 3. Update header.
			rte_pktmbuf_append(buf[i], buflen + hdr_len - buf[i]->data_len);
			build_packet(data_addr, buflen + hdr_len);
			//move success packet to front.
			buf[ret_num ++] = buf[i];
		}
	}
	return 0;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	uint16_t portid = 0, nb_ports = 1;
	uint32_t lcore_id, worker_id = 0, lcore_active = 0;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	if (rte_lcore_count() < 5) {
		rte_exit(EXIT_FAILURE, "Error, This application needs at "
				"least 5 logical cores to run:\n"
				"1 lcore for stats (can be core 0)\n"
				"1 lcore for packet RX\n"
				"1 lcore for distribution\n"
				"1 lcore for packet TX\n"
				"and at least 1 lcore for worker threads\n");
	}

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize port 0. */
	if (port_init(portid, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);

	d = rte_distributor_create("PKT_DIST", rte_socket_id(),
			rte_lcore_count() - 4,
			RTE_DIST_ALG_BURST);
	if (d == NULL){
		rte_exit(EXIT_FAILURE, "Cannot create distributor\n");
	}

	/*
	 * scheduler ring is read by the transmitter core, and written to
	 * by scheduler core
	 */
	dist_tx_ring = rte_ring_create("Output_ring", SCHED_TX_RING_SZ,
			rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (dist_tx_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create output ring\n");

	rx_dist_ring = rte_ring_create("Input_ring", SCHED_RX_RING_SZ,
			rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (rx_dist_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create output ring\n");

	RTE_LCORE_FOREACH_SLAVE(lcore_id){
		if(lcore_active == 0){
			printf("Master: Launch lcore %"PRIu32": TX.\n", rte_lcore_id());
			rte_eal_remote_launch((lcore_function_t *)lcore_tx,
					dist_tx_ring, lcore_id);
		}
		else if(lcore_active == 1){
			printf("Master: Launch lcore %"PRIu32": Distributor.\n", rte_lcore_id());
			rte_eal_remote_launch((lcore_function_t *)lcore_distributor,
					NULL, lcore_id);
		}
		else if(lcore_active == 2){
			printf("Master: Launch lcore %"PRIu32": RX.\n", rte_lcore_id());
			rte_eal_remote_launch((lcore_function_t *)lcore_rx,
					NULL, lcore_id);
		}
		else{
			printf("Master: Launch lcore %"PRIu32": Worker.\n", rte_lcore_id());
			rte_eal_remote_launch((lcore_function_t *)lcore_worker,
					&worker_id, lcore_id);
			worker_id ++;
		}
		lcore_active ++;
	}

	while(!quit_signal_dist){
		usleep(1000);
	}

	RTE_LCORE_FOREACH_SLAVE(lcore_id){
		if(rte_eal_wait_lcore(lcore_id) < 0){
			return -1;
		}
	}

	return 0;
}
