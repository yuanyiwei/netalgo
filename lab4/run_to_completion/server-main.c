#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_debug.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <stdbool.h>
#include <inttypes.h>
#include <signal.h>

#include "SimpleDNS.h"

static volatile bool force_quit;

#define RX_RING_SIZE 4096
// #define RX_RING_SIZE 8192
#define TX_RING_SIZE 4096
// #define TX_RING_SIZE 8192

// #define NUM_MBUFS 32767
#define NUM_MBUFS 65535
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 2
// #define BURST_SIZE 32

#define NUM_QUEUES 8

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_NONFRAG_IPV4_UDP,
		},
	},
};
struct rte_mempool *mbuf_pool;

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = NUM_QUEUES, tx_rings = NUM_QUEUES;
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
	for (q = 0; q < rx_rings; q++)
	{
        printf("starting setup\n");
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
										rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++)
	{
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


inline void memswap(void *addr1, void *addr2, size_t len)
{
    uint8_t tmp_buf[8];
    memcpy(tmp_buf, addr1, len);
    memcpy(addr1, addr2, len);
    memcpy(addr2, tmp_buf, len);
}

/*
 * In this function we complete the headers of a answer packet(buf1), 
 * basing on information from the query packet(buf2).
 */
static void
// build_packet(char *buf1, char *buf2, uint16_t pkt_size)
build_packet(uint8_t *buf, uint16_t pkt_size)
{
	// Add your code here.
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	struct udp_hdr *udp_hdr = (struct udp_hdr *)(ip_hdr + 1);
	uint8_t *pkt_end = buf + pkt_size;

	//ether_hdr
	uint8_t *d_addr = eth_hdr->d_addr.addr_bytes;
	uint8_t *s_addr = eth_hdr->s_addr.addr_bytes;
	memswap(d_addr, s_addr, 6);

	//ipv4
	uint32_t tmp_ip_addr;
	ip_hdr->total_length = htons((uint16_t)(pkt_end - (uint8_t *)ip_hdr));
	ip_hdr->packet_id = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live = 255;
	ip_hdr->hdr_checksum = 0;
	tmp_ip_addr = ip_hdr->src_addr;
	ip_hdr->src_addr = ip_hdr->dst_addr;
	ip_hdr->dst_addr = tmp_ip_addr;
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

	//udp
	uint16_t tmp_udp_port;
	tmp_udp_port = udp_hdr->src_port;
	udp_hdr->src_port = udp_hdr->dst_port;
	udp_hdr->dst_port = tmp_udp_port;
	udp_hdr->dgram_len = htons((uint16_t)(pkt_end - (uint8_t *)udp_hdr));
	udp_hdr->dgram_cksum = 0;

	udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr, udp_hdr);
	// Part 4.
}

/*
 * The lcore main. This is the main thread that does the work, read
 * an query packet and write an reply packet.
 */
static void
lcore_main_loop(void)
{
	uint16_t port = 0; // only one port is used.
	uint16_t i = 0, j = 0;
	unsigned lcore_id;
	struct rte_mbuf *query_buf[BURST_SIZE], *reply_buf[BURST_SIZE];

	//Add totoro code here.
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udp_hdr;

	uint16_t nb_rx, nb_tx;
	uint8_t *buffer;
	struct Message msg;

	memset(&msg, 0, sizeof(struct Message));

	lcore_id = rte_lcore_id(); // get lcore id

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	if (rte_eth_dev_socket_id(port) > 0 &&
		rte_eth_dev_socket_id(port) !=
			(int)rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to "
			   "polling thread.\n\tPerformance will "
			   "not be optimal.\n",
			   port);

	printf("\nSimpleDNS (using DPDK) is running...\n");

	int total_rx = 0;
	int total_tx = 0;
	/* Run until the application is quit or killed. */
	while (!force_quit)
	{
		// Add your code here.
		// Part 0.

		// ask for reply packet memory
		// for (i = 0; i < BURST_SIZE; i++)
		// {
		// 	do
		// 	{
		// 		reply_buf[i] = rte_pktmbuf_alloc(mbuf_pool);
		// 	} while (reply_buf[i] == NULL);
		// }

		/*********preparation (begin)**********/
		/*********preparation (end)**********/

		// Add your code here.
		// Part 1.
		// receive to query_buf and assign value to buffer. 0????????????0????????????1????????????1?????????...
		nb_rx = rte_eth_rx_burst(port, lcore_id, query_buf, BURST_SIZE);

		if (unlikely(nb_rx == 0))
		{
			// for (i = 0; i < BURST_SIZE; i++)
			// 	rte_pktmbuf_free(reply_buf[i]);
			continue;
		}

		uint16_t nb_tx_prepare = 0;
		for (i = 0; i < nb_rx; i++)
		{
			// Add your code here.
			uint8_t *data_addr = rte_pktmbuf_mtod(query_buf[i], void *);
			eth_hdr = (struct ether_hdr *)data_addr;
			ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
			udp_hdr = (struct udp_hdr *)(ip_hdr + 1);
			buffer = (uint8_t *)(udp_hdr + 1);
			reply_buf[i] = query_buf[i];

			int hdr_len = (int)(buffer - data_addr);
			// Add your code here.

			free_questions(msg.questions);
			free_resource_records(msg.answers);
			free_resource_records(msg.authorities);
			free_resource_records(msg.additionals);
			memset(&msg, 0, sizeof(struct Message));

			// filter the port 9000 not 9000
			if (*rte_pktmbuf_mtod_offset(query_buf[i], uint16_t *, 36) != rte_cpu_to_be_16(9000))
			{
				continue;
			}

			// assign the data start address to buffer

			// buffer = rte_pktmbuf_mtod_offset(query_buf[i], uint8_t *, 42); // 14 + 20 + 8 = 42

			/*********read input (begin)**********/
			// not DNS
			if (decode_msg(&msg, buffer, query_buf[i]->data_len - 42) != 0)
			{
				continue;
			}
			/* Print query */
			//print_query(&msg);

			resolver_process(&msg);
			/* Print response */
			//print_query(&msg);
			/*********read input (end)**********/

			//Add your code here.
			//Part 2.

			// plan the reply packet space.
			// add ethernet header, ipv4 header, udp header

			// rte_pktmbuf_append(reply_buf[nb_tx_prepare], sizeof(struct ether_hdr));
			// rte_pktmbuf_append(reply_buf[nb_tx_prepare], sizeof(struct ipv4_hdr));
			// rte_pktmbuf_append(reply_buf[nb_tx_prepare], sizeof(struct udp_hdr));

			/*********write output (begin)**********/
			uint8_t *p = buffer;
			if (encode_msg(&msg, &p) != 0)
			{
				continue;
			}

			uint32_t buflen = p - buffer;
			/*********write output (end)**********/

			//Add your code here.
			//Part 3.

			// // add the payload

			// char *payload = (char *)rte_pktmbuf_append(reply_buf[nb_tx_prepare], buflen);
			// rte_memcpy(payload, buffer, buflen);

			// // acording to query_buf, build DPDK packet head
			// build_packet(rte_pktmbuf_mtod_offset(query_buf[i], char *, 0), rte_pktmbuf_mtod_offset(reply_buf[nb_tx_prepare], char *, 0), buflen);

			rte_pktmbuf_append(reply_buf[i], buflen + hdr_len - reply_buf[i]->data_len);
			build_packet(data_addr, buflen + hdr_len);

			nb_tx_prepare++;
		}

		// send packet. 0???????????????0???queue???1???????????????1???queue
		nb_tx = rte_eth_tx_burst(port, lcore_id, reply_buf, nb_tx_prepare);

		total_rx += nb_tx_prepare;
		total_tx += nb_tx;

		// free query buffer and unsend packet.
		for (i = 0; i < nb_rx; i++)
		{
			rte_pktmbuf_free(query_buf[i]);
		}
		// for (i = nb_tx; i < nb_tx_prepare; i++)
		// {
		// 	rte_pktmbuf_free(reply_buf[i]);
		// }
	}

	// printf result
	printf("core id: %d nb_rx:%d, nb_tx:%d\n", lcore_id, total_rx, total_tx);
}

static int
dns_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	lcore_main_loop();
	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM)
	{
		printf("\n\nSignal %d received, preparing to exit...\n",
			   signum);
		force_quit = true;
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[])
{
	unsigned lcore_id;
	uint16_t portid = 0, nb_ports = 1;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
										MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize port 0. */
	if (port_init(portid, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(dns_launch_one_lcore, NULL, CALL_MASTER);

	// wait
	rte_eal_mp_wait_lcore();

	return 0;
}
