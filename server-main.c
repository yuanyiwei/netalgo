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

#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#include "SimpleDNS.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_LEN,
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
	//Part 4. 原地修改
	
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
 * The lcore main. This is the main thread that does the work, read
 * an query packet and write an reply packet.
 */
static __attribute__((noreturn)) void
lcore_main(void)
{
	int send_count = 0;
	int resolved_count = 0;
	int output_flag = 0;
	uint16_t port = 0;	//only one port is used.
	//uint8_t query_buf_flag = 0;		//set to 1 after query packet received.
	struct rte_mbuf *query_buf[BURST_SIZE], *reply_buf[BURST_SIZE];
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udp_hdr;
	
	uint8_t *buffer;
	struct Message msg;
	memset(&msg, 0, sizeof(struct Message));
	
	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	if (rte_eth_dev_socket_id(port) > 0 &&
			rte_eth_dev_socket_id(port) !=
					(int)rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to "
				"polling thread.\n\tPerformance will "
				"not be optimal.\n", port);
	
	printf("\nSimpleDNS (using DPDK) is running...\n");
	/* Run until the application is quit or killed. */
	for (;;) {
		//Part 0. 接收并去掉头部。
		int nb_rx, nb_tx;
		nb_rx = rte_eth_rx_burst(port, 0, query_buf, BURST_SIZE);
		if(nb_rx == 0){
			if(output_flag == 0){
				output_flag = 1;
				printf("Send: %d, Resolved: %d\n", send_count, resolved_count);
			}
			continue;
		}
		int i;
		for(i = 0; i < nb_rx; i ++){
			//printf("query_buf[%d]\n", i);
			//printf("0 OK! nb_rx: %d; data_len: %d; pkt_len: %d\n", nb_rx, query_buf[0]->data_len, query_buf[0]->pkt_len);
			//fflush(stdout);
			uint8_t *data_addr = rte_pktmbuf_mtod(query_buf[i], void *);
			eth_hdr = (struct ether_hdr *)data_addr;
			ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
			udp_hdr = (struct udp_hdr *)(ip_hdr + 1);
			buffer = (uint8_t *)(udp_hdr + 1);
			reply_buf[i] = query_buf[i];
			
			//printf("1 OK! eth_hdr: %d\n", ntohs(eth_hdr->ether_type));
			//fflush(stdout);

			if(eth_hdr->ether_type != htons(0x800)){
				nb_rx = i;
				break;
			}
			//printf("2 OK!\n");
			//fflush(stdout);
			if(ip_hdr->next_proto_id != 0x11){
				nb_rx = i;
				break;
			}
			//printf("3 OK!\n");
			//fflush(stdout);
			if(udp_hdr->dst_port != htons(9000u)){
				nb_rx = i;
				break;
			}
			//printf("4 OK!\n");
			//fflush(stdout);

			//Only allow UDP packet to port 9000
			int hdr_len = (int)(buffer - data_addr);
			int nbytes = query_buf[i]->data_len - hdr_len;
			
			/*********preparation (begin)**********/
			free_questions(msg.questions);
			free_resource_records(msg.answers);
			free_resource_records(msg.authorities);
			free_resource_records(msg.additionals);
			memset(&msg, 0, sizeof(struct Message));
			/*********preparation (end)**********/
			
			//Add your code here.
			//Part 1.  nothing
			
			/*********read input (begin)**********/
			if (decode_msg(&msg, buffer, nbytes) != 0) {
				continue;
			}
			/* Print query */
			//print_query(&msg);

			resolver_process(&msg);

			/* Print response */
			//print_query(&msg);
			/*********read input (end)**********/
			
			//Add your code here.
			//Part 2. nothing
			//原地修改，所以此处什么都不干。
			
			/*********write output (begin)**********/
			uint8_t *p = buffer;
			if (encode_msg(&msg, &p) != 0) {
				continue;
			}

			uint32_t buflen = p - buffer;
			/*********write output (end)**********/
			
			//Add your code here.
			//Part 3. 修改包头
			rte_pktmbuf_append(reply_buf[i], buflen + hdr_len - reply_buf[i]->data_len);
			build_packet(data_addr, buflen + hdr_len);
			resolved_count ++;
		}

		//printf("5 OK!\n");
		//fflush(stdout);
		if(nb_rx != 0){
			nb_tx = rte_eth_tx_burst(port, 0, reply_buf, nb_rx);
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(query_buf[buf]);
			}
			send_count += nb_tx;
			output_flag = 0;
		}
		//printf("6 OK!\n");
		//fflush(stdout);
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	uint16_t portid = 0, nb_ports = 1;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize port 0. */
	if (port_init(portid, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	lcore_main();

	return 0;
}
