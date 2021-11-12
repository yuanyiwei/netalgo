#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <rte_ether.h>
#include <rte_udp.h>
#include <rte_pdump.h>
#include <arpa/inet.h>
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define IP_VERSION 0x40
#define IP_HDRLEN 0x05 /* default IP header length == five 32-bits words. */
#define IP_DEFTTL 64   /* from RFC 1340. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)
#define IP_DN_FRAGMENT_FLAG 0x0040
struct rte_mempool *mbuf_pool;

static const struct rte_eth_conf port_conf_default = {

	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_LEN,
	},
};

static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
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
		port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
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
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
										rte_eth_dev_socket_id(port),
										NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}
	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++)
	{
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
										rte_eth_dev_socket_id(port),
										&txconf);
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

static void build_udp_packet(struct rte_mbuf *worker)
{
	//DPDK
	struct ether_hdr *eth_header =
		(struct ether_hdr *)rte_pktmbuf_append(worker,
											   sizeof(struct ether_hdr));
	struct ipv4_hdr *ip_header =
		(struct ipv4_hdr *)rte_pktmbuf_append(worker,
											  sizeof(struct ipv4_hdr));
	struct udp_hdr *udp_header =
		(struct udp_hdr *)rte_pktmbuf_append(worker,
											 sizeof(struct udp_hdr));

	// UDP header
	udp_header->src_port = rte_cpu_to_be_16(0xf1);
	udp_header->dst_port = rte_cpu_to_be_16(0xf2);
	udp_header->dgram_len = rte_cpu_to_be_16(16);
	udp_header->dgram_cksum = 0;
	udp_header->dgram_cksum = rte_ipv4_udptcp_cksum(ip_header, udp_header);

	// IPv4 header
	ip_header->version_ihl = IP_VHL_DEF;
	ip_header->type_of_service = 0;
	ip_header->total_length = rte_cpu_to_be_16(21);
	ip_header->packet_id = 0;
	ip_header->fragment_offset = IP_DN_FRAGMENT_FLAG;
	ip_header->time_to_live = IP_DEFTTL;
	ip_header->next_proto_id = IPPROTO_UDP;
	uint32_t s_addr = 10 | (1 << 8) | (168 << 16) | (192 << 24);
	uint32_t d_addr = 11 | (1 << 8) | (168 << 16) | (192 << 24);
	ip_header->src_addr = rte_cpu_to_be_32(s_addr);
	ip_header->dst_addr = rte_cpu_to_be_32(d_addr);
	ip_header->hdr_checksum = 0;
	ip_header->hdr_checksum = rte_ipv4_cksum(ip_header);

	// Ethernet header
	rte_eth_macaddr_get(0, &eth_header->s_addr);
	rte_eth_macaddr_get(0, &eth_header->d_addr);
	eth_header->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

	char *payload = (char *)rte_pktmbuf_append(worker, 14);

	*(payload + 0) = 'h';
	*(payload + 1) = 'e';
	*(payload + 2) = 'l';
	*(payload + 3) = 'l';
	*(payload + 4) = 'o';
	*(payload + 5) = ',';
	*(payload + 6) = ' ';
	*(payload + 7) = 'w';
	*(payload + 8) = 'o';
	*(payload + 9) = 'r';
	*(payload + 10) = 'l';
	*(payload + 11) = 'd';
	*(payload + 12) = '.';
	*(payload + 13) = '\0';
}

/*
 * The lcore main. This is the main thread that does the work, construct
 * packet and deliver it.
 */
static __attribute__((noreturn)) void lcore_main(void)
{
	uint16_t port;
	/*
* Check that the port is on the same NUMA node as the polling thread
* for best performance.
*/
	RTE_ETH_FOREACH_DEV(port)
	if (rte_eth_dev_socket_id(port) > 0 &&
		rte_eth_dev_socket_id(port) != (int)rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to "
			   "polling thread.\n\tPerformance will "
			   "not be optimal.\n",
			   port);
	printf("\nCore %u is running. [Ctrl+C to quit]\n", rte_lcore_id());
	/* Run until the application is quit or killed. */
	for (;;)
	{
		int ret;
		struct rte_mbuf *worker;
		do
		{
			worker = rte_pktmbuf_alloc(mbuf_pool);
		} while (unlikely(worker == NULL));
		worker->nb_segs = 1;
		worker->next = NULL;
		build_udp_packet(worker);
		ret = rte_eth_tx_burst(0, 0, &worker, 1);
		/* Free unsent packet. */
		if (unlikely(ret < 1))
		{
			rte_pktmbuf_free(worker);
		}
		sleep(1);
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[])
{

	unsigned nb_ports;
	uint16_t portid;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	/* Initialize pdump framework */
	// rte_pdump_init(NULL);
	if (ret < 0)

		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	argc -= ret;
	argv += ret;
	nb_ports = rte_eth_dev_count_avail();
	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
										MBUF_CACHE_SIZE, 0,
										RTE_MBUF_DEFAULT_BUF_SIZE,
										rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid)
	if (port_init(portid, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
				 portid);
	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");
	/* Call lcore_main on the master core only. */
	lcore_main();
	return 0;
}
