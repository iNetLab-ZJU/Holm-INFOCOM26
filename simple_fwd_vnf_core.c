/*
 * Copyright (c) 2021-2024 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, this list of
 *       conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *     * Neither the name of the NVIDIA CORPORATION nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NVIDIA CORPORATION BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TOR (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_flow.h>
#include <rte_hash.h>

#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>

#include <dpdk_utils.h>
#include <utils.h>

#include "simple_fwd_ft.h"
#include "simple_fwd_port.h"
#include "simple_fwd_vnf_core.h"

DOCA_LOG_REGISTER(SIMPLE_FWD_VNF : Core);

#define VNF_PKT_L2(M) rte_pktmbuf_mtod(M, uint8_t *) /* A marco that points to the start of the data in the mbuf */
#define VNF_PKT_LEN(M) rte_pktmbuf_pkt_len(M)	     /* A marco that returns the length of the packet */
#define VNF_RX_BURST_SIZE (32)			     /* Burst size of packets to read, RX burst read size */
#define VNF_TX_BURST_SIZE (32)
#define RX 1
#define TX 2
#define RATE_LIMITER 0

static int latency_dynfield_offset = -1;
#define GET_LATENCY_TS(m) \
    ((uint64_t *)RTE_MBUF_DYNFIELD(m, latency_dynfield_offset, uint64_t *))


/* Flag for forcing lcores to stop processing packets, and gracefully terminate the application */
static volatile bool force_quit;
extern struct simple_fwd_process_pkts_params process_pkts_params;
extern struct rte_ring *rx_ring_buffers[NUM_OF_PORTS][NUM_QOS_LEVELS];
extern FILE *latency_log;
extern struct rte_hash* ack_ts_map;
extern uint64_t ack_timestamps[MAX_TRACKED_FLOWS];
extern uint64_t added_latency[MAX_TRACKED_FLOWS];

/* Parameters used by each core */
struct vnf_per_core_params {
	int ports[NUM_OF_PORTS];  /* Ports identifiers */
	int queues[NUM_OF_PORTS]; /* Queue mapped for the core running */
	int used;		  /* Whether the core is used or not */
};

/* per core parameters */
static struct vnf_per_core_params core_params_arr[RTE_MAX_LCORE];
/*
 * Adjust the mbuf pointer, to point on the packet's raw data
 *
 * @m [in]: DPDK structure represent the packet received
 * @pinfo [in]: packet info representation  in the application
 */
static void vnf_adjust_mbuf(struct rte_mbuf *m, struct simple_fwd_pkt_info *pinfo)
{
	int diff = pinfo->outer.l2 - VNF_PKT_L2(m);

	rte_pktmbuf_adj(m, diff);
}

/*
 * Process received packets, mainly retrieving packet's key, then checking if there is an entry found
 * matching the generated key, in the entries table.
 * If no entry found, the function will create and add new one.
 * In addition, this function handles aging as well
 *
 * @mbuf [in]: DPDK structure represent the packet received
 * @queue_id [in]: Queue ID
 * @vnf [in]: Holder for all functions pointers used by the application
 */
static void simple_fwd_process_offload(struct rte_mbuf *mbuf, uint16_t queue_id, struct app_vnf *vnf, struct simple_fwd_pkt_info* pinfo)
{

	if (simple_fwd_parse_packet(VNF_PKT_L2(mbuf), VNF_PKT_LEN(mbuf), pinfo))
		return;
	pinfo->orig_data = mbuf;
	pinfo->orig_port_id = mbuf->port;
	pinfo->pipe_queue = queue_id;
	pinfo->rss_hash = mbuf->hash.rss;
	if (pinfo->outer.l3_type != IPV4)
		return;
	//vnf->vnf_process_pkt(&pinfo);
	//vnf_adjust_mbuf(mbuf, &pinfo);
    pinfo->tos = ((struct rte_ipv4_hdr *)pinfo->outer.l3)->type_of_service;


    printf("queue: %d TOS: 0x%02x\n", queue_id, pinfo->tos);
}


int process_rate_limiter() {
    return 0;
}


void register_latency_field() {
    struct rte_mbuf_dynfield field_desc = {
            .name = "latency_ts",
            .size = sizeof(uint64_t),
            .align = __alignof__(uint64_t),
            .flags = 0,
    };
    latency_dynfield_offset = rte_mbuf_dynfield_register(&field_desc);
    if (latency_dynfield_offset < 0) {
        rte_exit(EXIT_FAILURE, "Cannot register latency dynfield\n");
    }
}


int simple_fwd_process_pkts(void *process_pkts_params)
{
    uint32_t core_id = rte_lcore_id();
    uint16_t queue_id = core_params_arr[core_id].queues[0];
    const uint16_t port1 = 0;
    const uint16_t port2 = 1;
    struct rte_mbuf *mbufs[VNF_RX_BURST_SIZE];
    uint16_t nb_rx, nb_tx;

    if (core_params_arr[core_id].used != 1) {
        printf("Core %u not used\n", core_id);
    }

    while (!force_quit) {
        for (int rx_port = 0; rx_port < NUM_OF_PORTS; rx_port++) {
            uint16_t tx_port = rx_port ^ 1;
            nb_rx = rte_eth_rx_burst(rx_port, queue_id, mbufs, VNF_RX_BURST_SIZE);
            if (nb_rx == 0)
                continue;

            for (uint16_t i = 0; i < nb_rx; i++) {
                struct rte_mbuf *m = mbufs[i];
                struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

                if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                    rte_pktmbuf_free(m);
                    continue;
                }

                //提取 ip
                struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
                if (ip_hdr->next_proto_id != IPPROTO_TCP) {
                    rte_pktmbuf_free(m);
                    continue;
                }
                uint16_t ip_hdr_len = (ip_hdr->version_ihl & 0x0f) * 4;

                struct tcp_ack_key key = {};

                //提取 tcp
                struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)((char *)ip_hdr + ip_hdr_len);
                uint16_t tcp_hdr_len = ((tcp_hdr->data_off & 0xf0) >> 4) * 4;

                uint16_t total_len = rte_be_to_cpu_16(ip_hdr->total_length);
                uint16_t payload_len = total_len - ip_hdr_len - tcp_hdr_len;

                if (rx_port == port1) {
                    uint32_t seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);
                    uint32_t expected_ack = seq + payload_len;

                    key.src_port = tcp_hdr->src_port;
                    key.dst_port = tcp_hdr->dst_port,
                    key.ack_num = expected_ack;


                    uint64_t now = rte_rdtsc();
                    int ret = rte_hash_add_key(ack_ts_map, &key);
                    if (ret >= 0){
                        ack_timestamps[ret%MAX_TRACKED_FLOWS] = now;

                        if (Calculate_overhead) {
                            added_latency[ret%MAX_TRACKED_FLOWS] = now;
                        }
                    }


                } else if (rx_port == port2) {
                    if (tcp_hdr->tcp_flags & RTE_TCP_ACK_FLAG) {
                        uint32_t ack = rte_be_to_cpu_32(tcp_hdr->recv_ack);

                        key.src_port = tcp_hdr->dst_port;
                        key.dst_port = tcp_hdr->src_port,
                        key.ack_num = ack;

                        int ret = rte_hash_lookup(ack_ts_map, &key);
                        if (ret >= 0) {
                            uint64_t sent_tsc = ack_timestamps[ret%MAX_TRACKED_FLOWS];
                            uint64_t now = rte_rdtsc();
                            double latency_ns = (double)(now - sent_tsc) * 1e9 / rte_get_tsc_hz();
                            printf("Port %u TCP ACK: %u, delay = %.2f ns\n", port2, ack, latency_ns);
                            rte_hash_del_key(ack_ts_map, &key); // 可选：清除已匹配项
                        }
                    }
                }

                nb_tx = rte_eth_tx_burst(tx_port, queue_id, &m, 1);

                if (Calculate_overhead) {
                    int ret = rte_hash_lookup(ack_ts_map, &key);
                    if (ret >= 0) {
                        uint64_t now = rte_rdtsc();
                        double latency_ns = (double)(now - added_latency[ret%MAX_TRACKED_FLOWS]) * 1e9 / rte_get_tsc_hz();
                        printf("overhead latency delay = %.2f ns\n", latency_ns);
                    }
                }

                if (nb_tx < 1)
                    rte_pktmbuf_free(m);
            }
        }
    }

    return 0;
}

void simple_fwd_process_pkts_stop(void)
{
	force_quit = true;
}

/*
 * Callback function for setting time stats dump
 *
 * @param [in]: time for dumping stats
 * @config [out]: application configuration for setting the time
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t stats_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *)config;

	app_config->stats_timer = *(int *)param;
	DOCA_LOG_DBG("Set stats_timer:%lu", app_config->stats_timer);
	return DOCA_SUCCESS;
}

/*
 * Callback function for setting number of queues
 *
 * @param [in]: number of queues to set
 * @config [out]: application configuration for setting the number of queues
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t nr_queues_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *)config;
	int nr_queues = *(int *)param;

	if (nr_queues < 2) {
		DOCA_LOG_ERR("Invalid nr_queues should >= 2");
		return DOCA_ERROR_INVALID_VALUE;
	}
	app_config->dpdk_cfg->port_config.nb_queues = nr_queues;
	app_config->dpdk_cfg->port_config.rss_support = 1;
	DOCA_LOG_DBG("Set nr_queues:%u", nr_queues);
	return DOCA_SUCCESS;
}

/*
 * Callback function for setting the "rx-only" mode, where the application only receives packets
 *
 * @param [in]: parameter indicates whther or not to set the "rx-only" mode
 * @config [out]: application configuration to set the "rx-only" mode
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t rx_only_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *)config;

	app_config->rx_only = *(bool *)param ? 1 : 0;
	DOCA_LOG_DBG("Set rx_only:%u", app_config->rx_only);
	return DOCA_SUCCESS;
}

/*
 * Callback function for the HW offload
 *
 * @param [in]: parameter indicates whther or not to set the HW offload
 * @config [out]: application configuration to set the HW offload
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t hw_offload_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *)config;

	app_config->hw_offload = *(bool *)param ? 1 : 0;
	DOCA_LOG_DBG("Set hw_offload:%u", app_config->hw_offload);
	return DOCA_SUCCESS;
}

/*
 * Callback function for setting the hairpin usage
 *
 * @param [in]: parameter indicates whther or not to use hairpin queues
 * @config [out]: application configuration to set hairpin usage
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t hairpinq_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *)config;

	app_config->is_hairpin = *(bool *)param;
	DOCA_LOG_DBG("Set is_hairpin:%u", app_config->is_hairpin);
	return DOCA_SUCCESS;
}

/*
 * Callback function for setting dedicated thread for aging handling
 *
 * @param [in]: parameter indicates whther or not to use dedicated thread for aging
 * @config [out]: application configuration to set the usage of a dedicated thread for aged flows
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t age_thread_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *)config;

	app_config->age_thread = *(bool *)param;
	DOCA_LOG_DBG("Set age_thread:%s", app_config->age_thread ? "true" : "false");
	return DOCA_SUCCESS;
}

/*
 * Registers all flags used by the application for DOCA argument parser, so that when parsing
 * it can be parsed accordingly
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t register_simple_fwd_params(void)
{
	doca_error_t result;
	struct doca_argp_param *stats_param, *nr_queues_param, *rx_only_param, *hw_offload_param;
	struct doca_argp_param *hairpinq_param, *age_thread_param;

	/* Create and register stats timer param */
	result = doca_argp_param_create(&stats_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(stats_param, "t");
	doca_argp_param_set_long_name(stats_param, "stats-timer");
	doca_argp_param_set_arguments(stats_param, "<time>");
	doca_argp_param_set_description(stats_param, "Set interval to dump stats information");
	doca_argp_param_set_callback(stats_param, stats_callback);
	doca_argp_param_set_type(stats_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(stats_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Create and register queues number param */
	result = doca_argp_param_create(&nr_queues_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(nr_queues_param, "q");
	doca_argp_param_set_long_name(nr_queues_param, "nr-queues");
	doca_argp_param_set_arguments(nr_queues_param, "<num>");
	doca_argp_param_set_description(nr_queues_param, "Set queues number");
	doca_argp_param_set_callback(nr_queues_param, nr_queues_callback);
	doca_argp_param_set_type(nr_queues_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(nr_queues_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Create and register RX only param */
	result = doca_argp_param_create(&rx_only_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(rx_only_param, "r");
	doca_argp_param_set_long_name(rx_only_param, "rx-only");
	doca_argp_param_set_description(rx_only_param, "Set rx only");
	doca_argp_param_set_callback(rx_only_param, rx_only_callback);
	doca_argp_param_set_type(rx_only_param, DOCA_ARGP_TYPE_BOOLEAN);
	result = doca_argp_register_param(rx_only_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Create and register HW offload param */
	result = doca_argp_param_create(&hw_offload_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(hw_offload_param, "o");
	doca_argp_param_set_long_name(hw_offload_param, "hw-offload");
	doca_argp_param_set_description(hw_offload_param, "Set PCI address of the RXP engine to use");
	doca_argp_param_set_callback(hw_offload_param, hw_offload_callback);
	doca_argp_param_set_type(hw_offload_param, DOCA_ARGP_TYPE_BOOLEAN);
	result = doca_argp_register_param(hw_offload_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Create and register hairpin queue param */
	result = doca_argp_param_create(&hairpinq_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(hairpinq_param, "hq");
	doca_argp_param_set_long_name(hairpinq_param, "hairpinq");
	doca_argp_param_set_description(hairpinq_param, "Set forwarding to hairpin queue");
	doca_argp_param_set_callback(hairpinq_param, hairpinq_callback);
	doca_argp_param_set_type(hairpinq_param, DOCA_ARGP_TYPE_BOOLEAN);
	result = doca_argp_register_param(hairpinq_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Create and register age thread param */
	result = doca_argp_param_create(&age_thread_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(age_thread_param, "a");
	doca_argp_param_set_long_name(age_thread_param, "age-thread");
	doca_argp_param_set_description(age_thread_param, "Start thread do aging");
	doca_argp_param_set_callback(age_thread_param, age_thread_callback);
	doca_argp_param_set_type(age_thread_param, DOCA_ARGP_TYPE_BOOLEAN);
	result = doca_argp_register_param(age_thread_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Register version callback for DOCA SDK & RUNTIME */
	result = doca_argp_register_version_callback(sdk_version_callback);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register version callback: %s", doca_error_get_descr(result));
		return result;
	}
	return DOCA_SUCCESS;
}

void simple_fwd_map_queue(uint16_t nb_queues, uint16_t nb_tx)
{

	int i;
	memset(core_params_arr, 0, sizeof(core_params_arr));
//	for (i = 1; i <= nb_queues; i++) {
//        int queue_idx = i % nb_queues;
//		if (!rte_lcore_is_enabled(i))
//			continue;
//		core_params_arr[i].ports[0] = 0;
//		core_params_arr[i].ports[1] = 1;
//		core_params_arr[i].queues[0] = queue_idx;
//		core_params_arr[i].queues[1] = queue_idx;
//		core_params_arr[i].used = RX;
//	}
//
//    for (i = nb_queues + 1; i <= nb_queues + nb_tx; i++) {
//        if (!rte_lcore_is_enabled(i))
//            continue;
//        core_params_arr[i].used = TX;
//    }

    for(i = 1; i <= nb_queues; i++) {
        int queue_idx = i % nb_queues;
        core_params_arr[i].ports[0] = 0;
		core_params_arr[i].ports[1] = 1;
		core_params_arr[i].queues[0] = queue_idx;
		core_params_arr[i].queues[1] = queue_idx;
        core_params_arr[i].used = 1;
    }

}

void simple_fwd_destroy(struct app_vnf *vnf)
{
	vnf->vnf_destroy();
}


int init_ring_buffers(struct rte_ring *rx_ring_buffers[NUM_OF_PORTS][NUM_QOS_LEVELS]) {
    for(int p = 0; p < NUM_OF_PORTS; p++) {
        for (int i = 0; i < NUM_QOS_LEVELS; i++) {
            char ring_name[32];
            snprintf(ring_name, sizeof(ring_name), "rx_ring_p%d_q%d", p, i);

            rx_ring_buffers[p][i] = rte_ring_create(
                    ring_name,
                    1024,
                    rte_socket_id(),
                    0  // MP/MC 模式
            );

            if (rx_ring_buffers[p][i] == NULL) {
                rte_exit(EXIT_FAILURE, "Failed to create ring %d: %s\n", i, rte_strerror(rte_errno));
            }
        }
    }

    return 0;
}

