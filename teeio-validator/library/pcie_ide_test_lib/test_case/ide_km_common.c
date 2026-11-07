/**
 *  Copyright Notice:
 *  Copyright 2023-2024 Intel. All rights reserved.
 *  License: BSD 3-Clause License.
 **/

#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#include "assert.h"
#include "hal/base.h"
#include "hal/library/debuglib.h"

#include "hal/library/memlib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/pci_ide_km_requester_lib.h"
#include "library/spdm_crypt_lib.h"
#include "ide_test.h"
#include "helperlib.h"
#include "teeio_debug.h"
#include "pcie_ide_lib.h"
#include "pcie_ide_test_lib.h"

extern bool g_teeio_fixed_key;

const char *k_set_names[] = {
    "KS0", "KS1"};

const char *direction_names[] = {
    "RX", "TX"};

const char *substream_names[] = {
    "PR", "NPR", "CPL"};

/**
 * Dump key_iv in rootport registers
 * Refer to Root Complex IDE Key Configuration Unit Software Programing Guide Revision 1.01
 *   Figure 2-3 Key Slot
 *   Figure 2-4 IV Value Slot
 */
void pcie_dump_key_iv_in_rp(const char* direction, uint8_t *key, int key_size, uint8_t* iv, int iv_size)
{
  int i = 0;
  TEEIO_ASSERT(key_size == 32);
  TEEIO_ASSERT(iv_size == 8);

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "PCIe IDE Key in rootport registers (%s Key Slots):\n", direction));
  for(i = 0; i < 8; i++) {
    TEEIO_DEBUG((TEEIO_DEBUG_INFO, "  Key_DW%d: 0x%08x\n", i, *(uint32_t *)(key + i*4)));
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "PCIe IDE IV in rootport registers (%s IV Slots):\n", direction));
  for(i = 0; i < 2; i++) {
    TEEIO_DEBUG((TEEIO_DEBUG_INFO, "  IFV_DW%d: 0x%08x\n", i, *(uint32_t *)(iv + i*4)));
  }
}

// program keys to device card and root port
bool ide_km_key_prog(
    const void *pci_doe_context,
    void *spdm_context,
    const uint32_t *session_id,
    uint8_t ks,
    uint8_t direction,
    uint8_t substream,
    uint8_t port_index,
    uint8_t stream_id,
    uint8_t *kcbar_addr,
    ide_key_set_t *k_set,
    uint8_t rp_stream_index)
{
    bool result;
    pci_ide_km_aes_256_gcm_key_buffer_t key_buffer;
    uint8_t kp_ack_status;
    uint8_t slot_id;
    libspdm_return_t status;
    INTEL_KEYP_ROOT_COMPLEX_KCBAR *kcbar_ptr = 0;
    INTEL_KEYP_KEY_SLOT keys = {0};
    INTEL_KEYP_IV_SLOT iv = {0};
    uint8_t fixed_key_byte = 0;

    uint8_t k_sets[] = {PCI_IDE_KM_KEY_SET_K0, PCI_IDE_KM_KEY_SET_K1};
    uint8_t directions[] = {PCI_IDE_KM_KEY_DIRECTION_RX, PCI_IDE_KM_KEY_DIRECTION_TX};
    uint8_t substreams[] = {PCI_IDE_KM_KEY_SUB_STREAM_PR, PCI_IDE_KM_KEY_SUB_STREAM_NPR, PCI_IDE_KM_KEY_SUB_STREAM_CPL};

    iv.bytes[0] = PCIE_IDE_IV_INIT_VALUE;

    TEEIO_ASSERT(ks < PCIE_IDE_STREAM_KS_NUM);
    TEEIO_ASSERT(direction < PCIE_IDE_STREAM_DIRECTION_NUM);
    TEEIO_ASSERT(substream < PCIE_IDE_SUB_STREAM_NUM);

    if(direction == PCIE_IDE_STREAM_RX) {
      fixed_key_byte = TEEIO_TEST_FIXED_RX_KEY_BYTE_VALUE;
    } else {
      fixed_key_byte = TEEIO_TEST_FIXED_TX_KEY_BYTE_VALUE;
    }

    if(!g_teeio_fixed_key) {
      result = libspdm_get_random_number(sizeof(key_buffer.key), (void *)key_buffer.key);
      if(!result) {
        return false;
      }
    } else {
      memset(key_buffer.key, fixed_key_byte, sizeof(key_buffer.key));
    }

    key_buffer.iv[0] = 0;
    key_buffer.iv[1] = PCIE_IDE_IV_INIT_VALUE;

    status = pci_ide_km_key_prog(pci_doe_context, spdm_context, session_id,
                                 stream_id,
                                 k_sets[ks] | directions[direction] | substreams[substream],
                                 port_index,
                                 &key_buffer,
                                 &kp_ack_status);
    if(LIBSPDM_STATUS_IS_ERROR(status)) {
      TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "pci_ide_km_key_prog failed with status=0x%x\n", status));
      return false;
    }

    TEEIO_DEBUG((TEEIO_DEBUG_INFO, "dev key_prog %s|%s|%s - sts=%02x\n", k_set_names[ks], direction_names[direction], substream_names[substream], kp_ack_status));
    dump_key_iv_in_key_prog(key_buffer.key, sizeof(key_buffer.key)/sizeof(uint32_t), key_buffer.iv, sizeof(key_buffer.iv)/sizeof(uint32_t));

    if(kp_ack_status != PCI_IDE_KM_KP_ACK_STATUS_SUCCESS) {
      TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "pci_ide_km_key_prog failed with kp_ack_status=0x%x\n", kp_ack_status));
      return false;
    }

    kcbar_ptr = (INTEL_KEYP_ROOT_COMPLEX_KCBAR *)kcbar_addr;

    // program key in root port kcbar registers
    pcie_construct_rp_keys(key_buffer.key, sizeof(key_buffer.key), keys.bytes, sizeof(keys.bytes));
    slot_id = k_set->slot_id[direction][substream];
    cfg_rootport_ide_keys(kcbar_ptr, rp_stream_index, direction, ks, substream, slot_id, &keys, &iv);
    TEEIO_DEBUG((TEEIO_DEBUG_INFO, "rp key_prog %s|%s|%s - @key/iv slot[%02x]\n", k_set_names[ks], direction_names[direction], substream_names[substream], slot_id));
    pcie_dump_key_iv_in_rp(direction == PCIE_IDE_STREAM_RX ? "TX" : "RX", (uint8_t *)keys.bytes, sizeof(keys.bytes), (uint8_t *)iv.bytes, sizeof(iv.bytes));

    return true;
}

libspdm_return_t ide_km_key_set_go(const void *pci_doe_context,
                                   void *spdm_context, const uint32_t *session_id,
                                   uint8_t stream_id, uint8_t key_sub_stream,
                                   uint8_t port_index)
{
    libspdm_return_t status;
    pci_ide_km_k_set_go_t request;
    size_t request_size;
    pci_ide_km_k_gostop_ack_t response;
    size_t response_size;
    bool res;

    libspdm_zero_mem(&request, sizeof(request));
    request.header.object_id = PCI_IDE_KM_OBJECT_ID_K_SET_GO;
    request.stream_id = stream_id;
    request.key_sub_stream = key_sub_stream;
    request.port_index = port_index;

    request_size = sizeof(request);
    response_size = sizeof(response);
    status = pci_ide_km_send_receive_data(spdm_context, session_id,
                                          &request, request_size,
                                          &response, &response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
      return status;
    }

    res = response_size == sizeof(pci_ide_km_k_gostop_ack_t);
    if(!res) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    res = response.header.object_id == PCI_IDE_KM_OBJECT_ID_K_SET_GOSTOP_ACK;
    if(!res)
    {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    res = response.port_index == request.port_index;
    if(!res)
    {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    res = response.stream_id == request.stream_id;
    if(!res)
    {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    res = response.key_sub_stream == request.key_sub_stream;
    if(!res)
    {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

// AER register offsets relative to the AER extended capability
#define AER_UESTA_OFFSET            0x04
#define AER_CESTA_OFFSET            0x10
#define AER_CAP_CTRL_OFFSET         0x18
#define AER_HDR_LOG_OFFSET          0x1C
#define AER_TLP_PREFIX_LOG_OFFSET   0x38
#define AER_UESTA_CPL_TIMEOUT       (1u << 14)
#define AER_UESTA_IDE_CHECK_FAILED  (1u << 28)
#define AER_UESTA_MISROUTED_IDE_TLP (1u << 29)
#define AER_UESTA_PCRC_CHECK_FAILED (1u << 30)
#define AER_CAP_CTRL_PREFIX_LOG_PRESENT (1u << 11)

static void dump_aer_for_debug(const char* who, int cfg_space_fd)
{
  uint32_t aer = get_extended_cap_offset(cfg_space_fd, PCI_AER_EXT_CAPABILITY_ID);
  if(aer == 0) {
    TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[kr-dbg] %s: no AER ecap\n", who));
    return;
  }

  uint32_t uesta = device_pci_read_32(aer + AER_UESTA_OFFSET, cfg_space_fd);
  uint32_t cesta = device_pci_read_32(aer + AER_CESTA_OFFSET, cfg_space_fd);
  uint32_t capctl = device_pci_read_32(aer + AER_CAP_CTRL_OFFSET, cfg_space_fd);
  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[kr-dbg] %s AER@0x%03x: UESTA=0x%08x (IdeChk=%d Misrouted=%d PcrcChk=%d CplTo=%d) CESTA=0x%08x FirstErrPtr=%d\n",
    who, aer, uesta,
    !!(uesta & AER_UESTA_IDE_CHECK_FAILED),
    !!(uesta & AER_UESTA_MISROUTED_IDE_TLP),
    !!(uesta & AER_UESTA_PCRC_CHECK_FAILED),
    !!(uesta & AER_UESTA_CPL_TIMEOUT),
    cesta, capctl & 0x1f));

  if(uesta != 0) {
    TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[kr-dbg] %s HdrLog : %08x %08x %08x %08x\n", who,
      device_pci_read_32(aer + AER_HDR_LOG_OFFSET + 0, cfg_space_fd),
      device_pci_read_32(aer + AER_HDR_LOG_OFFSET + 4, cfg_space_fd),
      device_pci_read_32(aer + AER_HDR_LOG_OFFSET + 8, cfg_space_fd),
      device_pci_read_32(aer + AER_HDR_LOG_OFFSET + 12, cfg_space_fd)));
    if(capctl & AER_CAP_CTRL_PREFIX_LOG_PRESENT) {
      TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[kr-dbg] %s PfxLog : %08x %08x %08x %08x\n", who,
        device_pci_read_32(aer + AER_TLP_PREFIX_LOG_OFFSET + 0, cfg_space_fd),
        device_pci_read_32(aer + AER_TLP_PREFIX_LOG_OFFSET + 4, cfg_space_fd),
        device_pci_read_32(aer + AER_TLP_PREFIX_LOG_OFFSET + 8, cfg_space_fd),
        device_pci_read_32(aer + AER_TLP_PREFIX_LOG_OFFSET + 12, cfg_space_fd)));
    }
  }
}

// RP tx key_set_status = key set RP TX uses; RP rx last_rcvd_set_* = K bit the EP TX last sent per sub-stream.
void pcie_ide_dump_key_switch_state(const char* tag, uint8_t* kcbar_addr, uint8_t rp_stream_index,
                                    TEST_IDE_TYPE ide_type,
                                    ide_common_test_port_context_t* upper_port,
                                    ide_common_test_port_context_t* lower_port,
                                    bool with_aer)
{
  INTEL_KEYP_STREAM_CONFIG_REG_BLOCK *blk = get_stream_cfg_reg_block((INTEL_KEYP_ROOT_COMPLEX_KCBAR *)kcbar_addr, rp_stream_index);
  INTEL_KEYP_STREAM_TXRX_CONTROL tx_ctrl = {.raw = mmio_read_reg32(&blk->tx_ctrl)};
  INTEL_KEYP_STREAM_TXRX_STATUS tx_sts = {.raw = mmio_read_reg32(&blk->tx_status)};
  INTEL_KEYP_STREAM_TXRX_CONTROL rx_ctrl = {.raw = mmio_read_reg32(&blk->rx_ctrl)};
  INTEL_KEYP_STREAM_TXRX_STATUS rx_sts = {.raw = mmio_read_reg32(&blk->rx_status)};

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[kr-dbg] %s\n", tag));
  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[kr-dbg]   RP TX: ctrl=0x%08x (key_set_select=%d prime0=%d prime1=%d) status=0x%08x (key_set_status=%d ready0=%d ready1=%d)\n",
    tx_ctrl.raw, tx_ctrl.stream_tx_control.key_set_select, tx_ctrl.stream_tx_control.prime_key_set_0, tx_ctrl.stream_tx_control.prime_key_set_1,
    tx_sts.raw, tx_sts.stream_tx_status.key_set_status, tx_sts.stream_tx_status.ready_key_set_0, tx_sts.stream_tx_status.ready_key_set_1));
  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[kr-dbg]   RP RX: ctrl=0x%08x (prime0=%d prime1=%d) status=0x%08x (last_rcvd pr=%d npr=%d cpl=%d ready0=%d ready1=%d)\n",
    rx_ctrl.raw, rx_ctrl.stream_rx_control.prime_key_set_0, rx_ctrl.stream_rx_control.prime_key_set_1,
    rx_sts.raw, rx_sts.stream_rx_status.last_rcvd_set_pr, rx_sts.stream_rx_status.last_rcvd_set_npr, rx_sts.stream_rx_status.last_rcvd_set_cpl,
    rx_sts.stream_rx_status.ready_key_set_0, rx_sts.stream_rx_status.ready_key_set_1));

  PCIE_SEL_IDE_STREAM_STATUS rp_ss = {.raw = read_stream_status_in_rp_ecap(upper_port->cfg_space_fd, upper_port->ecap_offset, ide_type, upper_port->ide_id)};
  PCIE_SEL_IDE_STREAM_STATUS ep_ss = {.raw = read_ide_stream_status_in_ecap(lower_port->cfg_space_fd, ide_type, lower_port->ide_id, lower_port->ecap_offset)};
  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[kr-dbg]   StreamStatus RP=0x%08x (state=%d chkfail_msg=%d)  EP=0x%08x (state=%d chkfail_msg=%d)\n",
    rp_ss.raw, rp_ss.state, rp_ss.recv_intg_check_fail_msg, ep_ss.raw, ep_ss.state, ep_ss.recv_intg_check_fail_msg));

  if(with_aer) {
    dump_aer_for_debug("RP", upper_port->cfg_space_fd);
    dump_aer_for_debug("EP", lower_port->cfg_space_fd);
  }
}

bool is_ide_stream_secure(TEST_IDE_TYPE ide_type,
                          int rp_cfg_space_fd, uint32_t rp_ecap_offset, uint8_t rp_ide_id,
                          int ep_cfg_space_fd, uint32_t ep_ecap_offset, uint8_t ep_ide_id)
{
  PCIE_SEL_IDE_STREAM_STATUS stream_status;

  // Check IDE stream status on root port
  stream_status.raw = read_stream_status_in_rp_ecap(rp_cfg_space_fd, rp_ecap_offset, ide_type, rp_ide_id);
  if (stream_status.state != IDE_STREAM_STATUS_SECURE)
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "RP ide_stream state is %x.\n", stream_status.state));
    return false;
  }

  // Check IDE stream status on the device
  stream_status.raw = read_ide_stream_status_in_ecap(ep_cfg_space_fd, ide_type, ep_ide_id, ep_ecap_offset);
  if (stream_status.state != IDE_STREAM_STATUS_SECURE)
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "EP ide_stream state is %x.\n", stream_status.state));
    return false;
  }

  return true;
}

typedef struct {
  uint32_t tx_sts;
  uint32_t rx_sts;
  uint32_t rp_ues;
  uint32_t ep_ues;
} kr_watch_t;

static kr_watch_t m_kr_prev;
static bool m_kr_prev_valid = false;

static void kr_watch_read(kr_watch_t* w, uint8_t* kcbar_addr, uint8_t rp_stream_index,
                          ide_common_test_port_context_t* upper_port,
                          ide_common_test_port_context_t* lower_port)
{
  INTEL_KEYP_STREAM_CONFIG_REG_BLOCK *blk = get_stream_cfg_reg_block((INTEL_KEYP_ROOT_COMPLEX_KCBAR *)kcbar_addr, rp_stream_index);
  uint32_t rp_aer = get_extended_cap_offset(upper_port->cfg_space_fd, PCI_AER_EXT_CAPABILITY_ID);
  uint32_t ep_aer = get_extended_cap_offset(lower_port->cfg_space_fd, PCI_AER_EXT_CAPABILITY_ID);

  w->tx_sts = mmio_read_reg32(&blk->tx_status);
  w->rx_sts = mmio_read_reg32(&blk->rx_status);
  w->rp_ues = rp_aer ? device_pci_read_32(rp_aer + AER_UESTA_OFFSET, upper_port->cfg_space_fd) : 0;
  w->ep_ues = ep_aer ? device_pci_read_32(ep_aer + AER_UESTA_OFFSET, lower_port->cfg_space_fd) : 0;
}

// Start watching from the current register values.
void pcie_ide_watch_rebase(uint8_t* kcbar_addr, uint8_t rp_stream_index,
                           ide_common_test_port_context_t* upper_port,
                           ide_common_test_port_context_t* lower_port)
{
  kr_watch_read(&m_kr_prev, kcbar_addr, rp_stream_index, upper_port, lower_port);
  m_kr_prev_valid = true;
}

// Silent unless RP tx/rx key status or either port's AER UESTA changed; then log old->new plus a full snapshot.
bool pcie_ide_watch_poll(const char* tag, uint8_t* kcbar_addr, uint8_t rp_stream_index,
                         TEST_IDE_TYPE ide_type,
                         ide_common_test_port_context_t* upper_port,
                         ide_common_test_port_context_t* lower_port)
{
  kr_watch_t cur;
  kr_watch_read(&cur, kcbar_addr, rp_stream_index, upper_port, lower_port);

  if(!m_kr_prev_valid) {
    m_kr_prev = cur;
    m_kr_prev_valid = true;
    return false;
  }
  if(cur.tx_sts == m_kr_prev.tx_sts && cur.rx_sts == m_kr_prev.rx_sts &&
     cur.rp_ues == m_kr_prev.rp_ues && cur.ep_ues == m_kr_prev.ep_ues) {
    return false;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[kr-dbg] %s CHANGE: RP tx_sts 0x%08x->0x%08x  rx_sts 0x%08x->0x%08x  RP UESTA 0x%08x->0x%08x  EP UESTA 0x%08x->0x%08x\n",
    tag, m_kr_prev.tx_sts, cur.tx_sts, m_kr_prev.rx_sts, cur.rx_sts,
    m_kr_prev.rp_ues, cur.rp_ues, m_kr_prev.ep_ues, cur.ep_ues));
  m_kr_prev = cur;
  pcie_ide_dump_key_switch_state(tag, kcbar_addr, rp_stream_index, ide_type, upper_port, lower_port, true);
  return true;
}

#define KR_CUTOVER_TIMEOUT_MS 3000

// RP TX reports the new key set only after it has sent a TLP on it, so a Secure check right after K_SET_GO proves nothing about the cutover.
bool pcie_ide_wait_key_cutover(uint8_t ks, uint8_t* kcbar_addr, uint8_t rp_stream_index,
                               TEST_IDE_TYPE ide_type,
                               ide_common_test_port_context_t* upper_port,
                               ide_common_test_port_context_t* lower_port)
{
  INTEL_KEYP_STREAM_CONFIG_REG_BLOCK *blk = get_stream_cfg_reg_block((INTEL_KEYP_ROOT_COMPLEX_KCBAR *)kcbar_addr, rp_stream_index);
  int waited_ms = 0;

  pcie_ide_watch_rebase(kcbar_addr, rp_stream_index, upper_port, lower_port);
  while(waited_ms < KR_CUTOVER_TIMEOUT_MS) {
    INTEL_KEYP_STREAM_TXRX_STATUS s = {.raw = mmio_read_reg32(&blk->tx_status)};
    if(s.stream_tx_status.key_set_status == (uint32_t)(ks + 1)) {
      break;
    }
    libspdm_sleep(10 * 1000);
    waited_ms += 10;
    pcie_ide_watch_poll("cutover wait", kcbar_addr, rp_stream_index, ide_type, upper_port, lower_port);
  }
  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "[kr-dbg] RP TX cutover to %s %s (waited %d ms)\n",
    k_set_names[ks], waited_ms < KR_CUTOVER_TIMEOUT_MS ? "observed" : "NOT observed", waited_ms));

  bool secure = is_ide_stream_secure(ide_type,
                                     upper_port->cfg_space_fd, upper_port->ecap_offset, upper_port->ide_id,
                                     lower_port->cfg_space_fd, lower_port->ecap_offset, lower_port->ide_id);
  pcie_ide_dump_key_switch_state(secure ? "[7] after cutover wait, stream secure" : "[7] after cutover wait, FAILURE",
                                 kcbar_addr, rp_stream_index, ide_type, upper_port, lower_port, !secure);
  return secure;
}

// setup ide stream
bool setup_ide_stream(void* doe_context, void* spdm_context,
                    uint32_t* session_id, uint8_t* kcbar_addr,
                    uint8_t stream_id, uint8_t ks,
                    ide_key_set_t* k_set, uint8_t rp_stream_index,
                    uint8_t port_index, IDE_TEST_TOPOLOGY_TYPE top_type,
                    ide_common_test_port_context_t* upper_port,
                    ide_common_test_port_context_t* lower_port,
                    bool skip_ksetgo)
{
  libspdm_return_t status;
  bool result;

  int upper_port_cfg_space_fd = upper_port->cfg_space_fd;
  uint32_t upper_port_ecap_offset = upper_port->ecap_offset;
  int lower_port_cfg_space_fd = lower_port->cfg_space_fd;
  uint32_t lower_port_ecap_offset = lower_port->ecap_offset;

  uint8_t dev_func_num;
  uint8_t bus_num;
  uint8_t segment;
  uint8_t max_port_index;
  uint32_t ide_reg_block[PCI_IDE_KM_IDE_REG_BLOCK_SUPPORTED_COUNT] = {0};
  uint32_t ide_reg_block_count;

  // first query
  ide_reg_block_count = PCI_IDE_KM_IDE_REG_BLOCK_SUPPORTED_COUNT;
  status = pci_ide_km_query(doe_context,
                            spdm_context,
                            session_id,
                            port_index,
                            &dev_func_num,
                            &bus_num,
                            &segment,
                            &max_port_index,
                            ide_reg_block,
                            &ide_reg_block_count);
  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "pci_ide_km_query failed with status=0x%x\n", status));
    return false;
  }

  // ide_km_key_prog
  result = ide_km_key_prog(
      doe_context, spdm_context,
      session_id, ks, PCIE_IDE_STREAM_RX, PCIE_IDE_SUB_STREAM_PR,
      port_index, // port_index
      stream_id,
      kcbar_addr,
      k_set,
      rp_stream_index);
  if(!result) {
    return false;
  }

  result = ide_km_key_prog(
      doe_context, spdm_context,
      session_id, ks, PCIE_IDE_STREAM_RX, PCIE_IDE_SUB_STREAM_NPR,
      port_index,
      stream_id,
      kcbar_addr,
      k_set,
      rp_stream_index);
  if(!result) {
    return false;
  }

  result = ide_km_key_prog(
      doe_context, spdm_context,
      session_id, ks, PCIE_IDE_STREAM_RX, PCIE_IDE_SUB_STREAM_CPL,
      port_index,
      stream_id,
      kcbar_addr,
      k_set,
      rp_stream_index);
  if(!result) {
    return false;
  }

  prime_rp_ide_key_set(
      (INTEL_KEYP_ROOT_COMPLEX_KCBAR *)kcbar_addr,
      rp_stream_index,
      PCIE_IDE_STREAM_RX,
      ks);

  result = ide_km_key_prog(
      doe_context, spdm_context,
      session_id, ks, PCIE_IDE_STREAM_TX, PCIE_IDE_SUB_STREAM_PR,
      port_index,
      stream_id,
      kcbar_addr,
      k_set,
      rp_stream_index);
  if(!result) {
    return false;
  }

  result = ide_km_key_prog(
      doe_context, spdm_context,
      session_id, ks, PCIE_IDE_STREAM_TX, PCIE_IDE_SUB_STREAM_NPR,
      port_index,
      stream_id,
      kcbar_addr,
      k_set,
      rp_stream_index);
  if(!result) {
    return false;
  }

  result = ide_km_key_prog(
      doe_context, spdm_context,
      session_id, ks, PCIE_IDE_STREAM_TX, PCIE_IDE_SUB_STREAM_CPL,
      port_index,
      stream_id,
      kcbar_addr,
      k_set,
      rp_stream_index);
  if(!result) {
    return false;
  }

  prime_rp_ide_key_set(
      (INTEL_KEYP_ROOT_COMPLEX_KCBAR *)kcbar_addr,
      rp_stream_index,
      PCIE_IDE_STREAM_TX,
      ks);

  if(skip_ksetgo) {
    return true;
  }

  // Now KSetGo
  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|RX|PR\n", k_set_names[ks]));
  status = ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_PR, port_index);
  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|RX|PR failed with 0x%x\n", k_set_names[ks], status));
    return false;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|RX|NPR\n", k_set_names[ks]));
  status = ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_NPR, port_index);

  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "KSetGo %s|RX|NPR failed with 0x%x\n", k_set_names[ks], status));
    return false;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|RX|CPL\n", k_set_names[ks]));
  status = ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_CPL, port_index);

  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "KSetGo %s|RX|CPL failed with 0x%x\n", k_set_names[ks], status));
    return false;
  }

  // set key_set_select in host ide
  INTEL_KEYP_ROOT_COMPLEX_KCBAR *kcbar = (INTEL_KEYP_ROOT_COMPLEX_KCBAR *)kcbar_addr;
  set_rp_ide_key_set_select(kcbar, rp_stream_index, ks);

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|TX|PR\n", k_set_names[ks]));
  status = ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_PR, port_index);
  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "KSetGo %s|TX|PR failed with 0x%x\n", k_set_names[ks], status));
    return false;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|TX|NPR\n", k_set_names[ks]));
  status = ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_NPR, port_index);

  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "KSetGo %s|TX|NPR failed with 0x%x\n", k_set_names[ks], status));
    return false;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|TX|CPL\n", k_set_names[ks]));
  status = ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_CPL, port_index);

  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "KSetGo %s|TX|CPL failed with 0x%x\n", k_set_names[ks], status));
    return false;
  }

  // enable dev ide
  TEST_IDE_TYPE ide_type = TEST_IDE_TYPE_SEL_IDE;
  if (top_type == IDE_TEST_TOPOLOGY_TYPE_LINK_IDE)
  {
    ide_type = IDE_TEST_TOPOLOGY_TYPE_LINK_IDE;
  }
  else if(top_type == IDE_TEST_TOPOLOGY_TYPE_SEL_LINK_IDE)
  {
    NOT_IMPLEMENTED("selective_and_link_ide topoplogy");
  }
  enable_ide_stream_in_ecap(lower_port_cfg_space_fd, lower_port_ecap_offset, ide_type, lower_port->ide_id, true);

  // enable host ide stream
  enable_rootport_ide_stream(upper_port_cfg_space_fd,
                         upper_port_ecap_offset,
                         ide_type, upper_port->ide_id,
                         kcbar_addr,
                         rp_stream_index, true);

  // wait for 10 ms for device to get ide ready
  libspdm_sleep(10 * 1000);

  // Now ide stream shall be in secure state
  return is_ide_stream_secure(ide_type,
                              upper_port_cfg_space_fd, upper_port_ecap_offset, upper_port->ide_id,
                              lower_port->cfg_space_fd, lower_port->ecap_offset, lower_port->ide_id);
}

// key switch to @ks
bool ide_key_switch_to(void* doe_context, void* spdm_context,
                    uint32_t* session_id, uint8_t* kcbar_addr,
                    uint8_t stream_id, ide_key_set_t* k_set, uint8_t rp_stream_index,
                    uint8_t port_index, IDE_TEST_TOPOLOGY_TYPE top_type,
                    ide_common_test_port_context_t* upper_port,
                    ide_common_test_port_context_t* lower_port,
                    uint8_t ks, bool skip_ksetgo)
{
    int cmd = 0;
    TEST_IDE_TYPE ide_type = TEST_IDE_TYPE_SEL_IDE;
    int upper_port_cfg_space_fd = upper_port->cfg_space_fd;
    uint32_t upper_port_ecap_offset = upper_port->ecap_offset;

    if(top_type == IDE_TEST_TOPOLOGY_TYPE_LINK_IDE) {
        ide_type = TEST_IDE_TYPE_LNK_IDE;
    } else if(top_type == IDE_TEST_TOPOLOGY_TYPE_SEL_LINK_IDE) {
        NOT_IMPLEMENTED("selective_and_link_ide topoplogy");
    }

    // step1: ensure host_ide and dev_ide is enabled
    if(!is_ide_enabled(upper_port->cfg_space_fd, ide_type, upper_port->ide_id, upper_port->ecap_offset)) {
        TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "upper_port ide is not enabled.\n"));
        return false;
    }
    if(!is_ide_enabled(lower_port->cfg_space_fd, ide_type, lower_port->ide_id, lower_port->ecap_offset)) {
        TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "lower_port ide is not enabled.\n"));
        return false;
    }

    // step 2: program keys in rp/dev in RX/TX direction

  pcie_ide_dump_key_switch_state("[1] before KEY_PROG (baseline)", kcbar_addr, rp_stream_index, ide_type, upper_port, lower_port, true);

  // Before programming keys, we shall find empty key/iv slot
  while(true) {
    if(pcie_ide_alloc_slot_ids(upper_port, rp_stream_index, k_set)) {
      break;
    } else {
      TEEIO_PRINT(("There is no empty key/iv slots for PCIE-IDE KeyRefresh.\n"));
      TEEIO_PRINT(("Close other PCIE-IDE Streams and Press any other keys to try again.\n"));
      TEEIO_PRINT(("Or press 'q' to quit the test.\n"));
      cmd = getchar();
      if(cmd == 'q' || cmd == 'Q') {
        return false;
      }
    }
  }

  bool result = ide_km_key_prog(doe_context, spdm_context, session_id,
                                ks, PCIE_IDE_STREAM_RX, PCIE_IDE_SUB_STREAM_PR,
                                port_index, stream_id, kcbar_addr, k_set, rp_stream_index);
  if(!result) {
    return false;
  }

  result = ide_km_key_prog(doe_context, spdm_context, session_id,
                            ks, PCIE_IDE_STREAM_RX, PCIE_IDE_SUB_STREAM_NPR,
                            port_index, stream_id, kcbar_addr, k_set, rp_stream_index);
  if(!result) {
    return false;
  }

  result = ide_km_key_prog(doe_context, spdm_context, session_id,
                            ks, PCIE_IDE_STREAM_RX, PCIE_IDE_SUB_STREAM_CPL,
                            port_index, stream_id, kcbar_addr, k_set, rp_stream_index);
  if(!result) {
    return false;
  }

  prime_rp_ide_key_set((INTEL_KEYP_ROOT_COMPLEX_KCBAR *)kcbar_addr, rp_stream_index, PCIE_IDE_STREAM_RX, ks);

  result = ide_km_key_prog(doe_context, spdm_context,session_id,
                           ks, PCIE_IDE_STREAM_TX, PCIE_IDE_SUB_STREAM_PR,
                           port_index, stream_id, kcbar_addr, k_set, rp_stream_index);
  if(!result) {
    return false;
  }

  result = ide_km_key_prog(doe_context, spdm_context, session_id,
                        ks, PCIE_IDE_STREAM_TX, PCIE_IDE_SUB_STREAM_NPR,
                        port_index, stream_id, kcbar_addr, k_set, rp_stream_index);
  if(!result) {
    return false;
  }

  result = ide_km_key_prog(doe_context, spdm_context, session_id,
                            ks, PCIE_IDE_STREAM_TX, PCIE_IDE_SUB_STREAM_CPL,
                            port_index, stream_id, kcbar_addr, k_set, rp_stream_index);
  if(!result) {
    return false;
  }

  prime_rp_ide_key_set((INTEL_KEYP_ROOT_COMPLEX_KCBAR *)kcbar_addr, rp_stream_index, PCIE_IDE_STREAM_TX, ks);

  pcie_ide_dump_key_switch_state("[2] after KEY_PROG + prime, before KSetGo", kcbar_addr, rp_stream_index, ide_type, upper_port, lower_port, false);

  if(skip_ksetgo) {
    return true;
  }

  // Now KSetGo
  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|RX|PR\n", k_set_names[ks]));
  libspdm_return_t status = ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_PR, port_index);
  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "KSetGo %s|RX|PR failed with 0x%x\n", k_set_names[ks], status));
    return false;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|RX|NPR\n", k_set_names[ks]));
  status = ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_NPR, port_index);

  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "KSetGo %s|RX|NPR failed with 0x%x\n", k_set_names[ks], status));
    return false;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|RX|CPL\n", k_set_names[ks]));
  status = ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_RX | PCI_IDE_KM_KEY_SUB_STREAM_CPL, port_index);

  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "KSetGo %s|RX|CPL failed with 0x%x\n", k_set_names[ks], status));
    return false;
  }

  // RP TX has not toggled K yet, so an EP error here means EP RX dropped the old key set early.
  pcie_ide_dump_key_switch_state("[3] after dev RX KSetGo x3, before RP key_set_select", kcbar_addr, rp_stream_index, ide_type, upper_port, lower_port, true);

  // set key_set_select in host ide
  INTEL_KEYP_ROOT_COMPLEX_KCBAR *kcbar = (INTEL_KEYP_ROOT_COMPLEX_KCBAR *)kcbar_addr;
  set_rp_ide_key_set_select(kcbar, rp_stream_index, ks);

  pcie_ide_dump_key_switch_state("[4] right after RP key_set_select", kcbar_addr, rp_stream_index, ide_type, upper_port, lower_port, true);

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|TX|PR\n", k_set_names[ks]));
  status = ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_PR, port_index);
  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "KSetGo %s|TX|PR failed with 0x%x\n", k_set_names[ks], status));
    return false;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|TX|NPR\n", k_set_names[ks]));
  status = ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_NPR, port_index);

  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "KSetGo %s|TX|NPR failed with 0x%x\n", k_set_names[ks], status));
    return false;
  }

  TEEIO_DEBUG((TEEIO_DEBUG_INFO, "KSetGo %s|TX|CPL\n", k_set_names[ks]));
  status = ide_km_key_set_go(doe_context, spdm_context, session_id, stream_id,
                             ks | PCI_IDE_KM_KEY_DIRECTION_TX | PCI_IDE_KM_KEY_SUB_STREAM_CPL, port_index);

  if (LIBSPDM_STATUS_IS_ERROR(status))
  {
    TEEIO_DEBUG((TEEIO_DEBUG_ERROR, "KSetGo %s|TX|CPL failed with 0x%x\n", k_set_names[ks], status));
    return false;
  }

  pcie_ide_dump_key_switch_state("[5] after dev TX KSetGo x3", kcbar_addr, rp_stream_index, ide_type, upper_port, lower_port, true);

  // wait for 10 ms for device to get ide ready
  libspdm_sleep(10 * 1000);

  // Now ide stream shall be in secure state
  bool secure = is_ide_stream_secure(ide_type,
                              upper_port_cfg_space_fd, upper_port_ecap_offset, upper_port->ide_id,
                              lower_port->cfg_space_fd, lower_port->ecap_offset, lower_port->ide_id);
  pcie_ide_dump_key_switch_state(secure ? "[6] switch complete, stream secure" : "[6] FAILURE",
                                 kcbar_addr, rp_stream_index, ide_type, upper_port, lower_port, !secure);
  return secure;
}
