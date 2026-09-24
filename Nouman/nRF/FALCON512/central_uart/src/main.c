/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/** @file
 *  @brief Nordic UART Service Client sample
 */

#include <errno.h>
#include <uart_async_adapter.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/printk.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/gatt.h>

#include <bluetooth/services/nus.h>
#include <bluetooth/services/nus_client.h>
#include <bluetooth/gatt_dm.h>
#include <bluetooth/scan.h>

#include <zephyr/settings/settings.h>

#include <zephyr/drivers/uart.h>

#include <zephyr/logging/log.h>

#include "leds.h"

#define LOG_MODULE_NAME central_uart
LOG_MODULE_REGISTER(LOG_MODULE_NAME);

/* UART payload buffer element size. */
#define UART_BUF_SIZE 20

#define VERIFY_GPIO 25
static const struct device *gpio0 = DEVICE_DT_GET(DT_NODELABEL(gpio0));

#define KEY_PASSKEY_ACCEPT DK_BTN1_MSK
#define KEY_PASSKEY_REJECT DK_BTN2_MSK

#define NUS_WRITE_TIMEOUT K_MSEC(150)
#define UART_WAIT_FOR_BUF_DELAY K_MSEC(50)
#define UART_RX_TIMEOUT 50000

#if DT_HAS_CHOSEN(nordic_nus_uart)
#define NUS_UART_NODE DT_CHOSEN(nordic_nus_uart)
#elif DT_HAS_CHOSEN(zephyr_shell_uart)
#define NUS_UART_NODE DT_CHOSEN(zephyr_shell_uart)
#else
#error "No NUS UART: add chosen 'nordic,nus-uart' to devicetree (e.g. in a board overlay)."
#endif

#include "api.h"


static const struct device *uart = DEVICE_DT_GET(NUS_UART_NODE);

static struct k_work_delayable uart_work;
static struct k_work scan_work;

/*
 * Delayable work used for SIG_ACK.
 *
 * If the NUS client is busy with the previous write,
 * SIG_ACK will be retried.
 */
static struct k_work_delayable sig_ack_work;

/*
 * Delayable work used for MSG_ACK.
 *
 * If the NUS client is busy with the previous write,
 * MSG_ACK will be retried.
 */
static struct k_work_delayable msg_ack_work;
static struct k_work_delayable start_work;
#ifdef CONFIG_UART_ASYNC_ADAPTER
UART_ASYNC_ADAPTER_INST_DEFINE(async_adapter);
#else
#define async_adapter NULL
#endif

K_SEM_DEFINE(nus_write_sem, 0, 1);


/* =========================================================
 * ML-DSA DATA
 * =========================================================
 */

#define FALCON512_PUBLIC_KEY_SIZE PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES

static uint8_t public_key[FALCON512_PUBLIC_KEY_SIZE];
static uint16_t public_key_received = 0;
static bool public_key_complete = false;


/*
 * Signature buffer, sized to the algorithm's maximum signature
 * size (PQClean's CRYPTO_BYTES). Falcon-512 signatures are
 * variable-length, so the ACTUAL length used below is not a
 * fixed constant - it is received from the peripheral (as a
 * 2-byte value, sent right before the public key) and stored
 * in expected_signature_len.
 */
static uint8_t signature[PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES];
static uint16_t signature_received = 0;
static bool signature_complete = false;

/*
 * Signature-length reception state.
 *
 * The peripheral sends this untimed, right before starting the
 * public-key transfer, as a single 2-byte (uint16_t, native/
 * little-endian) BLE NUS notification.
 */
static uint8_t sig_len_buf[sizeof(uint16_t)];
static uint16_t sig_len_bytes_received = 0;
static bool sig_len_complete = false;
static uint16_t expected_signature_len = 0;


/*
 * Message sent by the peripheral.
 *
 * "hello from board_a" = 18 bytes
 */
#define FALCON512_MESSAGE_SIZE 18

static uint8_t message[FALCON512_MESSAGE_SIZE];
static uint16_t message_received = 0;
static bool message_complete = false;


/* =========================================================
 * PQC WORK QUEUE
 *
 * PQClean's clean 
 *  implementation stack-allocates
 * large polyvec/NTT buffers. Running crypto_sign_verify()
 * directly inside ble_data_received() overflows the BT RX
 * thread's stack (CONFIG_BT_RX_STACK_SIZE is only ~1.5-2KB).
 * Offload it to a dedicated workqueue with a large stack,
 * same fix pattern used for keygen/sign on the peripheral.
 * =========================================================
 */

#define PQC_WQ_STACK_SIZE 40960  /* 40KB, tune down once stable */
#define PQC_WQ_PRIORITY   K_PRIO_COOP(7)

K_THREAD_STACK_DEFINE(pqc_wq_stack, PQC_WQ_STACK_SIZE);
static struct k_work_q pqc_wq;

static struct k_work verify_work;


/* =========================================================
 * UART DATA
 * =========================================================
 */

struct uart_data_t {
	void *fifo_reserved;
	uint8_t data[UART_BUF_SIZE];
	uint16_t len;
};

static K_FIFO_DEFINE(fifo_uart_tx_data);
static K_FIFO_DEFINE(fifo_uart_rx_data);

static struct bt_conn *default_conn;
static struct bt_nus_client nus_client;


/* =========================================================
 * BLE DATA SENT CALLBACK
 * =========================================================
 */

static void ble_data_sent(struct bt_nus_client *nus,
			  uint8_t err,
			  const uint8_t *const data,
			  uint16_t len)
{
	ARG_UNUSED(nus);
	ARG_UNUSED(data);
	ARG_UNUSED(len);

	leds_indicate_ble_traffic();

	/*
	 * The NUS client clears its internal pending-write
	 * state before calling this callback.
	 */
	k_sem_give(&nus_write_sem);

	if (err) {
		LOG_WRN("ATT error code: 0x%02X", err);
	}
}


/* =========================================================
 * SIG_ACK WORK HANDLER
 * =========================================================
 */

static void sig_ack_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	static const uint8_t sig_ack[] = "SIG_ACK";

	//LOG_INF("Trying to send SIG_ACK...");

	int err = bt_nus_client_send(&nus_client,
				     sig_ack,
				     sizeof(sig_ack) - 1);

	if (err == 0) {

		LOG_INF("SIG_ACK sent to peripheral");
		return;
	}

	/*
	 * -EALREADY means the previous NUS write
	 * is still pending.
	 */
	if (err == -EALREADY) {

		//LOG_INF("NUS TX busy, retrying SIG_ACK...");

		k_work_reschedule(&sig_ack_work,
				  K_MSEC(20));

		return;
	}

	LOG_ERR("Failed to send SIG_ACK: %d", err);
}


/* =========================================================
 * MSG_ACK WORK HANDLER
 * =========================================================
 */

static void msg_ack_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	static const uint8_t msg_ack[] = "MSG_ACK";

	//LOG_INF("Trying to send MSG_ACK...");

	int err = bt_nus_client_send(&nus_client,
				     msg_ack,
				     sizeof(msg_ack) - 1);

	if (err == 0) {

		LOG_INF("MSG_ACK sent to peripheral");

		/*
		 * Only now that the ACK is actually on the wire,
		 * run verification.
		 */
		k_work_submit_to_queue(&pqc_wq, &verify_work);

		return;
	}

	/*
	 * -EALREADY means the previous NUS write
	 * is still pending.
	 */
	if (err == -EALREADY) {

		//LOG_INF("NUS TX busy, retrying MSG_ACK...");

		k_work_reschedule(&msg_ack_work,
				  K_MSEC(20));

		return;
	}

	LOG_ERR("Failed to send MSG_ACK: %d", err);
}

static void start_work_handler(struct k_work *work)
{
    ARG_UNUSED(work);

    static const uint8_t start_msg[] = "START";

    int err = bt_nus_client_send(&nus_client,
                                 start_msg,
                                 sizeof(start_msg) - 1);

    if (err == 0) {
        LOG_INF("START sent to peripheral");
        return;
    }

    if (err == -EALREADY) {
      //  LOG_INF("NUS TX busy, retrying START...");
        k_work_reschedule(&start_work, K_MSEC(20));
        return;
    }

    LOG_ERR("Failed to send START: %d", err);
}
/* =========================================================
 * VERIFY WORK HANDLER (runs on pqc_wq, NOT on BT RX thread)
 * =========================================================
 */

static void verify_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	int64_t verify_start_time = k_uptime_get();
gpio_pin_set(gpio0, VERIFY_GPIO, 1);
	int verify_ret = PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
		signature,
		signature_received,
		message,
		message_received,
		public_key
	);
gpio_pin_set(gpio0, VERIFY_GPIO, 0);
	int64_t verify_end_time = k_uptime_get();

	if (verify_ret == 0) {
		LOG_INF("SIGNATURE VERIFICATION SUCCESS");
	} else {
		LOG_ERR("SIGNATURE VERIFICATION FAILED");
	}

	LOG_INF("Verification time: %lld ms",
		verify_end_time - verify_start_time);

	LOG_INF("====================================");

	sig_len_bytes_received = 0;
    sig_len_complete = false;
    expected_signature_len = 0;

    public_key_received = 0;
    public_key_complete = false;

    signature_received = 0;
    signature_complete = false;

    message_received = 0;
    message_complete = false;

 //   LOG_INF("PQC state reset");

    k_work_reschedule(&start_work, K_MSEC(20));

}




/* =========================================================
 * BLE DATA RECEIVED CALLBACK
 * =========================================================
 */

static uint8_t ble_data_received(struct bt_nus_client *nus,
				 const uint8_t *data,
				 uint16_t len)
{
	ARG_UNUSED(nus);


	/*
	 * =====================================================
	 * STEP 0: RECEIVE SIGNATURE LENGTH
	 *
	 * Sent by the peripheral as a single untimed 2-byte
	 * notification, before it starts the public-key
	 * transfer. Used below (instead of a fixed size) to
	 * know how many bytes make up the signature.
	 * =====================================================
	 */

	if (!sig_len_complete) {

		if (sig_len_bytes_received + len <=
		    sizeof(sig_len_buf)) {

			memcpy(&sig_len_buf[sig_len_bytes_received],
			       data,
			       len);

			sig_len_bytes_received += len;

			if (sig_len_bytes_received ==
			    sizeof(sig_len_buf)) {

				sig_len_complete = true;

				memcpy(&expected_signature_len,
				       sig_len_buf,
				       sizeof(expected_signature_len));

				LOG_INF(
					"Signature length received: %u bytes",
					expected_signature_len);

				if (expected_signature_len >
				    sizeof(signature)) {

					LOG_ERR(
						"Signature length %u exceeds "
						"buffer size %u",
						expected_signature_len,
						(unsigned)sizeof(signature));
				}
			}

		} else {

			LOG_ERR("Signature length buffer overflow");
		}

		return BT_GATT_ITER_CONTINUE;
	}


	/*
	 * =====================================================
	 * STEP 1: RECEIVE PUBLIC KEY
	 * =====================================================
	 */

	if (!public_key_complete) {

		if (public_key_received + len <=
		    FALCON512_PUBLIC_KEY_SIZE) {

			memcpy(&public_key[public_key_received],
			       data,
			       len);

			public_key_received += len;

		//	LOG_INF("Public key received: %u / %u bytes",public_key_received,FALCON512_PUBLIC_KEY_SIZE);

			/*
			 * Public key completely received.
			 */
			if (public_key_received ==
			    FALCON512_PUBLIC_KEY_SIZE) {

				public_key_complete = true;

				//LOG_INF("================================");
				LOG_INF("PUBLIC KEY RECEIVED");
			//	LOG_INF("Total public key size: %u bytes",public_key_received);
			//	LOG_INF("================================");

				/*
				 * Send PK_ACK.
				 */
				static const uint8_t pk_ack[] = "PK_ACK";

				int err =
					bt_nus_client_send(
						&nus_client,
						pk_ack,
						sizeof(pk_ack) - 1);

				if (err) {

					LOG_ERR(
						"Failed to send PK_ACK: %d",
						err);

				} else {

					LOG_INF(
						"PK_ACK sent to peripheral");
				}
			}

		} else {

			LOG_ERR("Public key buffer overflow");
		}

		return BT_GATT_ITER_CONTINUE;
	}


	/*
	 * =====================================================
	 * STEP 2: RECEIVE SIGNATURE (variable length, driven by
	 * expected_signature_len received in STEP 0)
	 * =====================================================
	 */

	if (!signature_complete) {

		if (signature_received + len <=
		    expected_signature_len) {

			memcpy(&signature[signature_received],
			       data,
			       len);

			signature_received += len;

			LOG_INF("Signature received: %u / %u bytes",signature_received,	expected_signature_len);

			/*
			 * Signature completely received.
			 */
			if (signature_received ==
			    expected_signature_len) {

				signature_complete = true;

			//	LOG_INF("================================");
				LOG_INF("SIGNATURE RECEIVED");
			//	LOG_INF("Total signature size: %u bytes",signature_received);
			//	LOG_INF("================================");

				/*
				 * Send SIG_ACK.
				 */
				k_work_reschedule(&sig_ack_work,
						  K_NO_WAIT);


			}

		} else {

			LOG_ERR("Signature buffer overflow");
		}

		return BT_GATT_ITER_CONTINUE;
	}


	/*
	 * =====================================================
	 * STEP 3: RECEIVE MESSAGE
	 * =====================================================
	 */

	if (!message_complete) {

		if (message_received + len <=
		    FALCON512_MESSAGE_SIZE) {

			memcpy(&message[message_received],
			       data,
			       len);

			message_received += len;

			//LOG_INF("Message received: %u / %u bytes",message_received,FALCON512_MESSAGE_SIZE);

			/*
			 * Message completely received.
			 */
			if (message_received ==
			    FALCON512_MESSAGE_SIZE) {

				message_complete = true;

			//	LOG_INF("================================");
				LOG_INF("MESSAGE RECEIVED");
			//	LOG_INF("Total message size: %u bytes",	message_received);

				LOG_INF("Message: %.*s",
					message_received,
					message);

			//	LOG_INF("================================");

				/*
				 * Send MSG_ACK. Verification is triggered
				 * from msg_ack_work_handler() once the ACK
				 * has actually been sent, so the log order
				 * is: MESSAGE RECEIVED -> MSG_ACK sent ->
				 * verification result.
				 */
				k_work_reschedule(&msg_ack_work,
						  K_NO_WAIT);
			}

		} else {

			LOG_ERR("Message buffer overflow");
		}

		return BT_GATT_ITER_CONTINUE;
	}


	return BT_GATT_ITER_CONTINUE;
}


/* =========================================================
 * UART CALLBACK
 * =========================================================
 */

static void uart_cb(const struct device *dev,
		    struct uart_event *evt,
		    void *user_data)
{
	ARG_UNUSED(dev);

	static size_t aborted_len;
	struct uart_data_t *buf;
	static uint8_t *aborted_buf;
	static bool disable_req;

	switch (evt->type) {

	case UART_TX_DONE:

		LOG_DBG("UART_TX_DONE");

		if ((evt->data.tx.len == 0) ||
		    (!evt->data.tx.buf)) {
			return;
		}

		if (aborted_buf) {

			buf = CONTAINER_OF(aborted_buf,
					   struct uart_data_t,
					   data[0]);

			aborted_buf = NULL;
			aborted_len = 0;

		} else {

			buf = CONTAINER_OF(evt->data.tx.buf,
					   struct uart_data_t,
					   data[0]);
		}

		k_free(buf);

		buf = k_fifo_get(&fifo_uart_tx_data,
				 K_NO_WAIT);

		if (!buf) {
			return;
		}

		if (uart_tx(uart,
			    buf->data,
			    buf->len,
			    SYS_FOREVER_MS)) {

			LOG_WRN("Failed to send data over UART");
		}

		break;


	case UART_RX_RDY:

		LOG_DBG("UART_RX_RDY");

		buf = CONTAINER_OF(evt->data.rx.buf,
				   struct uart_data_t,
				   data[0]);

		buf->len += evt->data.rx.len;

		if (disable_req) {
			return;
		}

		if ((evt->data.rx.buf[buf->len - 1] == '\n') ||
		    (evt->data.rx.buf[buf->len - 1] == '\r')) {

			disable_req = true;

			uart_rx_disable(uart);
		}

		break;


	case UART_RX_DISABLED:

		LOG_DBG("UART_RX_DISABLED");

		disable_req = false;

		buf = k_malloc(sizeof(*buf));

		if (buf) {

			buf->len = 0;

		} else {

			LOG_WRN(
				"Not able to allocate UART receive buffer");

			k_work_reschedule(&uart_work,
					  UART_WAIT_FOR_BUF_DELAY);

			return;
		}

		uart_rx_enable(uart,
			       buf->data,
			       sizeof(buf->data),
			       UART_RX_TIMEOUT);

		break;


	case UART_RX_BUF_REQUEST:

		LOG_DBG("UART_RX_BUF_REQUEST");

		buf = k_malloc(sizeof(*buf));

		if (buf) {

			buf->len = 0;

			uart_rx_buf_rsp(uart,
					buf->data,
					sizeof(buf->data));

		} else {

			LOG_WRN(
				"Not able to allocate UART receive buffer");
		}

		break;


	case UART_RX_BUF_RELEASED:

		LOG_DBG("UART_RX_BUF_RELEASED");

		buf = CONTAINER_OF(evt->data.rx_buf.buf,
				   struct uart_data_t,
				   data[0]);

		if (buf->len > 0) {

			k_fifo_put(&fifo_uart_rx_data,
				   buf);

		} else {

			k_free(buf);
		}

		break;


	case UART_TX_ABORTED:

		LOG_DBG("UART_TX_ABORTED");

		if (!aborted_buf) {
			aborted_buf =
				(uint8_t *)evt->data.tx.buf;
		}

		aborted_len += evt->data.tx.len;

		buf = CONTAINER_OF(aborted_buf,
				   struct uart_data_t,
				   data[0]);

		uart_tx(uart,
			&buf->data[aborted_len],
			buf->len - aborted_len,
			SYS_FOREVER_MS);

		break;


	default:
		break;
	}
}


/* =========================================================
 * UART WORK HANDLER
 * =========================================================
 */

static void uart_work_handler(struct k_work *item)
{
	struct uart_data_t *buf;

	buf = k_malloc(sizeof(*buf));

	if (buf) {

		buf->len = 0;

	} else {

		LOG_WRN(
			"Not able to allocate UART receive buffer");

		k_work_reschedule(&uart_work,
				  UART_WAIT_FOR_BUF_DELAY);

		return;
	}

	uart_rx_enable(uart,
		       buf->data,
		       sizeof(buf->data),
		       UART_RX_TIMEOUT);
}


/* =========================================================
 * UART INIT
 * =========================================================
 */

static int uart_init(void)
{
	int err;
	struct uart_data_t *rx;

	if (!device_is_ready(uart)) {

		LOG_ERR("UART device not ready");

		return -ENODEV;
	}

	rx = k_malloc(sizeof(*rx));

	if (rx) {

		rx->len = 0;

	} else {

		return -ENOMEM;
	}

	k_work_init_delayable(&uart_work,
			      uart_work_handler);

	if (IS_ENABLED(CONFIG_UART_ASYNC_ADAPTER)) {

		uart_async_adapter_init(async_adapter,
					uart);

		uart = async_adapter;
	}

	err = uart_callback_set(uart,
				uart_cb,
				NULL);

	if (err) {
		return err;
	}

	return uart_rx_enable(uart,
			      rx->data,
			      sizeof(rx->data),
			      UART_RX_TIMEOUT);
}


/* =========================================================
 * DISCOVERY COMPLETE
 * =========================================================
 */

static void discovery_complete(struct bt_gatt_dm *dm,
			       void *context)
{
	struct bt_nus_client *nus = context;

	LOG_INF("Service discovery completed");

	bt_gatt_dm_data_print(dm);

	bt_nus_handles_assign(dm, nus);

	bt_nus_subscribe_receive(nus);

	bt_gatt_dm_data_release(dm);

	/*
	 * Tell peripheral we are fully ready.
	 */
	static const uint8_t start_msg[] = "START";

	int err = bt_nus_client_send(&nus_client,
				    start_msg,
				    sizeof(start_msg) - 1);

	if (err) {

		LOG_ERR("Failed to send START: %d",
			err);

	} else {

		LOG_INF("START sent to peripheral");
	}
}


/* =========================================================
 * DISCOVERY CALLBACKS
 * =========================================================
 */

static void discovery_service_not_found(struct bt_conn *conn,
					void *context)
{
	LOG_INF("Service not found");
}


static void discovery_error(struct bt_conn *conn,
			    int err,
			    void *context)
{
	LOG_WRN("Error while discovering GATT database: (%d)",
		err);
}


struct bt_gatt_dm_cb discovery_cb = {
	.completed         = discovery_complete,
	.service_not_found = discovery_service_not_found,
	.error_found       = discovery_error,
};


/* =========================================================
 * GATT DISCOVER
 * =========================================================
 */

static void gatt_discover(struct bt_conn *conn)
{
	int err;

	if (conn != default_conn) {
		return;
	}

	err = bt_gatt_dm_start(conn,
			       BT_UUID_NUS_SERVICE,
			       &discovery_cb,
			       &nus_client);

	if (err) {

		LOG_ERR(
			"could not start the discovery procedure, "
			"error code: %d",
			err);
	}
}


/* =========================================================
 * MTU EXCHANGE
 * =========================================================
 */

static void exchange_func(struct bt_conn *conn,
			  uint8_t err,
			  struct bt_gatt_exchange_params *params)
{
	if (!err) {

		LOG_INF("MTU exchange done");

	} else {

		LOG_WRN("MTU exchange failed (err %" PRIu8 ")",
			err);
	}
}


/* =========================================================
 * CONNECTED
 * =========================================================
 */

static void connected(struct bt_conn *conn,
		      uint8_t conn_err)
{
	char addr[BT_ADDR_LE_STR_LEN];
	int err;

	bt_addr_le_to_str(bt_conn_get_dst(conn),
			  addr,
			  sizeof(addr));

	if (conn_err) {

		LOG_INF("Failed to connect to %s, 0x%02x %s",
			addr,
			conn_err,
			bt_hci_err_to_str(conn_err));

		if (default_conn == conn) {

			bt_conn_unref(default_conn);

			default_conn = NULL;

			(void)k_work_submit(&scan_work);
		}

		return;
	}

	LOG_INF("Connected: %s", addr);

	leds_set_ble_connected(true);

	static struct bt_gatt_exchange_params exchange_params;

	exchange_params.func = exchange_func;

	err = bt_gatt_exchange_mtu(conn,
				   &exchange_params);

	if (err) {

		LOG_WRN("MTU exchange failed (err %d)",
			err);
	}

	err = bt_conn_set_security(conn,
				   BT_SECURITY_L2);

	if (err) {

		LOG_WRN("Failed to set security: %d",
			err);

		gatt_discover(conn);
	}

	err = bt_scan_stop();

	if (err) {

		LOG_ERR("Stop LE scan failed (err %d)",
			err);
	}
}


/* =========================================================
 * DISCONNECTED
 * =========================================================
 */

static void disconnected(struct bt_conn *conn,
			 uint8_t reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn),
			  addr,
			  sizeof(addr));

	LOG_INF("Disconnected: %s, reason 0x%02x %s",
		addr,
		reason,
		bt_hci_err_to_str(reason));

	if (default_conn != conn) {
		return;
	}

	leds_set_ble_connected(false);

	bt_conn_unref(default_conn);

	default_conn = NULL;

	(void)k_work_submit(&scan_work);
}


/* =========================================================
 * SECURITY CHANGED
 * =========================================================
 */

static void security_changed(struct bt_conn *conn,
			     bt_security_t level,
			     enum bt_security_err err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn),
			  addr,
			  sizeof(addr));

	if (!err) {

		LOG_INF("Security changed: %s level %u",
			addr,
			level);

	} else {

		LOG_WRN("Security failed: %s level %u err %d %s",
			addr,
			level,
			err,
			bt_security_err_to_str(err));
	}

	gatt_discover(conn);
}


/* =========================================================
 * CONNECTION CALLBACKS
 * =========================================================
 */

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected = connected,
	.disconnected = disconnected,
	.security_changed = security_changed
};


/* =========================================================
 * SCAN CALLBACKS
 * =========================================================
 */

static void scan_filter_match(
	struct bt_scan_device_info *device_info,
	struct bt_scan_filter_match *filter_match,
	bool connectable)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(device_info->recv_info->addr,
			  addr,
			  sizeof(addr));

	LOG_INF("Filters matched. Address: %s connectable: %d",
		addr,
		connectable);
}


static void scan_connecting_error(
	struct bt_scan_device_info *device_info)
{
	LOG_WRN("Connecting failed");
}


static void scan_connecting(
	struct bt_scan_device_info *device_info,
	struct bt_conn *conn)
{
	default_conn = bt_conn_ref(conn);
}


/* =========================================================
 * NUS CLIENT INIT
 * =========================================================
 */

static int nus_client_init(void)
{
	int err;

	struct bt_nus_client_init_param init = {
		.cb = {
			.received = ble_data_received,
			.sent = ble_data_sent,
		}
	};

	err = bt_nus_client_init(&nus_client,
				 &init);

	if (err) {

		LOG_ERR(
			"NUS Client initialization failed (err %d)",
			err);

		return err;
	}

	LOG_INF("NUS Client module initialized");

	return err;
}


/* =========================================================
 * SCAN
 * =========================================================
 */

BT_SCAN_CB_INIT(scan_cb,
		scan_filter_match,
		NULL,
		scan_connecting_error,
		scan_connecting);


static void try_add_address_filter(
	const struct bt_bond_info *info,
	void *user_data)
{
	int err;
	char addr[BT_ADDR_LE_STR_LEN];
	uint8_t *filter_mode = user_data;

	bt_addr_le_to_str(&info->addr,
			  addr,
			  sizeof(addr));

	struct bt_conn *conn =
		bt_conn_lookup_addr_le(BT_ID_DEFAULT,
				       &info->addr);

	if (conn) {

		bt_conn_unref(conn);

		return;
	}

	err = bt_scan_filter_add(BT_SCAN_FILTER_TYPE_ADDR,
				 &info->addr);

	if (err) {

		LOG_ERR(
			"Address filter cannot be added "
			"(err %d): %s",
			err,
			addr);

		return;
	}

	LOG_INF("Address filter added: %s",
		addr);

	*filter_mode |= BT_SCAN_ADDR_FILTER;
}


static int scan_start(void)
{
	int err;
	uint8_t filter_mode = 0;

	err = bt_scan_stop();

	if (err) {

		LOG_ERR("Failed to stop scanning (err %d)",
			err);

		return err;
	}

	bt_scan_filter_remove_all();

	err = bt_scan_filter_add(BT_SCAN_FILTER_TYPE_UUID,
				 BT_UUID_NUS_SERVICE);

	if (err) {

		LOG_ERR(
			"UUID filter cannot be added (err %d",
			err);

		return err;
	}

	filter_mode |= BT_SCAN_UUID_FILTER;

	bt_foreach_bond(BT_ID_DEFAULT,
			try_add_address_filter,
			&filter_mode);

	err = bt_scan_filter_enable(filter_mode,
				    false);

	if (err) {

		LOG_ERR(
			"Filters cannot be turned on (err %d)",
			err);

		return err;
	}

	err = bt_scan_start(BT_SCAN_TYPE_SCAN_ACTIVE);

	if (err) {

		LOG_ERR(
			"Scanning failed to start (err %d)",
			err);

		return err;
	}

	LOG_INF("Scan started");

	return 0;
}


static void scan_work_handler(struct k_work *item)
{
	ARG_UNUSED(item);

	(void)scan_start();
}


static void scan_init(void)
{
	struct bt_scan_init_param scan_init = {
		.connect_if_match = true,
	};

	bt_scan_init(&scan_init);

	bt_scan_cb_register(&scan_cb);

	k_work_init(&scan_work,
		    scan_work_handler);

	LOG_INF("Scan module initialized");
}


/* =========================================================
 * AUTHENTICATION
 * =========================================================
 */

static void auth_cancel(struct bt_conn *conn)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn),
			  addr,
			  sizeof(addr));

	LOG_INF("Pairing cancelled: %s",
		addr);
}


static void pairing_complete(struct bt_conn *conn,
			     bool bonded)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn),
			  addr,
			  sizeof(addr));

	LOG_INF("Pairing completed: %s, bonded: %d",
		addr,
		bonded);
}


static void pairing_failed(struct bt_conn *conn,
			   enum bt_security_err reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn),
			  addr,
			  sizeof(addr));

	LOG_WRN("Pairing failed conn: %s, reason %d %s",
		addr,
		reason,
		bt_security_err_to_str(reason));
}


static struct bt_conn_auth_cb conn_auth_callbacks = {
	.cancel = auth_cancel,
};


static struct bt_conn_auth_info_cb conn_auth_info_callbacks = {
	.pairing_complete = pairing_complete,
	.pairing_failed = pairing_failed
};


/* =========================================================
 * MAIN
 * =========================================================
 */

int main(void)
{
	int err;

	leds_init();
if (!device_is_ready(gpio0)) {
    LOG_ERR("GPIO0 device not ready");
    return 0;
}

gpio_pin_configure(gpio0, VERIFY_GPIO, GPIO_OUTPUT_INACTIVE);
	err = bt_conn_auth_cb_register(
		&conn_auth_callbacks);

	if (err) {

		LOG_ERR(
			"Failed to register authorization callbacks.");

		return 0;
	}

	err = bt_conn_auth_info_cb_register(
		&conn_auth_info_callbacks);

	if (err) {

		printk(
			"Failed to register authorization "
			"info callbacks.\n");

		return 0;
	}

	err = bt_enable(NULL);

	if (err) {

		LOG_ERR(
			"Bluetooth init failed (err %d)",
			err);

		return 0;
	}

	LOG_INF("Bluetooth initialized");

	if (IS_ENABLED(CONFIG_SETTINGS)) {
		settings_load();
	}

	err = uart_init();

	if (err != 0) {

		LOG_ERR("uart_init failed (err %d)",
			err);

		return 0;
	}

	err = nus_client_init();

	if (err != 0) {

		LOG_ERR("nus_client_init failed (err %d)",
			err);

		return 0;
	}

	/*
	 * Initialize SIG_ACK work.
	 */
	k_work_init_delayable(&sig_ack_work,
			      sig_ack_work_handler);

	/*
	 * Initialize MSG_ACK work.
	 */
	k_work_init_delayable(&msg_ack_work,
			      msg_ack_work_handler);
k_work_init_delayable(&start_work, start_work_handler);
	/*
	 * Initialize the dedicated PQC workqueue (large stack)
	 * and the verify work item that runs on it. Doing this
	 * once here, rather than in ble_data_received(), avoids
	 * re-initializing a work item that could still be pending.
	 */
	k_work_queue_init(&pqc_wq);

	k_work_queue_start(&pqc_wq,
			   pqc_wq_stack,
			   K_THREAD_STACK_SIZEOF(pqc_wq_stack),
			   PQC_WQ_PRIORITY,
			   NULL);

	k_work_init(&verify_work,
		    verify_work_handler);

	scan_init();

	err = scan_start();

	if (err) {
		return 0;
	}

	printk("Starting Bluetooth Central UART sample\n");

	struct uart_data_t nus_data = {
		.len = 0,
	};

	for (;;) {

		/*
		 * Wait indefinitely for data to be sent
		 * over Bluetooth.
		 */

		struct uart_data_t *buf =
			k_fifo_get(&fifo_uart_rx_data,
				   K_FOREVER);

		int plen =
			MIN(sizeof(nus_data.data) -
			    nus_data.len,
			    buf->len);

		int loc = 0;

		while (plen > 0) {

			memcpy(&nus_data.data[nus_data.len],
			       &buf->data[loc],
			       plen);

			nus_data.len += plen;
			loc += plen;

			if (nus_data.len >=
			    sizeof(nus_data.data) ||
			    (nus_data.data[nus_data.len - 1] == '\n') ||
			    (nus_data.data[nus_data.len - 1] == '\r')) {

				err = bt_nus_client_send(
					&nus_client,
					nus_data.data,
					nus_data.len);

				if (err) {

					LOG_WRN(
						"Failed to send data over BLE "
						"connection (err %d)",
						err);
				}

				err = k_sem_take(
					&nus_write_sem,
					NUS_WRITE_TIMEOUT);

				if (err) {

					LOG_WRN(
						"NUS send timeout");
				}

				nus_data.len = 0;
			}

			plen = MIN(sizeof(nus_data.data),
				    buf->len - loc);
		}

		k_free(buf);
	}
}