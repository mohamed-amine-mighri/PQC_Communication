
/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/** @file
 *  @brief Nordic UART Bridge Service (NUS) sample
 */
#include <uart_async_adapter.h>
#include "api.h"
#include <zephyr/sys/printk.h>
#include <zephyr/sys/time_units.h>
#include <zephyr/types.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/drivers/gpio.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <soc.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/hci.h>

#include <bluetooth/services/nus.h>

#include <dk_buttons_and_leds.h>
static int64_t pk_send_start_time;
#include <zephyr/settings/settings.h>

#include <stdio.h>
#include <string.h>

#include <zephyr/logging/log.h>

#define LOG_MODULE_NAME peripheral_uart
LOG_MODULE_REGISTER(LOG_MODULE_NAME);

#define STACKSIZE CONFIG_BT_NUS_THREAD_STACK_SIZE
#define PRIORITY 7

#define DEVICE_NAME CONFIG_BT_DEVICE_NAME
#define DEVICE_NAME_LEN	(sizeof(DEVICE_NAME) - 1)

#define RUN_STATUS_LED DK_LED1
#define RUN_LED_BLINK_INTERVAL 1000

#define CON_STATUS_LED DK_LED2

#define KEY_PASSKEY_ACCEPT DK_BTN1_MSK
#define KEY_PASSKEY_REJECT DK_BTN2_MSK

#define UART_BUF_SIZE CONFIG_BT_NUS_UART_BUFFER_SIZE
#define UART_WAIT_FOR_BUF_DELAY K_MSEC(50)
#define UART_WAIT_FOR_RX CONFIG_BT_NUS_UART_RX_WAIT_TIME

static K_SEM_DEFINE(ble_init_ok, 0, 1);

static struct bt_conn *current_conn;
static struct bt_conn *auth_conn;
static struct k_work adv_work;
static uint8_t SPHINCSSHA2128SSIMPLE_pk[PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
static uint8_t SPHINCSSHA2128SSIMPLE_sk[PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
static uint8_t SPHINCSSHA2128SSIMPLE_signature[PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_BYTES];
static size_t SPHINCSSHA2128SSIMPLE_signature_len;

static uint8_t SPHINCSSHA2128SSIMPLE_message[] = "hello from board_a";
static size_t SPHINCSSHA2128SSIMPLE_message_len = sizeof(SPHINCSSHA2128SSIMPLE_message) - 1;
static int64_t msg_send_start_time;
static int64_t sig_send_start_time;

/*
 * PPK2 measurement trigger pins on nRF5340 DK
 *
 * GPIO0:
 *   P0.25 = Key generation
 *   P0.26 = Signing
 *
 * GPIO1:
 *   P1.04 = Public-key send (HIGH from send start until PK_ACK)
 *   P1.05 = Signature send (HIGH from send start until SIG_ACK)
 *   P1.06 = Message send (HIGH from send start until MSG_ACK)
 *
 * Trigger is active HIGH.
 */
#define TRIGGER_KEYGEN_PIN   25
#define TRIGGER_SIGNING_PIN  26
#define TRIGGER_PK_SEND_PIN   4
#define TRIGGER_SIG_SEND_PIN  5
#define TRIGGER_MSG_SEND_PIN  6

static const struct device *gpio0_dev = DEVICE_DT_GET(DT_NODELABEL(gpio0));
static const struct device *gpio1_dev = DEVICE_DT_GET(DT_NODELABEL(gpio1));

static inline void trigger_set0(uint32_t pin, bool active)
{
    gpio_pin_set(gpio0_dev, pin, active ? 1 : 0);
}

static inline void trigger_set1(uint32_t pin, bool active)
{
    gpio_pin_set(gpio1_dev, pin, active ? 1 : 0);
}
#if DT_HAS_CHOSEN(nordic_nus_uart)
#define NUS_UART_NODE DT_CHOSEN(nordic_nus_uart)
#elif DT_HAS_CHOSEN(zephyr_shell_uart)
#define NUS_UART_NODE DT_CHOSEN(zephyr_shell_uart)
#else
#error "No NUS UART: add chosen 'nordic,nus-uart' to devicetree (e.g. in a board overlay)."
#endif
static const struct device *uart = DEVICE_DT_GET(NUS_UART_NODE);
static struct k_work_delayable uart_work;

struct uart_data_t {
	void *fifo_reserved;
	uint8_t data[UART_BUF_SIZE];
	uint16_t len;
};

static K_FIFO_DEFINE(fifo_uart_tx_data);
static K_FIFO_DEFINE(fifo_uart_rx_data);

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA(BT_DATA_NAME_COMPLETE, DEVICE_NAME, DEVICE_NAME_LEN),
};

static const struct bt_data sd[] = {
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, BT_UUID_NUS_VAL),
};

#ifdef CONFIG_UART_ASYNC_ADAPTER
UART_ASYNC_ADAPTER_INST_DEFINE(async_adapter);
#else
#define async_adapter NULL
#endif


//key generatio  function
#define MLDSA_STACK_SIZE 65536
#define MLDSA_PRIORITY 5

K_THREAD_STACK_DEFINE(mldsa_stack, MLDSA_STACK_SIZE);
static struct k_thread mldsa_thread_data;

K_SEM_DEFINE(nus_tx_sem, 0, 1);
static void nus_sent_cb(struct bt_conn *conn)
{
    ARG_UNUSED(conn);
    k_sem_give(&nus_tx_sem);
}
static int send_public_key(void)
{
    if (current_conn == NULL) {
        LOG_ERR("No BLE connection available");
        return -ENOTCONN;
    }

    /* Start PPK2 trigger: public-key transfer + wait for PK_ACK */
    trigger_set1(TRIGGER_PK_SEND_PIN, true);

    const uint8_t *data = SPHINCSSHA2128SSIMPLE_pk;
    size_t total_len = PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;

    /* With MTU 247, NUS payload is 244 bytes */
    const size_t chunk_size = 244;

    size_t offset = 0;
    int ret;

   // LOG_INF("Starting public key transmission...");
   // LOG_INF("Public key total size: %d bytes", total_len);
    pk_send_start_time = k_uptime_get();
    while (offset < total_len) {

        size_t remaining = total_len - offset;
        size_t chunk_len = MIN(remaining, chunk_size);

        ret = bt_nus_send(
            current_conn,
            &data[offset],
            chunk_len
        );

        if (ret) {
            LOG_ERR("Public key transmission failed at offset %d, ret=%d",
                    offset, ret);
            trigger_set1(TRIGGER_PK_SEND_PIN, false);
            return ret;
        }

       // LOG_INF("Public key chunk sent: offset=%d, size=%d",offset, chunk_len);

        offset += chunk_len;

        /* Small delay between notifications */
        k_sleep(K_MSEC(5));
    }

    LOG_INF("Public key transmission SUCCESS");
    //LOG_INF("Total public key bytes sent: %d", offset);

    return 0;
}


static int send_signature(void)
{
    if (current_conn == NULL) {
        LOG_ERR("No BLE connection available");
        return -ENOTCONN;
    }

    /* Start PPK2 trigger: signature transfer + wait for SIG_ACK */
    trigger_set1(TRIGGER_SIG_SEND_PIN, true);

    const uint8_t *data = SPHINCSSHA2128SSIMPLE_signature;
    size_t total_len = SPHINCSSHA2128SSIMPLE_signature_len;

    const size_t chunk_size = 244;

    size_t offset = 0;
    int ret;

  //  LOG_INF("Starting signature transmission...");
  //  LOG_INF("Signature total size: %d bytes", total_len);

    sig_send_start_time = k_uptime_get();

    while (offset < total_len) {

        size_t remaining = total_len - offset;
        size_t chunk_len = MIN(remaining, chunk_size);

        ret = bt_nus_send(
            current_conn,
            &data[offset],
            chunk_len
        );

        if (ret) {
            LOG_ERR("Signature transmission failed at offset %d, ret=%d",
                    offset, ret);
            trigger_set1(TRIGGER_SIG_SEND_PIN, false);
            return ret;
        }

        offset += chunk_len;

      //  LOG_INF("Signature chunk sent: %d / %d",            offset, total_len);

        /*
         * Wait until BLE transmission is completed
         * before sending the next chunk.
         */
        ret = k_sem_take(&nus_tx_sem, K_SECONDS(2));

        if (ret) {
            LOG_ERR("Timeout waiting for BLE TX complete");
            trigger_set1(TRIGGER_SIG_SEND_PIN, false);
            return ret;
        }
    }

    LOG_INF("Signature transmission SUCCESS");
  //  LOG_INF("Total signature bytes sent: %d", offset);

    return 0;
}


static int send_message(void)
{
    if (current_conn == NULL) {
        LOG_ERR("No BLE connection available");
        return -ENOTCONN;
    }

    /* Start PPK2 trigger: message transfer + wait for MSG_ACK */
    trigger_set1(TRIGGER_MSG_SEND_PIN, true);

    const uint8_t *data = SPHINCSSHA2128SSIMPLE_message;
    size_t total_len = SPHINCSSHA2128SSIMPLE_message_len;

    /* NUS payload size with MTU 247 */
    const size_t chunk_size = 244;

    size_t offset = 0;
    int ret;

  //  LOG_INF("Starting message transmission...");
  //  LOG_INF("Message total size: %d bytes", total_len);

    msg_send_start_time = k_uptime_get();

    while (offset < total_len) {

        size_t remaining = total_len - offset;
        size_t chunk_len = MIN(remaining, chunk_size);

        ret = bt_nus_send(
            current_conn,
            &data[offset],
            chunk_len
        );

        if (ret) {
            LOG_ERR("Message transmission failed at offset %d, ret=%d",
                    offset, ret);
            trigger_set1(TRIGGER_MSG_SEND_PIN, false);
            return ret;
        }

        offset += chunk_len;

      //  LOG_INF("Message chunk sent: %d / %d",offset, total_len);

        /*
         * Wait until BLE transmission is completed
         * before sending the next chunk.
         */
        ret = k_sem_take(&nus_tx_sem, K_SECONDS(2));

        if (ret) {
            LOG_ERR("Timeout waiting for BLE TX complete");
            trigger_set1(TRIGGER_MSG_SEND_PIN, false);
            return ret;
        }
    }

    LOG_INF("Message transmission SUCCESS");
 //   LOG_INF("Total message bytes sent: %d", offset);

    return 0;
}


static void SPHINCSSHA2128SSIMPLE_keygen_thread(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1);
    ARG_UNUSED(p2);
    ARG_UNUSED(p3);

  //  LOG_INF("Starting key generation...");

    int64_t start_time = k_uptime_get();

    /* PPK2 trigger HIGH only during ML-DSA-44 key generation */
    trigger_set0(TRIGGER_KEYGEN_PIN, true);

    int ret = PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair(
        SPHINCSSHA2128SSIMPLE_pk,
        SPHINCSSHA2128SSIMPLE_sk
    );

    int64_t end_time = k_uptime_get();

    /* End key-generation measurement window */
    trigger_set0(TRIGGER_KEYGEN_PIN, false);

    if (ret != 0) {
        LOG_ERR("key generation FAILED, ret=%d", ret);
        return;
    }

    LOG_INF("key generation SUCCESS");
    LOG_INF("Key generation time: %lld ms",
            end_time - start_time);

  //  LOG_INF("Public key size: %d bytes", PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

 //   LOG_INF("Secret key size: %d bytes", PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);


	/* Message to sign */
//	LOG_INF("Message: %s", SPHINCSSHA2128SSIMPLE_message);
//	LOG_INF("Message length: %d bytes", SPHINCSSHA2128SSIMPLE_message_len);

	//LOG_INF("Starting signing...");
	start_time = k_uptime_get();

    /* PPK2 trigger HIGH only during ML-DSA-44 signing */
    trigger_set0(TRIGGER_SIGNING_PIN, true);

	ret = PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature(
		SPHINCSSHA2128SSIMPLE_signature,
		&SPHINCSSHA2128SSIMPLE_signature_len,
		SPHINCSSHA2128SSIMPLE_message,
		SPHINCSSHA2128SSIMPLE_message_len,
		SPHINCSSHA2128SSIMPLE_sk
	);
    end_time = k_uptime_get();

    /* End signing measurement window */
    trigger_set0(TRIGGER_SIGNING_PIN, false);

    if (ret == 0) {
        LOG_INF("signing SUCCESS");
        LOG_INF("Signing time: %lld ms",
                end_time - start_time);
        LOG_INF("Signature size: %d bytes", SPHINCSSHA2128SSIMPLE_signature_len);
    } else {
        LOG_ERR("signing FAILED, ret=%d", ret);
    }

	send_public_key();



}


static void uart_cb(const struct device *dev, struct uart_event *evt, void *user_data)
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
			buf = CONTAINER_OF(aborted_buf, struct uart_data_t,
					   data[0]);
			aborted_buf = NULL;
			aborted_len = 0;
		} else {
			buf = CONTAINER_OF(evt->data.tx.buf, struct uart_data_t,
					   data[0]);
		}

		k_free(buf);

		buf = k_fifo_get(&fifo_uart_tx_data, K_NO_WAIT);
		if (!buf) {
			return;
		}

		if (uart_tx(uart, buf->data, buf->len, SYS_FOREVER_MS)) {
			LOG_WRN("Failed to send data over UART");
		}

		break;

	case UART_RX_RDY:
		LOG_DBG("UART_RX_RDY");
		buf = CONTAINER_OF(evt->data.rx.buf, struct uart_data_t, data[0]);
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
			LOG_WRN("Not able to allocate UART receive buffer");
			k_work_reschedule(&uart_work, UART_WAIT_FOR_BUF_DELAY);
			return;
		}

		uart_rx_enable(uart, buf->data, sizeof(buf->data),
			       UART_WAIT_FOR_RX);

		break;

	case UART_RX_BUF_REQUEST:
		LOG_DBG("UART_RX_BUF_REQUEST");
		buf = k_malloc(sizeof(*buf));
		if (buf) {
			buf->len = 0;
			uart_rx_buf_rsp(uart, buf->data, sizeof(buf->data));
		} else {
			LOG_WRN("Not able to allocate UART receive buffer");
		}

		break;

	case UART_RX_BUF_RELEASED:
		LOG_DBG("UART_RX_BUF_RELEASED");
		buf = CONTAINER_OF(evt->data.rx_buf.buf, struct uart_data_t,
				   data[0]);

		if (buf->len > 0) {
			k_fifo_put(&fifo_uart_rx_data, buf);
		} else {
			k_free(buf);
		}

		break;

	case UART_TX_ABORTED:
		LOG_DBG("UART_TX_ABORTED");
		if (!aborted_buf) {
			aborted_buf = (uint8_t *)evt->data.tx.buf;
		}

		aborted_len += evt->data.tx.len;
		buf = CONTAINER_OF((void *)aborted_buf, struct uart_data_t,
				   data);

		uart_tx(uart, &buf->data[aborted_len],
			buf->len - aborted_len, SYS_FOREVER_MS);

		break;

	default:
		break;
	}
}

static void uart_work_handler(struct k_work *item)
{
	struct uart_data_t *buf;

	buf = k_malloc(sizeof(*buf));
	if (buf) {
		buf->len = 0;
	} else {
		LOG_WRN("Not able to allocate UART receive buffer");
		k_work_reschedule(&uart_work, UART_WAIT_FOR_BUF_DELAY);
		return;
	}

	uart_rx_enable(uart, buf->data, sizeof(buf->data), UART_WAIT_FOR_RX);
}

static bool uart_test_async_api(const struct device *dev)
{
	const struct uart_driver_api *api =
			(const struct uart_driver_api *)dev->api;

	return (api->callback_set != NULL);
}

static int uart_init(void)
{
	int err;
	int pos;
	struct uart_data_t *rx;
	struct uart_data_t *tx;

	if (!device_is_ready(uart)) {
		return -ENODEV;
	}

	rx = k_malloc(sizeof(*rx));
	if (rx) {
		rx->len = 0;
	} else {
		return -ENOMEM;
	}

	k_work_init_delayable(&uart_work, uart_work_handler);


	if (IS_ENABLED(CONFIG_UART_ASYNC_ADAPTER) && !uart_test_async_api(uart)) {
		/* Implement API adapter */
		uart_async_adapter_init(async_adapter, uart);
		uart = async_adapter;
	}

	err = uart_callback_set(uart, uart_cb, NULL);
	if (err) {
		k_free(rx);
		LOG_ERR("Cannot initialize UART callback");
		return err;
	}

	if (IS_ENABLED(CONFIG_UART_LINE_CTRL)) {
		LOG_INF("Wait for DTR");
		while (true) {
			uint32_t dtr = 0;

			uart_line_ctrl_get(uart, UART_LINE_CTRL_DTR, &dtr);
			if (dtr) {
				break;
			}
			/* Give CPU resources to low priority threads. */
			k_sleep(K_MSEC(100));
		}
		LOG_INF("DTR set");
		err = uart_line_ctrl_set(uart, UART_LINE_CTRL_DCD, 1);
		if (err) {
			LOG_WRN("Failed to set DCD, ret code %d", err);
		}
		err = uart_line_ctrl_set(uart, UART_LINE_CTRL_DSR, 1);
		if (err) {
			LOG_WRN("Failed to set DSR, ret code %d", err);
		}
	}

	tx = k_malloc(sizeof(*tx));

	if (tx) {
		pos = snprintf(tx->data, sizeof(tx->data),
			       "Starting Nordic UART service sample\r\n");

		if ((pos < 0) || (pos >= sizeof(tx->data))) {
			k_free(rx);
			k_free(tx);
			LOG_ERR("snprintf returned %d", pos);
			return -ENOMEM;
		}

		tx->len = pos;
	} else {
		k_free(rx);
		return -ENOMEM;
	}

	err = uart_tx(uart, tx->data, tx->len, SYS_FOREVER_MS);
	if (err) {
		k_free(rx);
		k_free(tx);
		LOG_ERR("Cannot display welcome message (err: %d)", err);
		return err;
	}

	err = uart_rx_enable(uart, rx->data, sizeof(rx->data), UART_WAIT_FOR_RX);
	if (err) {
		LOG_ERR("Cannot enable uart reception (err: %d)", err);
		/* Free the rx buffer only because the tx buffer will be handled in the callback */
		k_free(rx);
	}

	return err;
}

static void adv_work_handler(struct k_work *work)
{
	int err = bt_le_adv_start(BT_LE_ADV_CONN_FAST_2, ad, ARRAY_SIZE(ad), sd, ARRAY_SIZE(sd));

	if (err) {
		LOG_ERR("Advertising failed to start (err %d)", err);
		return;
	}

	LOG_INF("Advertising successfully started");
}

static void advertising_start(void)
{
	k_work_submit(&adv_work);
}

static void connected(struct bt_conn *conn, uint8_t err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	if (err) {
		LOG_ERR("Connection failed, err 0x%02x %s", err, bt_hci_err_to_str(err));
		return;
	}

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_INF("Connected %s", addr);

	current_conn = bt_conn_ref(conn);

	dk_set_led_on(CON_STATUS_LED);

}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	LOG_INF("Disconnected: %s, reason 0x%02x %s", addr, reason, bt_hci_err_to_str(reason));

	if (auth_conn) {
		bt_conn_unref(auth_conn);
		auth_conn = NULL;
	}

	if (current_conn) {
		bt_conn_unref(current_conn);
		current_conn = NULL;
		dk_set_led_off(CON_STATUS_LED);
	}
}

static void recycled_cb(void)
{
	LOG_INF("Connection object available from previous conn. Disconnect is complete!");
	advertising_start();
}

#ifdef CONFIG_BT_NUS_SECURITY_ENABLED
static void security_changed(struct bt_conn *conn, bt_security_t level,
			     enum bt_security_err err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (!err) {
		LOG_INF("Security changed: %s level %u", addr, level);
	} else {
		LOG_WRN("Security failed: %s level %u err %d %s", addr, level, err,
			bt_security_err_to_str(err));
	}
}
#endif

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected        = connected,
	.disconnected     = disconnected,
	.recycled         = recycled_cb,
#ifdef CONFIG_BT_NUS_SECURITY_ENABLED
	.security_changed = security_changed,
#endif
};

#if defined(CONFIG_BT_NUS_SECURITY_ENABLED)
static void auth_passkey_display(struct bt_conn *conn, unsigned int passkey)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	LOG_INF("Passkey for %s: %06u", addr, passkey);
}

static void auth_passkey_confirm(struct bt_conn *conn, unsigned int passkey)
{
	char addr[BT_ADDR_LE_STR_LEN];

	auth_conn = bt_conn_ref(conn);

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	LOG_INF("Passkey for %s: %06u", addr, passkey);

	if (IS_ENABLED(CONFIG_SOC_SERIES_NRF54H) || IS_ENABLED(CONFIG_SOC_SERIES_NRF54L)) {
		LOG_INF("Press Button 0 to confirm, Button 1 to reject.");
	} else {
		LOG_INF("Press Button 1 to confirm, Button 2 to reject.");
	}
}


static void auth_cancel(struct bt_conn *conn)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	LOG_INF("Pairing cancelled: %s", addr);
}


static void pairing_complete(struct bt_conn *conn, bool bonded)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	LOG_INF("Pairing completed: %s, bonded: %d", addr, bonded);
}


static void pairing_failed(struct bt_conn *conn, enum bt_security_err reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	LOG_INF("Pairing failed conn: %s, reason %d %s", addr, reason,
		bt_security_err_to_str(reason));
}

static struct bt_conn_auth_cb conn_auth_callbacks = {
	.passkey_display = auth_passkey_display,
	.passkey_confirm = auth_passkey_confirm,
	.cancel = auth_cancel,
};

static struct bt_conn_auth_info_cb conn_auth_info_callbacks = {
	.pairing_complete = pairing_complete,
	.pairing_failed = pairing_failed
};
#else
static struct bt_conn_auth_cb conn_auth_callbacks;
static struct bt_conn_auth_info_cb conn_auth_info_callbacks;
#endif

static void bt_receive_cb(struct bt_conn *conn, const uint8_t *const data,
			  uint16_t len)
{
	int err;
	char addr[BT_ADDR_LE_STR_LEN] = {0};

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, ARRAY_SIZE(addr));

//	LOG_INF("Received data from: %s", addr);

	/* Central signals it has finished discovery and is ready */
	if (len == 5 && memcmp(data, "START", 5) == 0) {
		LOG_INF("===================================================");
		LOG_INF("Received START trigger — beginning PQC keygen/sign");

		k_thread_create(&mldsa_thread_data,
		                mldsa_stack,
		                K_THREAD_STACK_SIZEOF(mldsa_stack),
		                SPHINCSSHA2128SSIMPLE_keygen_thread,
		                NULL, NULL, NULL,
		                MLDSA_PRIORITY,
		                0,
		                K_NO_WAIT);
		k_thread_name_set(&mldsa_thread_data, "mldsa_keygen");
		return;
	}

	/* Central acknowledges full public key was received */
	if (len == 6 && memcmp(data, "PK_ACK", 6) == 0) {
		/* End public-key PPK2 trigger exactly when PK_ACK is received */
		trigger_set1(TRIGGER_PK_SEND_PIN, false);

		int64_t elapsed = k_uptime_get() - pk_send_start_time;

		LOG_INF("PK_ACK received — Total public key send time: %lld ms",
		        elapsed);

		send_signature();
		return;
	}

	/* Central acknowledges message received */
	if (len == 7 && memcmp(data, "SIG_ACK", 7) == 0) {
		/* End signature PPK2 trigger exactly when SIG_ACK is received */
		trigger_set1(TRIGGER_SIG_SEND_PIN, false);

		int64_t elapsed = k_uptime_get() - sig_send_start_time;

		LOG_INF("SIG_ACK received — Total signature send time: %lld ms",
		        elapsed);

		send_message(); 
		return;
	}

	if (len == 7 && memcmp(data, "MSG_ACK", 7) == 0) {
		/* End message PPK2 trigger exactly when MSG_ACK is received */
		trigger_set1(TRIGGER_MSG_SEND_PIN, false);

		int64_t elapsed = k_uptime_get() - msg_send_start_time;

		LOG_INF("MSG_ACK received — Total message send time: %lld ms",
		        elapsed);


		return;
	}


	for (uint16_t pos = 0; pos != len;) {
		struct uart_data_t *tx = k_malloc(sizeof(*tx));

		if (!tx) {
			LOG_WRN("Not able to allocate UART send data buffer");
			return;
		}

		/* Keep the last byte of TX buffer for potential LF char. */
		size_t tx_data_size = sizeof(tx->data) - 1;

		if ((len - pos) > tx_data_size) {
			tx->len = tx_data_size;
		} else {
			tx->len = (len - pos);
		}

		memcpy(tx->data, &data[pos], tx->len);

		pos += tx->len;

		/* Append the LF character when the CR character triggered
		 * transmission from the peer.
		 */
		if ((pos == len) && (data[len - 1] == '\r')) {
			tx->data[tx->len] = '\n';
			tx->len++;
		}

		err = uart_tx(uart, tx->data, tx->len, SYS_FOREVER_MS);
		if (err) {
			k_fifo_put(&fifo_uart_tx_data, tx);
		}
	}
}



static struct bt_nus_cb nus_cb = {
	.received = bt_receive_cb,
	 .sent = nus_sent_cb,
};

void error(void)
{
	dk_set_leds_state(DK_ALL_LEDS_MSK, DK_NO_LEDS_MSK);

	while (true) {
		/* Spin for ever */
		k_sleep(K_MSEC(1000));
	}
}

#ifdef CONFIG_BT_NUS_SECURITY_ENABLED
static void num_comp_reply(bool accept)
{
	if (accept) {
		bt_conn_auth_passkey_confirm(auth_conn);
		LOG_INF("Numeric Match, conn %p", (void *)auth_conn);
	} else {
		bt_conn_auth_cancel(auth_conn);
		LOG_INF("Numeric Reject, conn %p", (void *)auth_conn);
	}

	bt_conn_unref(auth_conn);
	auth_conn = NULL;
}

void button_changed(uint32_t button_state, uint32_t has_changed)
{
	uint32_t buttons = button_state & has_changed;

	if (auth_conn) {
		if (buttons & KEY_PASSKEY_ACCEPT) {
			num_comp_reply(true);
		}

		if (buttons & KEY_PASSKEY_REJECT) {
			num_comp_reply(false);
		}
	}
}
#endif /* CONFIG_BT_NUS_SECURITY_ENABLED */

static void configure_gpio(void)
{
    int err;

    if (!device_is_ready(gpio0_dev)) {
        LOG_ERR("GPIO0 device is not ready");
        error();
    }

    if (!device_is_ready(gpio1_dev)) {
        LOG_ERR("GPIO1 device is not ready");
        error();
    }

    /* GPIO0: P0.25 = key generation */
    err = gpio_pin_configure(gpio0_dev, TRIGGER_KEYGEN_PIN, GPIO_OUTPUT_INACTIVE);
    if (err) {
        LOG_ERR("Failed to configure P0.25 (keygen trigger), err=%d", err);
        error();
    }

    /* GPIO0: P0.26 = signing */
    err = gpio_pin_configure(gpio0_dev, TRIGGER_SIGNING_PIN, GPIO_OUTPUT_INACTIVE);
    if (err) {
        LOG_ERR("Failed to configure P0.26 (signing trigger), err=%d", err);
        error();
    }

    /* GPIO1: P1.04 = public-key send */
    err = gpio_pin_configure(gpio1_dev, TRIGGER_PK_SEND_PIN, GPIO_OUTPUT_INACTIVE);
    if (err) {
        LOG_ERR("Failed to configure P1.04 (public-key trigger), err=%d", err);
        error();
    }

    /* GPIO1: P1.05 = signature send */
    err = gpio_pin_configure(gpio1_dev, TRIGGER_SIG_SEND_PIN, GPIO_OUTPUT_INACTIVE);
    if (err) {
        LOG_ERR("Failed to configure P1.05 (signature trigger), err=%d", err);
        error();
    }

    /* GPIO1: P1.06 = message send */
    err = gpio_pin_configure(gpio1_dev, TRIGGER_MSG_SEND_PIN, GPIO_OUTPUT_INACTIVE);
    if (err) {
        LOG_ERR("Failed to configure P1.06 (message trigger), err=%d", err);
        error();
    }

    /* Make sure all PPK2 trigger outputs start LOW. */
    trigger_set0(TRIGGER_KEYGEN_PIN, false);
    trigger_set0(TRIGGER_SIGNING_PIN, false);
    trigger_set1(TRIGGER_PK_SEND_PIN, false);
    trigger_set1(TRIGGER_SIG_SEND_PIN, false);
    trigger_set1(TRIGGER_MSG_SEND_PIN, false);

    LOG_INF("PPK2 trigger GPIOs configured:");
    LOG_INF("  P0.25 = key generation");
    LOG_INF("  P0.26 = signing");
    LOG_INF("  P1.04 = public key send -> PK_ACK");
    LOG_INF("  P1.05 = signature send -> SIG_ACK");
    LOG_INF("  P1.06 = message send -> MSG_ACK");

#ifdef CONFIG_BT_NUS_SECURITY_ENABLED
	err = dk_buttons_init(button_changed);
	if (err) {
		LOG_ERR("Cannot init buttons (err: %d)", err);
	}
#endif /* CONFIG_BT_NUS_SECURITY_ENABLED */

	err = dk_leds_init();
	if (err) {
		LOG_ERR("Cannot init LEDs (err: %d)", err);
	}
}

int main(void)
{
	int blink_status = 0;
	int err = 0;

	configure_gpio();

	err = uart_init();
	if (err) {
		error();
	}

	if (IS_ENABLED(CONFIG_BT_NUS_SECURITY_ENABLED)) {
		err = bt_conn_auth_cb_register(&conn_auth_callbacks);
		if (err) {
			LOG_ERR("Failed to register authorization callbacks. (err: %d)", err);
			return 0;
		}

		err = bt_conn_auth_info_cb_register(&conn_auth_info_callbacks);
		if (err) {
			LOG_ERR("Failed to register authorization info callbacks. (err: %d)", err);
			return 0;
		}
	}

	err = bt_enable(NULL);
	if (err) {
		error();
	}

	LOG_INF("Bluetooth initialized");

	k_sem_give(&ble_init_ok);

	if (IS_ENABLED(CONFIG_SETTINGS)) {
		settings_load();
	}

	err = bt_nus_init(&nus_cb);
	if (err) {
		LOG_ERR("Failed to initialize UART service (err: %d)", err);
		return 0;
	}

	k_work_init(&adv_work, adv_work_handler);
	advertising_start();

	for (;;) {
		dk_set_led(RUN_STATUS_LED, (++blink_status) % 2);
		k_sleep(K_MSEC(RUN_LED_BLINK_INTERVAL));
	}
}

void ble_write_thread(void)
{
	/* Don't go any further until BLE is initialized */
	k_sem_take(&ble_init_ok, K_FOREVER);
	struct uart_data_t nus_data = {
		.len = 0,
	};

	for (;;) {
		/* Wait indefinitely for data to be sent over bluetooth */
		struct uart_data_t *buf = k_fifo_get(&fifo_uart_rx_data,
						     K_FOREVER);

		int plen = MIN(sizeof(nus_data.data) - nus_data.len, buf->len);
		int loc = 0;

		while (plen > 0) {
			memcpy(&nus_data.data[nus_data.len], &buf->data[loc], plen);
			nus_data.len += plen;
			loc += plen;

			if (nus_data.len >= sizeof(nus_data.data) ||
			   (nus_data.data[nus_data.len - 1] == '\n') ||
			   (nus_data.data[nus_data.len - 1] == '\r')) {
				if (bt_nus_send(NULL, nus_data.data, nus_data.len)) {
					LOG_WRN("Failed to send data over BLE connection");
				}
				nus_data.len = 0;
			}

			plen = MIN(sizeof(nus_data.data), buf->len - loc);
		}

		k_free(buf);
	}
}

K_THREAD_DEFINE(ble_write_thread_id, STACKSIZE, ble_write_thread, NULL, NULL,
		NULL, PRIORITY, 0, 0);
