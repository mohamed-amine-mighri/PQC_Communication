/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    p2p_server_app.c
  * @author  MCD Application Team
  * @brief   Peer to peer Server Application
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2019-2021 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "app_common.h"
#include "dbg_trace.h"
#include "ble.h"
#include "p2p_server_app.h"
#include "stm32_seq.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "api.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
 typedef struct{
    uint8_t             Device_Led_Selection;
    uint8_t             Led1;
 }P2P_LedCharValue_t;

 typedef struct{
    uint8_t             Device_Button_Selection;
    uint8_t             ButtonStatus;
 }P2P_ButtonCharValue_t;

typedef struct
{
  uint8_t               Notification_Status; /* used to check if P2P Server is enabled to Notify */
  P2P_LedCharValue_t    LedControl;
  P2P_ButtonCharValue_t ButtonControl;
  uint16_t              ConnectionHandle;
} P2P_Server_App_Context_t;

/* State machine for the gated public key -> message -> signature -> verify handshake */
typedef enum
{
  TX_IDLE,
  TX_WAIT_PK_ACK,
  TX_WAIT_MSG_ACK,
  TX_WAIT_SIG_ACK,
  TX_WAIT_VER_ACK
} tx_state_t;
/* USER CODE END PTD */

/* Private defines ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
uint8_t pk[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES];
uint8_t sk[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES];
uint8_t sig[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES];
size_t  siglen;

const uint8_t msg[] = "hello from board a";
const size_t  msglen = sizeof(msg) - 1;  // -1 to exclude the null terminator

/* ACK codes - MUST match the client's PK_ACK / MSG_ACK / SIG_ACK / VER_ACK values */
#define PK_ACK    0x01
#define MSG_ACK   0x02
#define SIG_ACK   0x03
#define VER_ACK   0x04

/* Number of automated keygen -> sign -> send -> verify cycles to run */
#define TOTAL_RUNS  100
/* USER CODE END PD */

/* Private macros -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */
/**
 * START of Section BLE_APP_CONTEXT
 */

static P2P_Server_App_Context_t P2P_Server_App_Context;

/**
 * END of Section BLE_APP_CONTEXT
 */

/* Handshake state and per-stage send-start timestamps */
static tx_state_t tx_state = TX_IDLE;
static uint32_t   pk_send_start;
static uint32_t   msg_send_start;
static uint32_t   sig_send_start;

/* Automated run counter (1..TOTAL_RUNS) */
static uint32_t   run_count = 0;
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
/* USER CODE BEGIN PFP */
static void P2PS_Send_Notification(void);
static void P2PS_APP_LED_BUTTON_context_Init(void);
//static void print_hex_dbg(const char *label, const uint8_t *buf, size_t len);
static void send_publickey(void);
static void send_message(const uint8_t *data, size_t len);
static void send_signature(void);
static void Run_PQC_Cycle(void);
/* USER CODE END PFP */

/* Functions Definition ------------------------------------------------------*/
void P2PS_STM_App_Notification(P2PS_STM_App_Notification_evt_t *pNotification)
{
/* USER CODE BEGIN P2PS_STM_App_Notification_1 */

/* USER CODE END P2PS_STM_App_Notification_1 */
  switch(pNotification->P2P_Evt_Opcode)
  {
/* USER CODE BEGIN P2PS_STM_App_Notification_P2P_Evt_Opcode */
#if(BLE_CFG_OTA_REBOOT_CHAR != 0)
    case P2PS_STM_BOOT_REQUEST_EVT:
      APP_DBG_MSG("-- P2P APPLICATION SERVER : BOOT REQUESTED\n");
      APP_DBG_MSG(" \n\r");

      *(uint32_t*)SRAM1_BASE = *(uint32_t*)pNotification->DataTransfered.pPayload;
      NVIC_SystemReset();
      break;
#endif
/* USER CODE END P2PS_STM_App_Notification_P2P_Evt_Opcode */

    case P2PS_STM__NOTIFY_ENABLED_EVT:
/* USER CODE BEGIN P2PS_STM__NOTIFY_ENABLED_EVT */
      P2P_Server_App_Context.Notification_Status = 1;
      APP_DBG_MSG("-- P2P APPLICATION SERVER : NOTIFICATION ENABLED\n"); 
      APP_DBG_MSG(" \n\r");
/* USER CODE END P2PS_STM__NOTIFY_ENABLED_EVT */
      break;

    case P2PS_STM_NOTIFY_DISABLED_EVT:
/* USER CODE BEGIN P2PS_STM_NOTIFY_DISABLED_EVT */
      P2P_Server_App_Context.Notification_Status = 0;
      APP_DBG_MSG("-- P2P APPLICATION SERVER : NOTIFICATION DISABLED\n");
      APP_DBG_MSG(" \n\r");
/* USER CODE END P2PS_STM_NOTIFY_DISABLED_EVT */
      break;

    case P2PS_STM_WRITE_EVT:
/* USER CODE BEGIN P2PS_STM_WRITE_EVT */

      /*
       * First check whether this write is one of our handshake ACKs
       * (PK_ACK / MSG_ACK / SIG_ACK / VER_ACK). If so, handle it here
       * and skip the LED/button payload parsing below entirely -
       * this avoids any collision with the Device_Led_Selection values
       * (0x00-0x06) used by the LED-control payloads.
       */
      {
        uint8_t rx0 = pNotification->DataTransfered.pPayload[0];
        uint8_t is_ack = (rx0 == PK_ACK) || (rx0 == MSG_ACK) ||
                         (rx0 == SIG_ACK) || (rx0 == VER_ACK);

        if(is_ack)
        {
          switch(rx0)
          {
            case PK_ACK:
              if(tx_state == TX_WAIT_PK_ACK)
              {
                uint32_t pk_time = HAL_GetTick() - pk_send_start;

                APP_DBG_MSG("PK_ACK received\r\n");
                APP_DBG_MSG("key send end \r\n");
                APP_DBG_MSG("Public Key Send Time = %lu ms\r\n", pk_time);

                /* PK_ACK received -> now (and only now) send the message */
                msg_send_start = HAL_GetTick();
                send_message(msg, msglen);
                tx_state = TX_WAIT_MSG_ACK;
              }
              break;

            case MSG_ACK:
              if(tx_state == TX_WAIT_MSG_ACK)
              {
                uint32_t msg_time = HAL_GetTick() - msg_send_start;

                APP_DBG_MSG("MSG_ACK received\r\n");
                APP_DBG_MSG("msg send end \r\n");
                APP_DBG_MSG("Message Send Time = %lu ms\r\n", msg_time);

                /* MSG_ACK received -> now (and only now) send the signature */
                sig_send_start = HAL_GetTick();
                send_signature();
                tx_state = TX_WAIT_SIG_ACK;
              }
              break;

            case SIG_ACK:
              if(tx_state == TX_WAIT_SIG_ACK)
              {
                uint32_t sig_time = HAL_GetTick() - sig_send_start;

                APP_DBG_MSG("SIG_ACK received\r\n");
                APP_DBG_MSG("sig send end \r\n");
                APP_DBG_MSG("Signature Send Time = %lu ms\r\n", sig_time);

                tx_state = TX_WAIT_VER_ACK;
              }
              break;

            case VER_ACK:
              if(tx_state == TX_WAIT_VER_ACK)
              {
                /* Just acknowledge reception - no timing printed for this one */
                APP_DBG_MSG("VER_ACK received\r\n");
                APP_DBG_MSG("Run %lu / %d complete\r\n", (unsigned long)run_count, TOTAL_RUNS);
                APP_DBG_MSG("===========================================================  \r\n");

                tx_state = TX_IDLE;

                /* Automatically restart from key generation for the next run */
                if(run_count < TOTAL_RUNS)
                {
                  Run_PQC_Cycle();
                }
                else
                {
                  APP_DBG_MSG("All %d runs complete\r\n", TOTAL_RUNS);
                  APP_DBG_MSG("===========================================================  \r\n");
                }
              }
              break;

            default:
              break;
          }
        }
        else
        {
          if(pNotification->DataTransfered.pPayload[0] == 0x00){ /* ALL Deviceselected - may be necessary as LB Routeur informs all connection */
            if(pNotification->DataTransfered.pPayload[1] == 0x01)
            {
              BSP_LED_On(LED_BLUE);
              APP_DBG_MSG("-- P2P APPLICATION SERVER  : LED1 ON\n");
              APP_DBG_MSG(" \n\r");
              P2P_Server_App_Context.LedControl.Led1=0x01; /* LED1 ON */
            }
            if(pNotification->DataTransfered.pPayload[1] == 0x00)
            {
              BSP_LED_Off(LED_BLUE);
              APP_DBG_MSG("-- P2P APPLICATION SERVER  : LED1 OFF\n");
              APP_DBG_MSG(" \n\r");
              P2P_Server_App_Context.LedControl.Led1=0x00; /* LED1 OFF */
            }
          }
#if(P2P_SERVER1 != 0)  
          if(pNotification->DataTransfered.pPayload[0] == 0x01){ /* end device 1 selected - may be necessary as LB Routeur informs all connection */
            if(pNotification->DataTransfered.pPayload[1] == 0x01)
            {
              BSP_LED_On(LED_BLUE);
              APP_DBG_MSG("-- P2P APPLICATION SERVER 1 : LED1 ON\n");
              APP_DBG_MSG(" \n\r");
              P2P_Server_App_Context.LedControl.Led1=0x01; /* LED1 ON */
            }
            if(pNotification->DataTransfered.pPayload[1] == 0x00)
            {
              BSP_LED_Off(LED_BLUE);
              APP_DBG_MSG("-- P2P APPLICATION SERVER 1 : LED1 OFF\n");
              APP_DBG_MSG(" \n\r");
              P2P_Server_App_Context.LedControl.Led1=0x00; /* LED1 OFF */
            }
          }
#endif
#if(P2P_SERVER2 != 0)
          if(pNotification->DataTransfered.pPayload[0] == 0x02){ /* end device 2 selected */
            if(pNotification->DataTransfered.pPayload[1] == 0x01)
            {
              BSP_LED_On(LED_BLUE);
               APP_DBG_MSG("-- P2P APPLICATION SERVER 2 : LED1 ON\n");
              APP_DBG_MSG(" \n\r");
              P2P_Server_App_Context.LedControl.Led1=0x01; /* LED1 ON */
            }
            if(pNotification->DataTransfered.pPayload[1] == 0x00)
            {
              BSP_LED_Off(LED_BLUE);
              APP_DBG_MSG("-- P2P APPLICATION SERVER 2 : LED1 OFF\n");
              APP_DBG_MSG(" \n\r");
              P2P_Server_App_Context.LedControl.Led1=0x00; /* LED1 OFF */
            }
          }
#endif      
#if(P2P_SERVER3 != 0)  
          if(pNotification->DataTransfered.pPayload[0] == 0x03){ /* end device 3 selected - may be necessary as LB Routeur informs all connection */
            if(pNotification->DataTransfered.pPayload[1] == 0x01)
            {
              BSP_LED_On(LED_BLUE);
              APP_DBG_MSG("-- P2P APPLICATION SERVER 3 : LED1 ON\n");
              APP_DBG_MSG(" \n\r");
              P2P_Server_App_Context.LedControl.Led1=0x01; /* LED1 ON */
            }
            if(pNotification->DataTransfered.pPayload[1] == 0x00)
            {
              BSP_LED_Off(LED_BLUE);
              APP_DBG_MSG("-- P2P APPLICATION SERVER 3 : LED1 OFF\n");
              APP_DBG_MSG(" \n\r");
              P2P_Server_App_Context.LedControl.Led1=0x00; /* LED1 OFF */
            }
          }
#endif
#if(P2P_SERVER4 != 0)
          if(pNotification->DataTransfered.pPayload[0] == 0x04){ /* end device 4 selected */
            if(pNotification->DataTransfered.pPayload[1] == 0x01)
            {
              BSP_LED_On(LED_BLUE);
               APP_DBG_MSG("-- P2P APPLICATION SERVER 2 : LED1 ON\n");
              APP_DBG_MSG(" \n\r");
              P2P_Server_App_Context.LedControl.Led1=0x01; /* LED1 ON */
            }
            if(pNotification->DataTransfered.pPayload[1] == 0x00)
            {
              BSP_LED_Off(LED_BLUE);
              APP_DBG_MSG("-- P2P APPLICATION SERVER 2 : LED1 OFF\n");
              APP_DBG_MSG(" \n\r");
              P2P_Server_App_Context.LedControl.Led1=0x00; /* LED1 OFF */
            }
          }
#endif     
#if(P2P_SERVER5 != 0)  
          if(pNotification->DataTransfered.pPayload[0] == 0x05){ /* end device 5 selected - may be necessary as LB Routeur informs all connection */
            if(pNotification->DataTransfered.pPayload[1] == 0x01)
            {
              BSP_LED_On(LED_BLUE);
              APP_DBG_MSG("-- P2P APPLICATION SERVER 5 : LED1 ON\n");
              APP_DBG_MSG(" \n\r");
              P2P_Server_App_Context.LedControl.Led1=0x01; /* LED1 ON */
            }
            if(pNotification->DataTransfered.pPayload[1] == 0x00)
            {
              BSP_LED_Off(LED_BLUE);
              APP_DBG_MSG("-- P2P APPLICATION SERVER 5 : LED1 OFF\n");
              APP_DBG_MSG(" \n\r");
              P2P_Server_App_Context.LedControl.Led1=0x00; /* LED1 OFF */
            }
          }
#endif
#if(P2P_SERVER6 != 0)
          if(pNotification->DataTransfered.pPayload[0] == 0x06){ /* end device 6 selected */
            if(pNotification->DataTransfered.pPayload[1] == 0x01)
            {
              BSP_LED_On(LED_BLUE);
               APP_DBG_MSG("-- P2P APPLICATION SERVER 6 : LED1 ON\n");
              APP_DBG_MSG(" \n\r");
              P2P_Server_App_Context.LedControl.Led1=0x01; /* LED1 ON */
            }
            if(pNotification->DataTransfered.pPayload[1] == 0x00)
            {
              BSP_LED_Off(LED_BLUE);
              APP_DBG_MSG("-- P2P APPLICATION SERVER 6 : LED1 OFF\n");
              APP_DBG_MSG(" \n\r");
              P2P_Server_App_Context.LedControl.Led1=0x00; /* LED1 OFF */
            }
          }
#endif
        }
      }
/* USER CODE END P2PS_STM_WRITE_EVT */
      break;

    default:
/* USER CODE BEGIN P2PS_STM_App_Notification_default */
      
/* USER CODE END P2PS_STM_App_Notification_default */
      break;
  }
/* USER CODE BEGIN P2PS_STM_App_Notification_2 */

/* USER CODE END P2PS_STM_App_Notification_2 */
  return;
}

void P2PS_APP_Notification(P2PS_APP_ConnHandle_Not_evt_t *pNotification)
{
/* USER CODE BEGIN P2PS_APP_Notification_1 */

/* USER CODE END P2PS_APP_Notification_1 */
  switch(pNotification->P2P_Evt_Opcode)
  {
/* USER CODE BEGIN P2PS_APP_Notification_P2P_Evt_Opcode */

/* USER CODE END P2PS_APP_Notification_P2P_Evt_Opcode */
  case PEER_CONN_HANDLE_EVT :
/* USER CODE BEGIN PEER_CONN_HANDLE_EVT */
          
/* USER CODE END PEER_CONN_HANDLE_EVT */
    break;

    case PEER_DISCON_HANDLE_EVT :
/* USER CODE BEGIN PEER_DISCON_HANDLE_EVT */
       P2PS_APP_LED_BUTTON_context_Init();       
/* USER CODE END PEER_DISCON_HANDLE_EVT */
    break;

    default:
/* USER CODE BEGIN P2PS_APP_Notification_default */

/* USER CODE END P2PS_APP_Notification_default */
      break;
  }
/* USER CODE BEGIN P2PS_APP_Notification_2 */

/* USER CODE END P2PS_APP_Notification_2 */
  return;
}

void P2PS_APP_Init(void)
{
/* USER CODE BEGIN P2PS_APP_Init */
  UTIL_SEQ_RegTask( 1<< CFG_TASK_SW1_BUTTON_PUSHED_ID, UTIL_SEQ_RFU, P2PS_Send_Notification );

  /**
   * Initialize LedButton Service
   */
  P2P_Server_App_Context.Notification_Status=0; 
  P2PS_APP_LED_BUTTON_context_Init();
/* USER CODE END P2PS_APP_Init */
  return;
}

/* USER CODE BEGIN FD */
void P2PS_APP_LED_BUTTON_context_Init(void){
  
  BSP_LED_Off(LED_BLUE);
  APP_DBG_MSG("LED BLUE OFF\n");
  
  #if(P2P_SERVER1 != 0)
  P2P_Server_App_Context.LedControl.Device_Led_Selection=0x01; /* Device1 */
  P2P_Server_App_Context.LedControl.Led1=0x00; /* led OFF */
  P2P_Server_App_Context.ButtonControl.Device_Button_Selection=0x01;/* Device1 */
  P2P_Server_App_Context.ButtonControl.ButtonStatus=0x00;
#endif
#if(P2P_SERVER2 != 0)
  P2P_Server_App_Context.LedControl.Device_Led_Selection=0x02; /* Device2 */
  P2P_Server_App_Context.LedControl.Led1=0x00; /* led OFF */
  P2P_Server_App_Context.ButtonControl.Device_Button_Selection=0x02;/* Device2 */
  P2P_Server_App_Context.ButtonControl.ButtonStatus=0x00;
#endif  
#if(P2P_SERVER3 != 0)
  P2P_Server_App_Context.LedControl.Device_Led_Selection=0x03; /* Device3 */
  P2P_Server_App_Context.LedControl.Led1=0x00; /* led OFF */
  P2P_Server_App_Context.ButtonControl.Device_Button_Selection=0x03; /* Device3 */
  P2P_Server_App_Context.ButtonControl.ButtonStatus=0x00;
#endif
#if(P2P_SERVER4 != 0)
  P2P_Server_App_Context.LedControl.Device_Led_Selection=0x04; /* Device4 */
  P2P_Server_App_Context.LedControl.Led1=0x00; /* led OFF */
  P2P_Server_App_Context.ButtonControl.Device_Button_Selection=0x04; /* Device4 */
  P2P_Server_App_Context.ButtonControl.ButtonStatus=0x00;
#endif  
 #if(P2P_SERVER5 != 0)
  P2P_Server_App_Context.LedControl.Device_Led_Selection=0x05; /* Device5 */
  P2P_Server_App_Context.LedControl.Led1=0x00; /* led OFF */
  P2P_Server_App_Context.ButtonControl.Device_Button_Selection=0x05; /* Device5 */
  P2P_Server_App_Context.ButtonControl.ButtonStatus=0x00;
#endif
#if(P2P_SERVER6 != 0)
  P2P_Server_App_Context.LedControl.Device_Led_Selection=0x06; /* device6 */
  P2P_Server_App_Context.LedControl.Led1=0x00; /* led OFF */
  P2P_Server_App_Context.ButtonControl.Device_Button_Selection=0x06; /* Device6 */
  P2P_Server_App_Context.ButtonControl.ButtonStatus=0x00;
#endif  
}

void P2PS_APP_SW1_Button_Action(void)
{
  /* Button press starts (or restarts) a fresh batch of TOTAL_RUNS cycles */
  run_count = 0;
  Run_PQC_Cycle();

  return;
}
/* USER CODE END FD */

/*************************************************************
 *
 * LOCAL FUNCTIONS
 *
 *************************************************************/
/* USER CODE BEGIN FD_LOCAL_FUNCTIONS*/

/**
 * @brief One full keygen -> sign -> (schedule) send cycle.
 *        Called from the button action for the first run, and again
 *        automatically from the VER_ACK handler for every subsequent
 *        run until TOTAL_RUNS is reached.
 */
void Run_PQC_Cycle(void)
{
  run_count++;

  APP_DBG_MSG("Starting run %lu / %d\r\n", (unsigned long)run_count, TOTAL_RUNS);

  uint32_t keygen_start;
  uint32_t keygen_end;
  keygen_start = HAL_GetTick();
  APP_DBG_MSG("key gen start \r\n");
  int status = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk, sk);
  APP_DBG_MSG("key gen end \r\n");
  keygen_end = HAL_GetTick();

  if (!status)
  {	  APP_DBG_MSG("Public and Private keys generated \r\n");
  APP_DBG_MSG("Key Generation Time = %lu ms\r\n",  keygen_end - keygen_start);
  }
  else
  {	  APP_DBG_MSG("Error in Key Generation \r\n");     }

//  print_hex_dbg("PUBLIC KEY", pk, CRYPTO_PUBLICKEYBYTES);
//  print_hex_dbg("SECRET KEY", sk, CRYPTO_SECRETKEYBYTES);

  UTIL_SEQ_SetTask( 1<<CFG_TASK_SW1_BUTTON_PUSHED_ID, CFG_SCH_PRIO_0);
  uint32_t sign_end;
  uint32_t sign_start;
  sign_start = HAL_GetTick();
  APP_DBG_MSG("sig gen start \r\n");
  int sign_status = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(sig, &siglen, msg, msglen, sk);
  APP_DBG_MSG("sig gen end \r\n");
  sign_end = HAL_GetTick();
    if (sign_status == 0)
    {    APP_DBG_MSG("Message signed successfully \r\n");
         APP_DBG_MSG("Signing Time = %lu ms\r\n", sign_end-sign_start);

    }
    else
    {   APP_DBG_MSG("Signing failed\r\n");}

  return;
}

void P2PS_Send_Notification(void)
{
  /*
   * Only the public key is sent here. The message is sent once PK_ACK
   * is received, and the signature is sent once MSG_ACK is received
   * (see the ACK handling in P2PS_STM_App_Notification / P2PS_STM_WRITE_EVT).
   */
  pk_send_start = HAL_GetTick();
  send_publickey();
  tx_state = TX_WAIT_PK_ACK;

  return;
}

// Function to print hex data


void send_publickey(void)
{
	uint16_t offset = 0;
	uint16_t chunk_len;
    tBleStatus sendstatus;
    APP_DBG_MSG("key send start \r\n");
	while (offset < PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES)
	{
		chunk_len = PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES - offset;

		if (chunk_len > 248)
		{
			chunk_len = 248;
		}

		do {
		    sendstatus = P2PS_STM_App_Update_Char(P2P_NOTIFY_CHAR_UUID, &pk[offset], chunk_len);
		    if (sendstatus != BLE_STATUS_SUCCESS) {
		        HAL_Delay(5);  // brief backoff, then retry same chunk
		    }
		} while (sendstatus != BLE_STATUS_SUCCESS);


		offset += chunk_len;
	//	APP_DBG_MSG("Chunk %d succeful \r\n", offset);


	}
		APP_DBG_MSG("Public Key sent \r\n");
}


void send_message(const uint8_t *data, size_t len)
{
    uint16_t offset = 0;
    uint16_t chunk_len;
    tBleStatus sendstatus;
    APP_DBG_MSG("msg send start \r\n");
    /* --- send message payload directly in chunks --- */
    while (offset < len)
    {
        chunk_len = (uint16_t)(len - offset);

        if (chunk_len > 248)
        {
            chunk_len = 248;
        }

        do
        {
            sendstatus = P2PS_STM_App_Update_Char(
                P2P_NOTIFY_CHAR_UUID,
                (uint8_t *)&data[offset],
                chunk_len
            );

            if (sendstatus != BLE_STATUS_SUCCESS)
            {
                HAL_Delay(5);
            }

        } while (sendstatus != BLE_STATUS_SUCCESS);

        offset += chunk_len;

   //     HAL_Delay(10);
    }

    APP_DBG_MSG("Message sent (%u bytes)\r\n", (unsigned)len);
}

void send_signature(void)
{
    uint16_t offset = 0;
    uint16_t chunk_len;
    tBleStatus sendstatus;
    uint16_t chunk_num = 0;
    APP_DBG_MSG("sig send start \r\n");
    while (offset < siglen)
    {
        chunk_len = siglen - offset;
        if (chunk_len > 248) chunk_len = 248;

        do {
            sendstatus = P2PS_STM_App_Update_Char(P2P_NOTIFY_CHAR_UUID, &sig[offset], chunk_len);
            if (sendstatus != BLE_STATUS_SUCCESS) HAL_Delay(5);
        } while (sendstatus != BLE_STATUS_SUCCESS);

        chunk_num++;
      //  APP_DBG_MSG("Chunk %u: %u B sent\r\n", chunk_num, chunk_len);

        offset += chunk_len;
     //   HAL_Delay(10);
    }
    APP_DBG_MSG("Signature sent \r\n");
}
/* USER CODE END FD_LOCAL_FUNCTIONS*/
/*
static void print_hex_dbg(const char *label, const uint8_t *buf, size_t len) {
    APP_DBG_MSG("\r\n=== %s (%u bytes) ===\r\n", label, (unsigned int)len);

    for (size_t i = 0; i < len; i++) {
        APP_DBG_MSG("%02X", buf[i]);

        // Add line break every 32 bytes for clean readability
        if ((i + 1) % 32 == 0) {
            APP_DBG_MSG("\r\n");
        }
    }
    APP_DBG_MSG("\r\n");
}*/
