#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "bench_common.h"
#include "esp_task_wdt.h"

static void bench_task(void *arg)
{
    (void)arg;

    // WDT: si pas initialisé, c'est OK
    esp_task_wdt_deinit();

    bench_local_run();

    vTaskDelete(NULL);
}

void app_main(void)
{
#if CONFIG_DSA_APP_LOCAL
    printf("[APP] mode=LOCAL\n");

    // 64 KB stack (en words)
    const uint32_t stack_bytes = 64 * 1024;
    const uint32_t stack_words = stack_bytes / sizeof(StackType_t);

    BaseType_t ok = xTaskCreate(bench_task, "bench_task", stack_words, NULL, 5, NULL);
    if (ok != pdPASS) {
        printf("[APP] ERROR: xTaskCreate failed\n");
    }

#elif CONFIG_DSA_APP_INTEROP
    printf("[APP] mode=INTEROP\n");
    app_interop_run();
#else
    printf("[APP] no mode selected\n");
#endif

    while (1) vTaskDelay(pdMS_TO_TICKS(1000));
}