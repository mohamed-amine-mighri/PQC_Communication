################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (14.3.rel1)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../Application/User/Core/address.c \
../Application/User/Core/aes.c \
C:/Users/BIG\ BANG/STM32Cube/Repository/STM32Cube_FW_WB_V1.24.0/Projects/P-NUCLEO-WB55.Nucleo/Applications/My_work/BLE_p2pClient/Core/Src/app_debug.c \
C:/Users/BIG\ BANG/STM32Cube/Repository/STM32Cube_FW_WB_V1.24.0/Projects/P-NUCLEO-WB55.Nucleo/Applications/My_work/BLE_p2pClient/Core/Src/app_entry.c \
../Application/User/Core/context_shake.c \
../Application/User/Core/fips202.c \
../Application/User/Core/fors.c \
../Application/User/Core/hash_shake.c \
C:/Users/BIG\ BANG/STM32Cube/Repository/STM32Cube_FW_WB_V1.24.0/Projects/P-NUCLEO-WB55.Nucleo/Applications/My_work/BLE_p2pClient/Core/Src/hw_timerserver.c \
C:/Users/BIG\ BANG/STM32Cube/Repository/STM32Cube_FW_WB_V1.24.0/Projects/P-NUCLEO-WB55.Nucleo/Applications/My_work/BLE_p2pClient/Core/Src/hw_uart.c \
C:/Users/BIG\ BANG/STM32Cube/Repository/STM32Cube_FW_WB_V1.24.0/Projects/P-NUCLEO-WB55.Nucleo/Applications/My_work/BLE_p2pClient/Core/Src/main.c \
../Application/User/Core/merkle.c \
../Application/User/Core/nistseedexpander.c \
../Application/User/Core/randombytes.c \
../Application/User/Core/sha2.c \
../Application/User/Core/sign.c \
../Application/User/Core/sp800-185.c \
C:/Users/BIG\ BANG/STM32Cube/Repository/STM32Cube_FW_WB_V1.24.0/Projects/P-NUCLEO-WB55.Nucleo/Applications/My_work/BLE_p2pClient/Core/Src/stm32_lpm_if.c \
C:/Users/BIG\ BANG/STM32Cube/Repository/STM32Cube_FW_WB_V1.24.0/Projects/P-NUCLEO-WB55.Nucleo/Applications/My_work/BLE_p2pClient/Core/Src/stm32wbxx_hal_msp.c \
C:/Users/BIG\ BANG/STM32Cube/Repository/STM32Cube_FW_WB_V1.24.0/Projects/P-NUCLEO-WB55.Nucleo/Applications/My_work/BLE_p2pClient/Core/Src/stm32wbxx_it.c \
../Application/User/Core/syscalls.c \
../Application/User/Core/sysmem.c \
../Application/User/Core/thash_shake_simple.c \
../Application/User/Core/utils.c \
../Application/User/Core/utilsx1.c \
../Application/User/Core/wots.c \
../Application/User/Core/wotsx1.c 

OBJS += \
./Application/User/Core/address.o \
./Application/User/Core/aes.o \
./Application/User/Core/app_debug.o \
./Application/User/Core/app_entry.o \
./Application/User/Core/context_shake.o \
./Application/User/Core/fips202.o \
./Application/User/Core/fors.o \
./Application/User/Core/hash_shake.o \
./Application/User/Core/hw_timerserver.o \
./Application/User/Core/hw_uart.o \
./Application/User/Core/main.o \
./Application/User/Core/merkle.o \
./Application/User/Core/nistseedexpander.o \
./Application/User/Core/randombytes.o \
./Application/User/Core/sha2.o \
./Application/User/Core/sign.o \
./Application/User/Core/sp800-185.o \
./Application/User/Core/stm32_lpm_if.o \
./Application/User/Core/stm32wbxx_hal_msp.o \
./Application/User/Core/stm32wbxx_it.o \
./Application/User/Core/syscalls.o \
./Application/User/Core/sysmem.o \
./Application/User/Core/thash_shake_simple.o \
./Application/User/Core/utils.o \
./Application/User/Core/utilsx1.o \
./Application/User/Core/wots.o \
./Application/User/Core/wotsx1.o 

C_DEPS += \
./Application/User/Core/address.d \
./Application/User/Core/aes.d \
./Application/User/Core/app_debug.d \
./Application/User/Core/app_entry.d \
./Application/User/Core/context_shake.d \
./Application/User/Core/fips202.d \
./Application/User/Core/fors.d \
./Application/User/Core/hash_shake.d \
./Application/User/Core/hw_timerserver.d \
./Application/User/Core/hw_uart.d \
./Application/User/Core/main.d \
./Application/User/Core/merkle.d \
./Application/User/Core/nistseedexpander.d \
./Application/User/Core/randombytes.d \
./Application/User/Core/sha2.d \
./Application/User/Core/sign.d \
./Application/User/Core/sp800-185.d \
./Application/User/Core/stm32_lpm_if.d \
./Application/User/Core/stm32wbxx_hal_msp.d \
./Application/User/Core/stm32wbxx_it.d \
./Application/User/Core/syscalls.d \
./Application/User/Core/sysmem.d \
./Application/User/Core/thash_shake_simple.d \
./Application/User/Core/utils.d \
./Application/User/Core/utilsx1.d \
./Application/User/Core/wots.d \
./Application/User/Core/wotsx1.d 


# Each subdirectory must supply rules for building sources it contributes
Application/User/Core/%.o Application/User/Core/%.su Application/User/Core/%.cyclo: ../Application/User/Core/%.c Application/User/Core/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m4 -std=gnu11 -g3 -DUSE_HAL_DRIVER -DUSE_STM32WBXX_NUCLEO -DDEBUG -DSTM32WB55xx -c -I../../Core/Inc -I../../STM32_WPAN/App -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc/Legacy -I../../../../../../../Utilities/lpm/tiny_lpm -I../../../../../../../Middlewares/ST/STM32_WPAN -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/tl -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/shci -I../../../../../../../Middlewares/ST/STM32_WPAN/utilities -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/auto -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/template -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Inc -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Src -I../../../../../../../Drivers/CMSIS/Device/ST/STM32WBxx/Include -I../../../../../../../Utilities/sequencer -I../../../../../../../Middlewares/ST/STM32_WPAN/ble -I../../../../../../../Drivers/CMSIS/Include -I../../../../../../../Drivers/BSP/P-NUCLEO-WB55.Nucleo -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -o "$@"
Application/User/Core/app_debug.o: C:/Users/BIG\ BANG/STM32Cube/Repository/STM32Cube_FW_WB_V1.24.0/Projects/P-NUCLEO-WB55.Nucleo/Applications/My_work/BLE_p2pClient/Core/Src/app_debug.c Application/User/Core/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m4 -std=gnu11 -g3 -DUSE_HAL_DRIVER -DUSE_STM32WBXX_NUCLEO -DDEBUG -DSTM32WB55xx -c -I../../Core/Inc -I../../STM32_WPAN/App -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc/Legacy -I../../../../../../../Utilities/lpm/tiny_lpm -I../../../../../../../Middlewares/ST/STM32_WPAN -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/tl -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/shci -I../../../../../../../Middlewares/ST/STM32_WPAN/utilities -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/auto -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/template -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Inc -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Src -I../../../../../../../Drivers/CMSIS/Device/ST/STM32WBxx/Include -I../../../../../../../Utilities/sequencer -I../../../../../../../Middlewares/ST/STM32_WPAN/ble -I../../../../../../../Drivers/CMSIS/Include -I../../../../../../../Drivers/BSP/P-NUCLEO-WB55.Nucleo -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"Application/User/Core/app_debug.d" -MT"$@" --specs=nano.specs -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -o "$@"
Application/User/Core/app_entry.o: C:/Users/BIG\ BANG/STM32Cube/Repository/STM32Cube_FW_WB_V1.24.0/Projects/P-NUCLEO-WB55.Nucleo/Applications/My_work/BLE_p2pClient/Core/Src/app_entry.c Application/User/Core/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m4 -std=gnu11 -g3 -DUSE_HAL_DRIVER -DUSE_STM32WBXX_NUCLEO -DDEBUG -DSTM32WB55xx -c -I../../Core/Inc -I../../STM32_WPAN/App -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc/Legacy -I../../../../../../../Utilities/lpm/tiny_lpm -I../../../../../../../Middlewares/ST/STM32_WPAN -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/tl -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/shci -I../../../../../../../Middlewares/ST/STM32_WPAN/utilities -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/auto -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/template -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Inc -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Src -I../../../../../../../Drivers/CMSIS/Device/ST/STM32WBxx/Include -I../../../../../../../Utilities/sequencer -I../../../../../../../Middlewares/ST/STM32_WPAN/ble -I../../../../../../../Drivers/CMSIS/Include -I../../../../../../../Drivers/BSP/P-NUCLEO-WB55.Nucleo -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"Application/User/Core/app_entry.d" -MT"$@" --specs=nano.specs -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -o "$@"
Application/User/Core/hw_timerserver.o: C:/Users/BIG\ BANG/STM32Cube/Repository/STM32Cube_FW_WB_V1.24.0/Projects/P-NUCLEO-WB55.Nucleo/Applications/My_work/BLE_p2pClient/Core/Src/hw_timerserver.c Application/User/Core/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m4 -std=gnu11 -g3 -DUSE_HAL_DRIVER -DUSE_STM32WBXX_NUCLEO -DDEBUG -DSTM32WB55xx -c -I../../Core/Inc -I../../STM32_WPAN/App -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc/Legacy -I../../../../../../../Utilities/lpm/tiny_lpm -I../../../../../../../Middlewares/ST/STM32_WPAN -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/tl -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/shci -I../../../../../../../Middlewares/ST/STM32_WPAN/utilities -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/auto -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/template -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Inc -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Src -I../../../../../../../Drivers/CMSIS/Device/ST/STM32WBxx/Include -I../../../../../../../Utilities/sequencer -I../../../../../../../Middlewares/ST/STM32_WPAN/ble -I../../../../../../../Drivers/CMSIS/Include -I../../../../../../../Drivers/BSP/P-NUCLEO-WB55.Nucleo -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"Application/User/Core/hw_timerserver.d" -MT"$@" --specs=nano.specs -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -o "$@"
Application/User/Core/hw_uart.o: C:/Users/BIG\ BANG/STM32Cube/Repository/STM32Cube_FW_WB_V1.24.0/Projects/P-NUCLEO-WB55.Nucleo/Applications/My_work/BLE_p2pClient/Core/Src/hw_uart.c Application/User/Core/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m4 -std=gnu11 -g3 -DUSE_HAL_DRIVER -DUSE_STM32WBXX_NUCLEO -DDEBUG -DSTM32WB55xx -c -I../../Core/Inc -I../../STM32_WPAN/App -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc/Legacy -I../../../../../../../Utilities/lpm/tiny_lpm -I../../../../../../../Middlewares/ST/STM32_WPAN -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/tl -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/shci -I../../../../../../../Middlewares/ST/STM32_WPAN/utilities -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/auto -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/template -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Inc -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Src -I../../../../../../../Drivers/CMSIS/Device/ST/STM32WBxx/Include -I../../../../../../../Utilities/sequencer -I../../../../../../../Middlewares/ST/STM32_WPAN/ble -I../../../../../../../Drivers/CMSIS/Include -I../../../../../../../Drivers/BSP/P-NUCLEO-WB55.Nucleo -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"Application/User/Core/hw_uart.d" -MT"$@" --specs=nano.specs -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -o "$@"
Application/User/Core/main.o: C:/Users/BIG\ BANG/STM32Cube/Repository/STM32Cube_FW_WB_V1.24.0/Projects/P-NUCLEO-WB55.Nucleo/Applications/My_work/BLE_p2pClient/Core/Src/main.c Application/User/Core/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m4 -std=gnu11 -g3 -DUSE_HAL_DRIVER -DUSE_STM32WBXX_NUCLEO -DDEBUG -DSTM32WB55xx -c -I../../Core/Inc -I../../STM32_WPAN/App -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc/Legacy -I../../../../../../../Utilities/lpm/tiny_lpm -I../../../../../../../Middlewares/ST/STM32_WPAN -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/tl -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/shci -I../../../../../../../Middlewares/ST/STM32_WPAN/utilities -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/auto -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/template -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Inc -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Src -I../../../../../../../Drivers/CMSIS/Device/ST/STM32WBxx/Include -I../../../../../../../Utilities/sequencer -I../../../../../../../Middlewares/ST/STM32_WPAN/ble -I../../../../../../../Drivers/CMSIS/Include -I../../../../../../../Drivers/BSP/P-NUCLEO-WB55.Nucleo -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"Application/User/Core/main.d" -MT"$@" --specs=nano.specs -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -o "$@"
Application/User/Core/stm32_lpm_if.o: C:/Users/BIG\ BANG/STM32Cube/Repository/STM32Cube_FW_WB_V1.24.0/Projects/P-NUCLEO-WB55.Nucleo/Applications/My_work/BLE_p2pClient/Core/Src/stm32_lpm_if.c Application/User/Core/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m4 -std=gnu11 -g3 -DUSE_HAL_DRIVER -DUSE_STM32WBXX_NUCLEO -DDEBUG -DSTM32WB55xx -c -I../../Core/Inc -I../../STM32_WPAN/App -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc/Legacy -I../../../../../../../Utilities/lpm/tiny_lpm -I../../../../../../../Middlewares/ST/STM32_WPAN -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/tl -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/shci -I../../../../../../../Middlewares/ST/STM32_WPAN/utilities -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/auto -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/template -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Inc -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Src -I../../../../../../../Drivers/CMSIS/Device/ST/STM32WBxx/Include -I../../../../../../../Utilities/sequencer -I../../../../../../../Middlewares/ST/STM32_WPAN/ble -I../../../../../../../Drivers/CMSIS/Include -I../../../../../../../Drivers/BSP/P-NUCLEO-WB55.Nucleo -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"Application/User/Core/stm32_lpm_if.d" -MT"$@" --specs=nano.specs -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -o "$@"
Application/User/Core/stm32wbxx_hal_msp.o: C:/Users/BIG\ BANG/STM32Cube/Repository/STM32Cube_FW_WB_V1.24.0/Projects/P-NUCLEO-WB55.Nucleo/Applications/My_work/BLE_p2pClient/Core/Src/stm32wbxx_hal_msp.c Application/User/Core/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m4 -std=gnu11 -g3 -DUSE_HAL_DRIVER -DUSE_STM32WBXX_NUCLEO -DDEBUG -DSTM32WB55xx -c -I../../Core/Inc -I../../STM32_WPAN/App -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc/Legacy -I../../../../../../../Utilities/lpm/tiny_lpm -I../../../../../../../Middlewares/ST/STM32_WPAN -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/tl -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/shci -I../../../../../../../Middlewares/ST/STM32_WPAN/utilities -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/auto -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/template -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Inc -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Src -I../../../../../../../Drivers/CMSIS/Device/ST/STM32WBxx/Include -I../../../../../../../Utilities/sequencer -I../../../../../../../Middlewares/ST/STM32_WPAN/ble -I../../../../../../../Drivers/CMSIS/Include -I../../../../../../../Drivers/BSP/P-NUCLEO-WB55.Nucleo -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"Application/User/Core/stm32wbxx_hal_msp.d" -MT"$@" --specs=nano.specs -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -o "$@"
Application/User/Core/stm32wbxx_it.o: C:/Users/BIG\ BANG/STM32Cube/Repository/STM32Cube_FW_WB_V1.24.0/Projects/P-NUCLEO-WB55.Nucleo/Applications/My_work/BLE_p2pClient/Core/Src/stm32wbxx_it.c Application/User/Core/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m4 -std=gnu11 -g3 -DUSE_HAL_DRIVER -DUSE_STM32WBXX_NUCLEO -DDEBUG -DSTM32WB55xx -c -I../../Core/Inc -I../../STM32_WPAN/App -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc -I../../../../../../../Drivers/STM32WBxx_HAL_Driver/Inc/Legacy -I../../../../../../../Utilities/lpm/tiny_lpm -I../../../../../../../Middlewares/ST/STM32_WPAN -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/tl -I../../../../../../../Middlewares/ST/STM32_WPAN/interface/patterns/ble_thread/shci -I../../../../../../../Middlewares/ST/STM32_WPAN/utilities -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/auto -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/core/template -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Inc -I../../../../../../../Middlewares/ST/STM32_WPAN/ble/svc/Src -I../../../../../../../Drivers/CMSIS/Device/ST/STM32WBxx/Include -I../../../../../../../Utilities/sequencer -I../../../../../../../Middlewares/ST/STM32_WPAN/ble -I../../../../../../../Drivers/CMSIS/Include -I../../../../../../../Drivers/BSP/P-NUCLEO-WB55.Nucleo -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"Application/User/Core/stm32wbxx_it.d" -MT"$@" --specs=nano.specs -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -o "$@"

clean: clean-Application-2f-User-2f-Core

clean-Application-2f-User-2f-Core:
	-$(RM) ./Application/User/Core/address.cyclo ./Application/User/Core/address.d ./Application/User/Core/address.o ./Application/User/Core/address.su ./Application/User/Core/aes.cyclo ./Application/User/Core/aes.d ./Application/User/Core/aes.o ./Application/User/Core/aes.su ./Application/User/Core/app_debug.cyclo ./Application/User/Core/app_debug.d ./Application/User/Core/app_debug.o ./Application/User/Core/app_debug.su ./Application/User/Core/app_entry.cyclo ./Application/User/Core/app_entry.d ./Application/User/Core/app_entry.o ./Application/User/Core/app_entry.su ./Application/User/Core/context_shake.cyclo ./Application/User/Core/context_shake.d ./Application/User/Core/context_shake.o ./Application/User/Core/context_shake.su ./Application/User/Core/fips202.cyclo ./Application/User/Core/fips202.d ./Application/User/Core/fips202.o ./Application/User/Core/fips202.su ./Application/User/Core/fors.cyclo ./Application/User/Core/fors.d ./Application/User/Core/fors.o ./Application/User/Core/fors.su ./Application/User/Core/hash_shake.cyclo ./Application/User/Core/hash_shake.d ./Application/User/Core/hash_shake.o ./Application/User/Core/hash_shake.su ./Application/User/Core/hw_timerserver.cyclo ./Application/User/Core/hw_timerserver.d ./Application/User/Core/hw_timerserver.o ./Application/User/Core/hw_timerserver.su ./Application/User/Core/hw_uart.cyclo ./Application/User/Core/hw_uart.d ./Application/User/Core/hw_uart.o ./Application/User/Core/hw_uart.su ./Application/User/Core/main.cyclo ./Application/User/Core/main.d ./Application/User/Core/main.o ./Application/User/Core/main.su ./Application/User/Core/merkle.cyclo ./Application/User/Core/merkle.d ./Application/User/Core/merkle.o ./Application/User/Core/merkle.su ./Application/User/Core/nistseedexpander.cyclo ./Application/User/Core/nistseedexpander.d ./Application/User/Core/nistseedexpander.o ./Application/User/Core/nistseedexpander.su ./Application/User/Core/randombytes.cyclo ./Application/User/Core/randombytes.d ./Application/User/Core/randombytes.o ./Application/User/Core/randombytes.su ./Application/User/Core/sha2.cyclo ./Application/User/Core/sha2.d ./Application/User/Core/sha2.o ./Application/User/Core/sha2.su ./Application/User/Core/sign.cyclo ./Application/User/Core/sign.d ./Application/User/Core/sign.o ./Application/User/Core/sign.su ./Application/User/Core/sp800-185.cyclo ./Application/User/Core/sp800-185.d ./Application/User/Core/sp800-185.o ./Application/User/Core/sp800-185.su ./Application/User/Core/stm32_lpm_if.cyclo ./Application/User/Core/stm32_lpm_if.d ./Application/User/Core/stm32_lpm_if.o ./Application/User/Core/stm32_lpm_if.su ./Application/User/Core/stm32wbxx_hal_msp.cyclo ./Application/User/Core/stm32wbxx_hal_msp.d ./Application/User/Core/stm32wbxx_hal_msp.o ./Application/User/Core/stm32wbxx_hal_msp.su ./Application/User/Core/stm32wbxx_it.cyclo ./Application/User/Core/stm32wbxx_it.d ./Application/User/Core/stm32wbxx_it.o ./Application/User/Core/stm32wbxx_it.su ./Application/User/Core/syscalls.cyclo ./Application/User/Core/syscalls.d ./Application/User/Core/syscalls.o ./Application/User/Core/syscalls.su ./Application/User/Core/sysmem.cyclo ./Application/User/Core/sysmem.d ./Application/User/Core/sysmem.o ./Application/User/Core/sysmem.su ./Application/User/Core/thash_shake_simple.cyclo ./Application/User/Core/thash_shake_simple.d ./Application/User/Core/thash_shake_simple.o ./Application/User/Core/thash_shake_simple.su ./Application/User/Core/utils.cyclo ./Application/User/Core/utils.d ./Application/User/Core/utils.o ./Application/User/Core/utils.su ./Application/User/Core/utilsx1.cyclo ./Application/User/Core/utilsx1.d ./Application/User/Core/utilsx1.o ./Application/User/Core/utilsx1.su ./Application/User/Core/wots.cyclo ./Application/User/Core/wots.d ./Application/User/Core/wots.o ./Application/User/Core/wots.su ./Application/User/Core/wotsx1.cyclo ./Application/User/Core/wotsx1.d ./Application/User/Core/wotsx1.o ./Application/User/Core/wotsx1.su

.PHONY: clean-Application-2f-User-2f-Core

