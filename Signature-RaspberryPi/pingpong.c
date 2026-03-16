#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <wiringPi.h>
#include <wiringSerial.h>

int main() {
    int serial_port;
    if((serial_port = serialOpen("/dev/serial0", 115200)) < 0) {
        fprintf(stderr, "unable to open serial device: %s\n", strerror(errno));
        return 1;
    }
    if(wiringPiSetup() == -1) {
        fprintf(stderr, "unable to start wiringPi: %s\n", strerror(errno));
    }

    char buf[1024];
    while(1) {
        if (serialDataAvail(serial_port)) {
            int c = serialGetchar(serial_port);
            putchar(c);
            fflush(stdout);

            if (c == '\n') {
                buf[0] = '\0';
            } else {
                strncat(buf, (char *)&c, 1);
            }

            if (strcmp(buf, "ping") == 0) {
                serialPuts(serial_port, "pong\n");
                printf("Raspberry Pi replied: pong\n");
                buf[0] = '\0'; // reset buffer
            }
        }
    }
}