#include <stdio.h>
#include <string.h>
// POSIX sys lib: fork, pipe, I/O (read, write)
#include <unistd.h>
// superset of unistd, same
#include <stdlib.h>

//Bluetooth
//usr/src/linux-headers-4.14.0-deepin2-common/include/net/bluetooth
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/sco.h>

//socket
#include <sys/socket.h>

//Cryotograph
#include <tomcrypt.h>
//#include "libcrypto.h"
//#include "libcrypto.c"

int wait_for_ack(int s) {
    unsigned char input[256] = {0};
    int bytes_read, cont = 0;
    bytes_read = read(s, input, sizeof(input));
    while ((input[0] != 0xff)) {
        bytes_read = read(s, input, sizeof(input));
        cont++;
        if(cont==10)
            break;
    }
    if (cont == 10) {
        printf("ACK not received\n");
        return -1;
    }
    else {
        printf("ACK received\n");
        return 0;
    }
}

int read_data(int s, unsigned char *input, int block_size){
    int bytes_read;
    bytes_read = read(s, input, block_size);
    if(bytes_read != block_size){
        //printf("Error frame len\n");
        return -1;
    }
    else
        return 0;
}

int main(int argc, char **argv) {
    unsigned char msg[8];
    int block_size = 8;
    unsigned char pt[block_size];
    Symmetric_key skey;
    unsigned char Skey[10] = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D,0xCA,0x7D};
    unsigned char Bkey[8]  = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D};
    unsigned char key[16]  = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D,0x53,0x23,0x91,0x42,0xf3,0xc3,0x12,0x1a};

    int flag = 0,  cont = 0;
    unsigned char input[block_size] = {0};
    struct sockaddr_rc addrress = { 0 };
    int s, status;

    char dest[18] = "00:06:66:46:B7:01";//="";// = "B0:10:41:3F:6E:80";//My destination address Laptop
    char namelaptop[20]="RN42-B701";


    // allocate a socket
    s = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    ///create a socket

    // set the connection parameters (who to connect to)
    addrress.rc_family = AF_BLUETOOTH;
    addrress.rc_channel = (__uint8_t ) 1;//must use sdp to work in real devices
    //may this channel not ready

    ///search
    printf("Search for BT Devices...\n");
    inquiry_info *ii = NULL;
    int max_rsp, num_rsp;
    int dev_id, sock, len, flags;
    int i;
    char addr[18] = { 0 };
    char name[248] = { 0 };

    dev_id = hci_get_route(NULL);
    sock = hci_open_dev( dev_id );
    if (dev_id < 0 || sock < 0) {
        perror("opening socket");
        exit(1);
    }

    len = 8;
    max_rsp = 2;
    flags = IREQ_CACHE_FLUSH;
    ii = (inquiry_info*)malloc(max_rsp * sizeof(inquiry_info));

    num_rsp = hci_inquiry(dev_id, len, max_rsp, NULL, &ii, flags);
    if( num_rsp < 0 ) {
        perror("hci_inquiry");
        exit(1);
    }

    for (i = 0; i < num_rsp; i++) {
        ba2str(&(ii+i)->bdaddr, addr);
        memset(name, 0, sizeof(name));
        if (hci_read_remote_name(sock, &(ii+i)->bdaddr, sizeof(name), name, 0) < 0)
            strcpy(name, "[unknown]");

        else{
            printf("\nFind #%d\n",i);
            printf("Addr:%s    Name:%s\n", addr, name);
            int a=strcmp(name, namelaptop);
            //printf("compare:%d\n",a);
            if (!a){   // if name mached
                str2ba( addr, &addrress.rc_bdaddr );//copy dest-->addr.rc_bdaddr
                flag =1;
            }
        }
    }
/// End Search

///Connect and send
    if (flag==0){
        printf("Not find dest: %s\n",name);
        exit(0);
    }
    // connect to server, throw socket s
    status = connect(s, (struct sockaddr *)&addrress, sizeof(addrress));
    //successful, connect() returns 0.
    if (status == 0){
        printf("connection status OK\n\n");
        // send a message to configure server
        printf("send the set sensors command\n");
        msg[0] = 0x08;
        msg[1] = 0x80;
        msg[3] = 0x00;
        write(s, msg, 3);
        wait_for_ack(s);

        printf("send the set sampling rate command\n");
        msg[0] = 0x05;
        msg[1] = 0xCC;  //0x14  # 51.2Hz
        write(s, msg, 2);
        wait_for_ack(s);

        printf("send start streaming command\n");
        msg[0] = 0x07;
        write(s, msg, 1);
        wait_for_ack(s);
    }
    else {
        if (status < 0) {
            perror("connection status Failed\n");
            close(s);
            free(ii);
            close(sock);
            return 0;
        }
    }
    // receiver data
    skipjack_setup(Skey, 10, 0, &skey);

    while (cont<100){
        if(read_data(s, input, block_size ) == 0) {
            printf("Data receiver\n");

            printf("Input\n");
            for (int i = 0; i < block_size; i++) {
                printf("%.2x ", input[i]);
            }
            skipjack_ecb_decrypt(input,pt,&skey);
            printf("\n");
            printf("PlainText\n");
            for (int i = 0; i < block_size; i++) {
                printf("%.2x ", pt[i]);
            }
            printf("\n");
            cont++;
        }
    }
    //send stop streaming command
    msg[0] = 0x20;
    write(s, msg, 1);

    printf("Closing socket\n");//close the socket
    close(s);
    free(ii);///End connect and send
    close(sock);

    return 0;
}