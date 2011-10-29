//
//  kindle_tool.h
//  KindleTool
//
//  Created by Yifan Lu on 10/28/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#ifndef KINDLETOOL
#define KINDLETOOL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#define SWAPENDIAN(x) (((x>>24)&0xff) | ((x<<8)&0xff0000) | ((x>>8)&0xff00) | ((x<<24)&0xff000000))
#define SWAPENDIAN(x) (x)
#define BUFFER_SIZE 1024

#define MAGIC_NUMBER_LENGTH 4
#define MD5_HASH_LENGTH 32

#define OTA_UPDATE_BLOCK_SIZE 64
#define RECOVERY_UPDATE_BLOCK_SIZE 131072
#define UPDATE_SIGNATURE_BLOCK_SIZE 64

#define CERTIFICATE_DEV_SIZE 128
#define CERTIFICATE_1K_SIZE 128
#define CERTIFICATE_2K_SIZE 256

typedef struct {
    char magic_number[MAGIC_NUMBER_LENGTH];
    unsigned char blocks[UPDATE_SIGNATURE_BLOCK_SIZE-MAGIC_NUMBER_LENGTH];
} UpdateHeader;

typedef struct {
    char magic_number[MAGIC_NUMBER_LENGTH];
    unsigned int certificate_number;
} UpdateSignatureHeader;

typedef struct {
    char magic_number[MAGIC_NUMBER_LENGTH];
    unsigned long source_revision;
    unsigned long target_revision;
    unsigned short num_devices;
} OTAUpdateV2Header;

typedef struct {
    char magic_number[MAGIC_NUMBER_LENGTH];
    unsigned int source_revision;
    unsigned int target_revision;
    unsigned short device;
    unsigned char optional;
    unsigned char unused;
    unsigned char md5_sum[MD5_HASH_LENGTH];
} OTAUpdateHeader;

typedef struct {
    OTAUpdateHeader update_header;
    unsigned int magic_1;
    unsigned int magic_2;
    unsigned int minor;
    unsigned int device;
} RecoveryUpdateHeader;

typedef enum {
    UpdateSignature,
    OTAUpdateV2,
    OTAUpdate,
    RecoveryUpdate,
    UnknownUpdate = -1
} BundleVersion;

typedef enum {
    CertificateDeveloper = 0x00,
    Certificate1K = 0x01,
    Certificate2K = 0x02,
    CertificateUnknown = 0x00
} CertificateNumber;

typedef enum {
    Kindle1 = 0x01,
    Kindle2US = 0x02,
    Kindle2International = 0x03,
    KindleDXUS = 0x04,
    KindleDXInternational = 0x05,
    KindleDXGraphite = 0x09,
    Kindle3Wifi = 0x08,
    Kindle3Wifi3G = 0x06,
    Kindle3Wifi3GEurope = 0x0A,
    Kindle4NonTouch = 0x0E,
    Kindle4Touch = 0xFF,
    KindleUnknown = 0x00
} Device;

void md(unsigned char *, size_t);
void dm(unsigned char *, size_t);
int munger(FILE *, FILE *, size_t);
int demunger(FILE *, FILE *, size_t);
BundleVersion get_bundle_version(char*);
int read_bundle_header(UpdateHeader *, FILE *);
const char *convert_device_id(Device);

#endif
