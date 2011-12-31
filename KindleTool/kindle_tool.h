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
#include <fcntl.h>
#include <libtar.h>
#include <unistd.h>
#include <dirent.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

//#define SWAPENDIAN(x) (((x>>24)&0xff) | ((x<<8)&0xff0000) | ((x>>8)&0xff00) | ((x<<24)&0xff000000))
#define SWAPENDIAN(x) (x)
#define BUFFER_SIZE 1024
#define BLOCK_SIZE 64

#define MAGIC_NUMBER_LENGTH 4
#define MD5_HASH_LENGTH 32

#define OTA_UPDATE_BLOCK_SIZE 60
#define OTA_UPDATE_V2_BLOCK_SIZE 18
#define OTA_UPDATE_V2_PART_2_BLOCK_SIZE 36
#define RECOVERY_UPDATE_BLOCK_SIZE 131068
#define UPDATE_SIGNATURE_BLOCK_SIZE 60

#define CERTIFICATE_DEV_SIZE 128
#define CERTIFICATE_1K_SIZE 128
#define CERTIFICATE_2K_SIZE 256

#define INDEX_FILE_NAME "update-filelist.dat"

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
    CertificateUnknown = 0xFF
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
    Kindle4Touch = 0x0F,
    KindleUnknown = 0x00
} Device;

typedef struct {
    char magic_number[MAGIC_NUMBER_LENGTH];
} UpdateHeader;

typedef struct {
    CertificateNumber certificate_number;
} UpdateSignatureHeader;

typedef struct {
    unsigned int source_revision;
    unsigned int target_revision;
    unsigned short device;
    unsigned char optional;
    unsigned char unused;
    unsigned char md5_sum[MD5_HASH_LENGTH];
} OTAUpdateHeader;

typedef struct {
    unsigned char unused[12];
    unsigned char md5_sum[MD5_HASH_LENGTH];
    unsigned int magic_1;
    unsigned int magic_2;
    unsigned int minor;
    unsigned int device;
} RecoveryUpdateHeader;

static const char *SIGN_KEY = 
    "-----BEGIN RSA PRIVATE KEY-----\
    MIICXgIBAAKBgQDJn1jWU+xxVv/eRKfCPR9e47lPWN2rH33z9QbfnqmCxBRLP6mM\
    jGy6APyycQXg3nPi5fcb75alZo+Oh012HpMe9LnpeEgloIdm1E4LOsyrz4kttQtG\
    RlzCErmBGt6+cAVEV86y2phOJ3mLk0Ek9UQXbIUfrvyJnS2MKLG2cczjlQIDAQAB\
    AoGASLym1POD2kOznSERkF5yoc3vvXNmzORYkRk1eJkJuDY6yAbYiO7kDppqj4l8\
    wGogTpv98OMXauY8JgQj6tgO5LkY2upttukDr8uhE2z9Dh7HMZV/rDYa+9rybJus\
    RiAQDmF+VCzY2HirjpsSzgRu0r82NC8znNm2eGORys9BvmECQQDoIokOr0fYz3UT\
    SbHfD3engXFPZ+JaJqU8xayR7C+Gp5I0CgSnCDTQVgdkVGbPuLVYiWDIcEaxjvVr\
    hXYt2Ac9AkEA3lnERgg0RmWBC3K8toCyfDvr8eXao+xgUJ3lNWbqS0HtwxczwnIE\
    H49IIDojbTnLUr3OitFMZuaJuT2MtWzTOQJBAK6GCHU54tJmZqbxqQEDJ/qPnxkM\
    CWmt1F00YOH0qGacZZcqUQUjblGT3EraCdHyFKVT46fOgdfMm0cTOB6PZCECQQDI\
    s5Zq8HTfJjg5MTQOOFTjtuLe0m9sj6zQl/WRInhRvgzzkDn0Rh5armaYUGIx8X0K\
    DrIks4+XQnkGb/xWtwhhAkEA3FdnrsFiCNNJhvit2aTmtLzXxU46K+sV6NIY1tEJ\
    G+RFzLRwO4IFDY4a/dooh1Yh1iFFGjcmpqza6tRutaw8zA==\
    -----END RSA PRIVATE KEY-----\
    ";

void md(unsigned char *, size_t);
void dm(unsigned char *, size_t);
int munger(FILE *, FILE *, size_t);
int demunger(FILE *, FILE *, size_t);
const char *convert_device_id(Device);
BundleVersion get_bundle_version(char*);
int md5_sum(FILE *, char*);
FILE *get_default_key();

int read_bundle_header(UpdateHeader *, FILE *);
int extract(FILE *, FILE *, FILE *);
int extract_ota_update_v2(FILE *, FILE *);
int extract_signature(FILE *, FILE *);
int extract_ota_update(FILE *, FILE *);
int extract_recovery(FILE *, FILE *);

int is_script(char *);
int sign_file(FILE *, FILE *, FILE *);
int kindle_create();
int kindle_create_tar_from_directory(const char *, const char *, FILE *);
int kindle_sign_and_add_files(DIR *, char *, FILE *, FILE *, TAR *);
int kindle_create_from_tar(TAR *);

#endif
