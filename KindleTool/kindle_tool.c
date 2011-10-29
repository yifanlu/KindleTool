//
//  main.c
//  KindleTool
//
//  Created by Yifan Lu on 10/26/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#define SWAPENDIAN(x) (((x>>24)&0xff) | ((x<<8)&0xff0000) | ((x>>8)&0xff00) | ((x<<24)&0xff000000))
#define SWAPENDIAN(x) (x)
#define MAGIC_NUMBER_LENGTH 4
#define MD5_HASH_LENGTH 32
#define OTA_UPDATE_BLOCK_SIZE 64
#define RECOVERY_UPDATE_BLOCK_SIZE 131072
#define UPDATE_SIGNATURE_BLOCK_SIZE 64
#define BUFFER_SIZE 1024
#define CERTIFICATE_DEV_SIZE 128
#define CERTIFICATE_1K_SIZE 128
#define CERTIFICATE_2K_SIZE 256

typedef struct {
    char magic_number[MAGIC_NUMBER_LENGTH];
    unsigned char blocks[UPDATE_SIGNATURE_BLOCK_SIZE-MAGIC_NUMBER_LENGTH];
} UpdateHeader;

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

typedef enum {
    RecoveryUpdate,
    OTAUpdate,
    OTAUpdateV2,
    UpdateSignature,
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

void md(unsigned char *bytes, size_t length)
{
    int i;
    for(i = 0; i < length; i++)
    {
        bytes[i] = ( ( bytes[i] >> 4 | bytes[i] << 4 ) & 0xFF ) ^ 0x7A;
    }
}

void dm(unsigned char *bytes, size_t length)
{
    int i;
    for(i = 0; i < length; i++)
    {
        bytes[i] = ( bytes[i] ^ 0x7A );
        bytes[i] = ( bytes[i] >> 4 | bytes[i] << 4 ) & 0xFF;
    }
}

int munger(FILE *input, FILE *output, size_t length)
{
	unsigned char *bytes;
	int i;
	size_t bytes_read;
	size_t bytes_written;
	bytes = malloc(BUFFER_SIZE);
	while((bytes_read = fread(bytes, sizeof(char), (length < BUFFER_SIZE && length > 0 ? length : BUFFER_SIZE), input)) > 0)
	{
		md(bytes, bytes_read);
		bytes_written = fwrite(bytes, sizeof(char), bytes_read, output);
		if(ferror(output) != 0)
		{
			fprintf(stderr, "Error munging, cannot write to output.\n");
			return -1;
		}
		else if(bytes_written < bytes_read)
		{
			fprintf(stderr, "Error munging, read %zu bytes but only wrote %zu bytes\n", bytes_read, bytes_written);
			return -1;
		}
		length -= bytes_read;
	}
	if(ferror(input) != 0)
	{
		fprintf(stderr, "Error munging, cannot read input.\n");
		return -1;
	}
	
	return 0;
}

int demunger(FILE *input, FILE *output, size_t length)
{
	unsigned char *bytes;
	int i;
	size_t bytes_read;
	size_t bytes_written;
	bytes = malloc(BUFFER_SIZE);
	while((bytes_read = fread(bytes, sizeof(char), (length < BUFFER_SIZE && length > 0 ? length : BUFFER_SIZE), input)) > 0)
	{
		dm(bytes, bytes_read);
		bytes_written = fwrite(bytes, sizeof(char), bytes_read, output);
		if(ferror(output) != 0)
		{
			fprintf(stderr, "Error munging, cannot write to output.\n");
			free(bytes);
			return -1;
		}
		else if(bytes_written < bytes_read)
		{
			fprintf(stderr, "Error munging, read %zu bytes but only wrote %zu bytes\n", bytes_read, bytes_written);
			free(bytes);
			return -1;
		}
		length -= bytes_read;
	}
	if(ferror(input) != 0)
	{
		fprintf(stderr, "Error munging, cannot read input.\n");
		free(bytes);
		return -1;
	}
	free(bytes);
	
	return 0;
}

BundleVersion get_bundle_version(char magic_number[4])
{
    if(!strncmp(magic_number, "FB02", 4) || !strncmp(magic_number, "FB01", 4))
        return RecoveryUpdate;
    else if(!strncmp(magic_number, "FC02", 4) || !strncmp(magic_number, "FD03", 4))
        return OTAUpdate;
    else if(!strncmp(magic_number, "FC04", 4) || !strncmp(magic_number, "FD04", 4) || !strncmp(magic_number, "FL01", 4))
        return OTAUpdateV2;
    else if(!strncmp(magic_number, "SP01", 4))
        return UpdateSignature;
    else
        return UnknownUpdate;
}

int read_bundle_header(UpdateHeader *header, FILE *input)
{
    if(fread(header, sizeof(UpdateHeader), 1, input) < 1 || ferror(input) != 0)
    {
        return -1;
    }
    return 0;
}

int extract_signature(FILE *input, FILE *output, UpdateHeader *abstract_header)
{
    UpdateSignatureHeader *header;
    CertificateNumber cert_num;
    char *cert_name;
    size_t seek;
    unsigned char *signature;
    
    
    header = (UpdateSignatureHeader*)abstract_header;
    cert_num = (CertificateNumber)(SWAPENDIAN(header->certificate_number));
    printf("Certificate number:\t\t%u\n", cert_num);
    switch(cert_num)
    {
        case CertificateDeveloper:
            cert_name = "pubdevkey01.pem";
            seek = CERTIFICATE_DEV_SIZE;
            break;
        case Certificate1K:
            cert_name = "pubprodkey01.pem";
            seek = CERTIFICATE_1K_SIZE;
            break;
        case Certificate2K:
            cert_name = "pubprodkey02.pem";
            seek = CERTIFICATE_2K_SIZE;
            break;
        default:
            fprintf(stderr, "Unknown signature size, cannot continue.\n");
            return -1;
            break;
    }
    printf("Certificate file:\t\t%s\n", cert_name);
    if(output == NULL)
    {
        return fseek(input, seek, SEEK_CUR);
    }
    else
    {
        signature = malloc(seek);
        if(fread(signature, sizeof(char), seek, input) < seek || ferror(input))
        {
            fprintf(stderr, "Cannot read signature!\n");
            free(signature);
            return -1;
        }
        if(fwrite(signature, sizeof(char), seek, output) < seek || ferror(output))
        {
            fprintf(stderr, "Cannot write signature file!\n");
            free(signature);
            return -1;
        }
    }
    return 0;
}

const char *convert_device_id(Device dev)
{
    switch(dev)
    {
        case Kindle1:
            return "Kindle 1";
        case Kindle2US:
            return "Kindle 2 US";
        case Kindle2International:
            return "Kindle 2 International";
        case KindleDXUS:
            return "Kindle DX US";
        case KindleDXInternational:
            return "Kindle DX International";
        case KindleDXGraphite:
            return "Kindle DX Graphite";
        case Kindle3Wifi:
            return "Kindle 3 Wifi";
        case Kindle3Wifi3G:
            return "Kindle 3 Wifi+3G";
        case Kindle3Wifi3GEurope:
            return "Kindle 3 Wifi+3G Europe";
        case Kindle4NonTouch:
            return "Kindle 4 Non-Touch";
        case Kindle4Touch:
            return "Kindle 4 Touch";
        case KindleUnknown:
        default:
            return "Unknown";
    }
}

int extract_recovery(FILE *input, FILE *output, UpdateHeader *abstract_header)
{
    RecoveryUpdateHeader *header;
    
    header = (RecoveryUpdateHeader*)abstract_header;
    dm(header->update_header.md5_sum, MD5_HASH_LENGTH);
    printf("MD5 Hash:\t\t%.*s\n", MD5_HASH_LENGTH, header->update_header.md5_sum);
    printf("Magic 1:\t\t%d\n", SWAPENDIAN(header->magic_1));
    printf("Magic 2:\t\t%d\n", SWAPENDIAN(header->magic_2));
    printf("Minor:\t\t%d\n", SWAPENDIAN(header->minor));
    printf("Device:\t\t%s\n", convert_device_id(SWAPENDIAN(header->device)));
    
    if(fseek(input, RECOVERY_UPDATE_BLOCK_SIZE - OTA_UPDATE_BLOCK_SIZE, SEEK_CUR) != 0)
    {
        fprintf(stderr, "Cannot read recovery update!\n");
        return -1;
    }
    return demunger(input, output, 0);
}

int extract_ota_update(FILE *input, FILE *output, UpdateHeader *abstract_header)
{
    OTAUpdateHeader *header;
    
    header = (OTAUpdateHeader*)abstract_header;
    dm(header->md5_sum, MD5_HASH_LENGTH);
    printf("MD5 Hash:\t\t%.*s\n", MD5_HASH_LENGTH, header->md5_sum);
    printf("Minimum OTA:\t\t%d\n", SWAPENDIAN(header->source_revision));
    printf("Target OTA:\t\t%d\n", SWAPENDIAN(header->target_revision));
    printf("Device:\t\t%s\n", convert_device_id(SWAPENDIAN(header->device)));
    printf("Optional:\t\t%d\n", SWAPENDIAN(header->optional));
    
    return demunger(input, output, 0);
}

int extract(FILE *input, FILE *output, FILE *sig_output)
{
    UpdateHeader abstract_header;
    UpdateSignatureHeader *sig_header;
    BundleVersion bundle_version;
    if(read_bundle_header(&abstract_header, input) < 0)
    {
        fprintf(stderr, "Cannot read input file.\n");
        return -1;
    }
    bundle_version = get_bundle_version(abstract_header.magic_number);
    switch(bundle_version)
    {
        case UnknownUpdate:
        default:
            printf("Unknown update bundle version!\n");
            break;
        case UpdateSignature:
            if(extract_signature(input, sig_output, &abstract_header) < 0)
            {
                fprintf(stderr, "Cannot extract signature file!\n");
                return -1;
            }
            extract(input, output, sig_output);
            break;
        case RecoveryUpdate:
            if(extract_recovery(input, output, &abstract_header) < 0)
            {
                fprintf(stderr, "Cannot extract update!\n");
                return -1;
            }
            break;
        case OTAUpdate:
            if(extract_ota_update(input, output, &abstract_header) < 0)
            {
                fprintf(stderr, "Cannot extract update!\n");
                return -1;
            }
    }
}

int main (int argc, const char * argv[])
{
    FILE *input = fopen("/Users/yifanlu/Downloads/Update_kindle_3.3_B006.bin", "r");
    FILE *output = fopen("/Users/yifanlu/Downloads/Update_kindle_3.3_B006.tgz", "w");
    FILE *output_sig = fopen("/Users/yifanlu/Downloads/Update_kindle_3.3_B006.tgz.sig", "w");
    extract(input, output, output_sig);
    return 0;
}

