//
//  extract.c
//  KindleTool
//
//  Created by Yifan Lu on 10/28/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#include "kindle_tool.h"

int kindle_read_bundle_header(UpdateHeader *header, FILE *input)
{
    if(fread(header, sizeof(UpdateHeader), 1, input) < 1 || ferror(input) != 0)
    {
        return -1;
    }
    return 0;
}

int kindle_convert(FILE *input, FILE *output, FILE *sig_output)
{
    UpdateHeader abstract_header;
    BundleVersion bundle_version;
    if(kindle_read_bundle_header(&abstract_header, input) < 0)
    {
        fprintf(stderr, "Cannot read input file.\n");
        return -1;
    }
    bundle_version = get_bundle_version(abstract_header.magic_number);
    switch(bundle_version)
    {
        case OTAUpdateV2:
            return kindle_convert_ota_update_v2(input, output);
            break;
        case UpdateSignature:
            if(kindle_convert_signature(input, sig_output) < 0)
            {
                fprintf(stderr, "Cannot extract signature file!\n");
                return -1;
            }
            kindle_convert(input, output, sig_output);
            break;
        case OTAUpdate:
            return kindle_convert_ota_update(input, output);
            break;
        case RecoveryUpdate:
            return kindle_convert_recovery(input, output);
            break;
        case UnknownUpdate:
        default:
            break;
    }
    printf("Unknown update bundle version!\n");
    return -1;
}

int kindle_convert_ota_update_v2(FILE *input, FILE *output)
{
    void *data;
    int index;
    uint64_t source_revision;
    uint64_t target_revision;
    uint16_t num_devices;
    uint16_t device;
    //uint16_t *devices;
    uint16_t critical;
    unsigned char *md5_sum;
    uint16_t num_metadata;
    uint16_t metastring_length;
    char *metastring;
    //unsigned char **metastrings;
    
    // First read the set block size and determine how much to resize
    data = malloc(OTA_UPDATE_V2_BLOCK_SIZE * sizeof(char));
    fread(data, sizeof(char), OTA_UPDATE_V2_BLOCK_SIZE, input);
    index = 0;
    
    source_revision = *(uint64_t *)&data[index];
    index += sizeof(uint64_t);
    printf("Minimum OTA    %llu\n", SWAPENDIAN(source_revision));
    target_revision = *(uint64_t *)&data[index];
    index += sizeof(uint64_t);
    printf("Target OTA     %llu\n", SWAPENDIAN(target_revision));
    num_devices = *(uint16_t *)&data[index];
    index += sizeof(uint16_t);
    printf("Devices        %hd\n", SWAPENDIAN(num_devices));
    free(data);
    
    // Now get the data 
    data = malloc(num_devices * sizeof(uint16_t));
    fread(data, sizeof(uint16_t), num_devices, input);
    for(index = 0; index < num_devices * sizeof(uint16_t); index += sizeof(uint16_t))
    {
        device = *(uint16_t *)&data[index];
        printf("Device         %s\n", convert_device_id(SWAPENDIAN(device)));
    }
    free(data);
    
    // Now get second part of set sized data
    data = malloc(OTA_UPDATE_V2_PART_2_BLOCK_SIZE * sizeof(char));
    fread(data, sizeof(char), OTA_UPDATE_V2_PART_2_BLOCK_SIZE, input);
    index = 0;
    
    critical = *(uint16_t *)&data[index];
    index += sizeof(uint16_t);
    printf("Critical       %hd\n", SWAPENDIAN(num_devices));
    md5_sum = &data[index];
    dm(md5_sum, MD5_HASH_LENGTH);
    index += MD5_HASH_LENGTH;
    printf("MD5 Hash       %.*s\n", MD5_HASH_LENGTH, md5_sum);
    num_metadata = *(uint16_t *)&data[index];
    index += sizeof(uint16_t);
    printf("Metadata       %hd\n", SWAPENDIAN(num_metadata));
    free(data);
    
    // Finally, get the metastrings
    for(index = 0; index < num_metadata; index++)
    {
        fread(&metastring_length, sizeof(uint16_t), 1, input);
        metastring = malloc(metastring_length);
        fread(metastring, sizeof(char), metastring_length, input);
        printf("Metastring     %.*s\n", metastring_length, metastring);
        free(metastring);
    }
    
    if(ferror(input) != 0)
    {
        fprintf(stderr, "Cannot read update correctly.\n");
        return -1;
    }
    
    if(output == NULL)
    {
        printf("%s\n", "No output found. Exiting.");
        return 0;
    }
    
    // Now we can decrypt the data
    return demunger(input, output, 0);
}

int kindle_convert_signature(FILE *input, FILE *output)
{
    UpdateSignatureHeader header;
    CertificateNumber cert_num;
    char *cert_name;
    size_t seek;
    unsigned char *signature;
    
    
    if(fread(&header, sizeof(UpdateSignatureHeader), 1, input) < 1 || ferror(input) != 0)
    {
        fprintf(stderr, "Cannot read signature header.\n");
        return -1;
    }
    cert_num = (CertificateNumber)(SWAPENDIAN(header.certificate_number));
    printf("Cert number    %u\n", cert_num);
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
        case CertificateUnknown:
        default:
            fprintf(stderr, "Unknown signature size, cannot continue.\n");
            return -1;
            break;
    }
    printf("Cert file      %s\n", cert_name);
    if(fseek(input, UPDATE_SIGNATURE_BLOCK_SIZE - sizeof(UpdateSignatureHeader), SEEK_CUR) != 0) // Skip useless part of header
    {
        fprintf(stderr, "Cannot read signature header!\n");
        return -1;
    }
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

int kindle_convert_ota_update(FILE *input, FILE *output)
{
    OTAUpdateHeader header;
    
    if(fread(&header, sizeof(OTAUpdateHeader), 1, input) < 1 || ferror(input) != 0)
    {
        fprintf(stderr, "Cannot read OTA header.\n");
        return -1;
    }
    dm(header.md5_sum, MD5_HASH_LENGTH);
    printf("MD5 Hash       %.*s\n", MD5_HASH_LENGTH, header.md5_sum);
    printf("Minimum OTA    %d\n", SWAPENDIAN(header.source_revision));
    printf("Target OTA     %d\n", SWAPENDIAN(header.target_revision));
    printf("Device         %s\n", convert_device_id(SWAPENDIAN(header.device)));
    printf("Optional       %d\n", SWAPENDIAN(header.optional));
    if(fseek(input, OTA_UPDATE_BLOCK_SIZE - sizeof(OTAUpdateHeader), SEEK_CUR) != 0) // Skip useless part of header
    {
        fprintf(stderr, "Cannot read OTA header!\n");
        return -1;
    }
    
    if(output == NULL)
    {
        printf("%s\n", "No output found. Exiting.");
        return 0;
    }
    
    return demunger(input, output, 0);
}

int kindle_convert_recovery(FILE *input, FILE *output)
{
    RecoveryUpdateHeader header;
    
    if(fread(&header, sizeof(RecoveryUpdateHeader), 1, input) < 1 || ferror(input) != 0)
    {
        fprintf(stderr, "Cannot read recovery update header.\n");
        return -1;
    }
    dm(header.md5_sum, MD5_HASH_LENGTH);
    printf("MD5 Hash       %.*s\n", MD5_HASH_LENGTH, header.md5_sum);
    printf("Magic 1        %d\n", SWAPENDIAN(header.magic_1));
    printf("Magic 2        %d\n", SWAPENDIAN(header.magic_2));
    printf("Minor          %d\n", SWAPENDIAN(header.minor));
    printf("Device         %s\n", convert_device_id(SWAPENDIAN(header.device)));
    
    if(fseek(input, RECOVERY_UPDATE_BLOCK_SIZE - sizeof(RecoveryUpdateHeader), SEEK_CUR) != 0)
    {
        fprintf(stderr, "Cannot read recovery update header!\n");
        return -1;
    }
    
    if(output == NULL)
    {
        printf("%s\n", "No output found. Exiting.");
        return 0;
    }
    
    return demunger(input, output, 0);
}
