//
//  extract.c
//  KindleTool
//
//  Created by Yifan Lu on 10/28/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#include "extract.h"

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

int extract(FILE *input, FILE *output, FILE *sig_output)
{
    UpdateHeader abstract_header;
    BundleVersion bundle_version;
    if(read_bundle_header(&abstract_header, input) < 0)
    {
        fprintf(stderr, "Cannot read input file.\n");
        return -1;
    }
    bundle_version = get_bundle_version(abstract_header.magic_number);
    switch(bundle_version)
    {
        case OTAUpdateV2:
            if(extract_ota_update_v2(input, output) < 0)
            {
                fprintf(stderr, "Cannot extract update!\n");
                return -1;
            }
            break;
        case UpdateSignature:
            if(extract_signature(input, sig_output) < 0)
            {
                fprintf(stderr, "Cannot extract signature file!\n");
                return -1;
            }
            extract(input, output, sig_output);
            break;
        case OTAUpdate:
            if(extract_ota_update(input, output) < 0)
            {
                fprintf(stderr, "Cannot extract update!\n");
                return -1;
            }
            break;
        case RecoveryUpdate:
            if(extract_recovery(input, output) < 0)
            {
                fprintf(stderr, "Cannot extract update!\n");
                return -1;
            }
            break;
        case UnknownUpdate:
        default:
            printf("Unknown update bundle version!\n");
            return -1;
            break;
    }
    return 0;
}

int extract_ota_update_v2(FILE *input, FILE *output)
{
    void *data;
    int index;
    unsigned long source_revision;
    unsigned long target_revision;
    unsigned short num_devices;
    unsigned short device;
    //unsigned short *devices;
    unsigned short critical;
    unsigned char *md5_sum;
    unsigned short num_metadata;
    unsigned short metastring_length;
    char *metastring;
    //unsigned char **metastrings;
    
    // First read the set block size and determine how much to resize
    data = malloc(OTA_UPDATE_V2_BLOCK_SIZE * sizeof(char));
    fread(data, sizeof(char), OTA_UPDATE_V2_BLOCK_SIZE, input);
    index = 0;
    
    source_revision = *(unsigned long *)&data[index];
    index += sizeof(unsigned long);
    printf("Minimum OTA    %lu\n", SWAPENDIAN(source_revision));
    target_revision = *(unsigned long *)&data[index];
    index += sizeof(unsigned long);
    printf("Target OTA     %lu\n", SWAPENDIAN(target_revision));
    num_devices = *(unsigned short *)&data[index];
    index += sizeof(unsigned short);
    printf("Devices        %hd\n", SWAPENDIAN(num_devices));
    free(data);
    
    // Now get the data 
    data = malloc(num_devices * sizeof(unsigned short));
    fread(data, sizeof(unsigned short), num_devices, input);
    for(index = 0; index < num_devices * sizeof(unsigned short); index += sizeof(unsigned short))
    {
        device = *(unsigned short *)&data[index];
        printf("Device         %s\n", convert_device_id(SWAPENDIAN(device)));
    }
    free(data);
    
    // Now get second part of set sized data
    data = malloc(OTA_UPDATE_V2_PART_2_BLOCK_SIZE * sizeof(char));
    fread(data, sizeof(char), OTA_UPDATE_V2_PART_2_BLOCK_SIZE, input);
    index = 0;
    
    critical = *(unsigned short *)&data[index];
    index += sizeof(unsigned short);
    printf("Critical       %hd\n", SWAPENDIAN(num_devices));
    md5_sum = &data[index];
    dm(md5_sum, MD5_HASH_LENGTH);
    index += MD5_HASH_LENGTH;
    printf("MD5 Hash       %.*s\n", MD5_HASH_LENGTH, md5_sum);
    num_metadata = *(unsigned short *)&data[index];
    index += sizeof(unsigned short);
    printf("Metadata       %hd\n", SWAPENDIAN(num_metadata));
    free(data);
    
    // Finally, get the metastrings
    for(index = 0; index < num_metadata; index++)
    {
        fread(&metastring_length, sizeof(unsigned short), 1, input);
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
    
    // Now we can decrypt the data
    return demunger(input, output, 0);
}

int extract_signature(FILE *input, FILE *output)
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

int extract_ota_update(FILE *input, FILE *output)
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
    
    return demunger(input, output, 0);
}

int extract_recovery(FILE *input, FILE *output)
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
    return demunger(input, output, 0);
}
