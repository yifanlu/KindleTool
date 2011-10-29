//
//  extract.c
//  KindleTool
//
//  Created by Yifan Lu on 10/28/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#include "extract.h"

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
            break;
        case UnknownUpdate:
        default:
            printf("Unknown update bundle version!\n");
            return -1;
            break;
    }
    return 0;
}

int extract_ota_update_v2(FILE *input, FILE *output, UpdateHeader *abstract_header)
{
    OTAUpdateV2Header *header;
    
    header = (OTAUpdateV2Header*)abstract_header;
    
    return demunger(input, output, 0);
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
        default:
            fprintf(stderr, "Unknown signature size, cannot continue.\n");
            return -1;
            break;
    }
    printf("Cert file      %s\n", cert_name);
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

int extract_ota_update(FILE *input, FILE *output, UpdateHeader *abstract_header)
{
    OTAUpdateHeader *header;
    
    header = (OTAUpdateHeader*)abstract_header;
    dm(header->md5_sum, MD5_HASH_LENGTH);
    printf("MD5 Hash       %.*s\n", MD5_HASH_LENGTH, header->md5_sum);
    printf("Minimum OTA    %d\n", SWAPENDIAN(header->source_revision));
    printf("Target OTA     %d\n", SWAPENDIAN(header->target_revision));
    printf("Device         %s\n", convert_device_id(SWAPENDIAN(header->device)));
    printf("Optional       %d\n", SWAPENDIAN(header->optional));
    
    return demunger(input, output, 0);
}

int extract_recovery(FILE *input, FILE *output, UpdateHeader *abstract_header)
{
    RecoveryUpdateHeader *header;
    
    header = (RecoveryUpdateHeader*)abstract_header;
    dm(header->update_header.md5_sum, MD5_HASH_LENGTH);
    printf("MD5 Hash       %.*s\n", MD5_HASH_LENGTH, header->update_header.md5_sum);
    printf("Magic 1        %d\n", SWAPENDIAN(header->magic_1));
    printf("Magic 2        %d\n", SWAPENDIAN(header->magic_2));
    printf("Minor          %d\n", SWAPENDIAN(header->minor));
    printf("Device         %s\n", convert_device_id(SWAPENDIAN(header->device)));
    
    if(fseek(input, RECOVERY_UPDATE_BLOCK_SIZE - OTA_UPDATE_BLOCK_SIZE, SEEK_CUR) != 0)
    {
        fprintf(stderr, "Cannot read recovery update!\n");
        return -1;
    }
    return demunger(input, output, 0);
}
