//
//  extract.c
//  KindleTool
//
//  Created by Yifan Lu on 10/28/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#include "kindle_tool.h"

int gunzip_file(FILE *input, FILE *output)
{
    gzFile gz_input;
    unsigned char buffer[BUFFER_SIZE];
    size_t count;
    
	// open the gzip file
	if((gz_input = gzdopen(fileno(input), "rb")) == NULL)
	{
        fprintf(stderr, "Cannot cannot read compressed input.\n");
        return -1;
	}
    // just to be safe, no compression
    if(gzsetparams(gz_file, Z_NO_COMPRESSION, Z_DEFAULT_STRATEGY) != Z_OK)
    {
        fprintf(stderr, "Cannot set compression level for input.\n");
		gzclose(gz_input);
        return -1;
    }
    // read the input and decompress it
    while((count = (uint32_t)gzread(buffer, sizeof(char), BUFFER_SIZE, gz_input)) > 0)
    {
        if(fwrite(output, buffer, count) != count)
        {
            fprintf(stderr, "Cannot decompress input.\n");
			gzclose(gz_input);
            return -1;
        }
    }
    if(gzerror(gz_input) != 0)
    {
        fprintf(stderr, "Error reading input.\n");
		gzclose(gz_input);
        return -1;
    }
    gzclose(gz_input);
    return 0;
}

int kindle_extract_tar(TAR *input_tar, const char *output_path)
{

}

int kindle_read_bundle_header(UpdateHeader *header, FILE *input)
{
    if(fread(header, sizeof(char), MAGIC_NUMBER_LENGTH, input) < 1 || ferror(input) != 0)
    {
        return -1;
    }
    return 0;
}

int kindle_convert(FILE *input, FILE *output, FILE *sig_output)
{
    UpdateHeader header;
    BundleVersion bundle_version;
    if(kindle_read_bundle_header(&header, input) < 0)
    {
        fprintf(stderr, "Cannot read input file.\n");
        return -1;
    }
    bundle_version = get_bundle_version(header.magic_number);
    switch(bundle_version)
    {
        case OTAUpdateV2:
            return kindle_convert_ota_update_v2(input, output); // no absolutet size, so no struct to pass
            break;
        case UpdateSignature:
            if(kindle_convert_signature(&header, input, sig_output) < 0)
            {
                fprintf(stderr, "Cannot extract signature file!\n");
                return -1;
            }
            kindle_convert(input, output, sig_output);
            break;
        case OTAUpdate:
            return kindle_convert_ota_update(&header, input, output);
            break;
        case RecoveryUpdate:
            return kindle_convert_recovery(&header, input, output);
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
    char *md5_sum;
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
    printf("Minimum OTA    %llu\n", source_revision);
    target_revision = *(uint64_t *)&data[index];
    index += sizeof(uint64_t);
    printf("Target OTA     %llu\n", target_revision);
    num_devices = *(uint16_t *)&data[index];
    index += sizeof(uint16_t);
    printf("Devices        %hd\n", num_devices);
    free(data);
    
    // Now get the data 
    data = malloc(num_devices * sizeof(uint16_t));
    fread(data, sizeof(uint16_t), num_devices, input);
    for(index = 0; index < num_devices * sizeof(uint16_t); index += sizeof(uint16_t))
    {
        device = *(uint16_t *)&data[index];
        printf("Device         %s\n", convert_device_id(device));
    }
    free(data);
    
    // Now get second part of set sized data
    data = malloc(OTA_UPDATE_V2_PART_2_BLOCK_SIZE * sizeof(char));
    fread(data, sizeof(char), OTA_UPDATE_V2_PART_2_BLOCK_SIZE, input);
    index = 0;
    
    critical = *(uint16_t *)&data[index];
    index += sizeof(uint16_t);
    printf("Critical       %hd\n", num_devices);
    md5_sum = &data[index];
    dm((unsigned char*)md5_sum, MD5_HASH_LENGTH);
    index += MD5_HASH_LENGTH;
    printf("MD5 Hash       %.*s\n", MD5_HASH_LENGTH, md5_sum);
    num_metadata = *(uint16_t *)&data[index];
    index += sizeof(uint16_t);
    printf("Metadata       %hd\n", num_metadata);
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

int kindle_convert_signature(UpdateHeader *header, FILE *input, FILE *output)
{
    CertificateNumber cert_num;
    char *cert_name;
    size_t seek;
    unsigned char *signature;
    
    
    if(fread(header->data.signature_header_data, sizeof(char), UPDATE_SIGNATURE_BLOCK_SIZE, input) < UPDATE_SIGNATURE_BLOCK_SIZE)
    {
        fprintf(stderr, "Cannot read signature header.\n");
        return -1;
    }
    cert_num = (CertificateNumber)(header->data.signature.certificate_number);
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
    if(output == NULL)
    {
        return fseek(input, seek, SEEK_CUR);
    }
    else
    {
        signature = malloc(seek);
        if(fread(signature, sizeof(char), seek, input) < seek)
        {
            fprintf(stderr, "Cannot read signature!\n");
            free(signature);
            return -1;
        }
        if(fwrite(signature, sizeof(char), seek, output) < seek)
        {
            fprintf(stderr, "Cannot write signature file!\n");
            free(signature);
            return -1;
        }
    }
    return 0;
}

int kindle_convert_ota_update(UpdateHeader *header, FILE *input, FILE *output)
{
    if(fread(header->data.ota_header_data, sizeof(char), OTA_UPDATE_BLOCK_SIZE, input) < OTA_UPDATE_BLOCK_SIZE)
    {
        fprintf(stderr, "Cannot read OTA header.\n");
        return -1;
    }
    dm((unsigned char*)header->data.ota_update.md5_sum, MD5_HASH_LENGTH);
    printf("MD5 Hash       %.*s\n", MD5_HASH_LENGTH, header->data.ota_update.md5_sum);
    printf("Minimum OTA    %d\n", header->data.ota_update.source_revision);
    printf("Target OTA     %d\n", header->data.ota_update.target_revision);
    printf("Device         %s\n", convert_device_id(header->data.ota_update.device));
    printf("Optional       %d\n", header->data.ota_update.optional);
    
    if(output == NULL)
    {
        printf("%s\n", "No output found. Exiting.");
        return 0;
    }
    
    return demunger(input, output, 0);
}

int kindle_convert_recovery(UpdateHeader *header, FILE *input, FILE *output)
{
    if(fread(header->data.recovery_header_data, sizeof(char), RECOVERY_UPDATE_BLOCK_SIZE, input) < RECOVERY_UPDATE_BLOCK_SIZE)
    {
        fprintf(stderr, "Cannot read recovery update header.\n");
        return -1;
    }
    dm((unsigned char*)header->data.recovery_update.md5_sum, MD5_HASH_LENGTH);
    printf("MD5 Hash       %.*s\n", MD5_HASH_LENGTH, header->data.recovery_update.md5_sum);
    printf("Magic 1        %d\n", header->data.recovery_update.magic_1);
    printf("Magic 2        %d\n", header->data.recovery_update.magic_2);
    printf("Minor          %d\n", header->data.recovery_update.minor);
    printf("Device         %s\n", convert_device_id(header->data.recovery_update.device));
    
    if(output == NULL)
    {
        printf("%s\n", "No output found. Exiting.");
        return 0;
    }
    
    return demunger(input, output, 0);
}
