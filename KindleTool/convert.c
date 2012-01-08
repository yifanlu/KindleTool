//
//  extract.c
//  KindleTool
//
//  Copyright (C) 2011  Yifan Lu
//  
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//  
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//  
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

#include "kindle_tool.h"

FILE *gunzip_file(FILE *input)
{
    FILE *output;
    gzFile gz_input;
    unsigned char buffer[BUFFER_SIZE];
    size_t count;
    
    // create a temporary file and open
    if((output = tmpfile()) == NULL)
    {
        fprintf(stderr, "Cannot create gunzip output.\n");
        return NULL;
    }
    // open the gzip file
    if((gz_input = gzdopen(fileno(input), "rb")) == NULL)
    {
        fprintf(stderr, "Cannot read compressed input.\n");
        return NULL;
    }
    // read the input and decompress it
    while((count = (uint32_t)gzread(gz_input, buffer, BUFFER_SIZE)) > 0)
    {
        if(fwrite(buffer, sizeof(char), BUFFER_SIZE, output) != count)
        {
            fprintf(stderr, "Cannot decompress input.\n");
			gzclose(gz_input);
            return NULL;
        }
    }
    gzclose(gz_input);
    rewind(output);
    return output;
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
    fprintf(stderr, "Bundle         %s\n", header.magic_number);
    bundle_version = get_bundle_version(header.magic_number);
    switch(bundle_version)
    {
        case OTAUpdateV2:
            fprintf(stderr, "Bundle Type    %s\n", "OTA V2");
            return kindle_convert_ota_update_v2(input, output); // no absolutet size, so no struct to pass
            break;
        case UpdateSignature:
            if(kindle_convert_signature(&header, input, sig_output) < 0)
            {
                fprintf(stderr, "Cannot extract signature file!\n");
                return -1;
            }
            return kindle_convert(input, output, sig_output);
            break;
        case OTAUpdate:
            fprintf(stderr, "Bundle Type    %s\n", "OTA V1");
            return kindle_convert_ota_update(&header, input, output);
            break;
        case RecoveryUpdate:
            fprintf(stderr, "Bundle Type    %s\n", "Recovery");
            return kindle_convert_recovery(&header, input, output);
            break;
        case UnknownUpdate:
        default:
            fprintf(stderr, "Unknown update bundle version!\n");
            break;
    }
    return -1; // if we get here, there has been an error
}

int kindle_convert_ota_update_v2(FILE *input, FILE *output)
{
    char *data;
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
    fprintf(stderr, "Minimum OTA    %llu\n", source_revision);
    target_revision = *(uint64_t *)&data[index];
    index += sizeof(uint64_t);
    fprintf(stderr, "Target OTA     %llu\n", target_revision);
    num_devices = *(uint16_t *)&data[index];
    index += sizeof(uint16_t);
    fprintf(stderr, "Devices        %hd\n", num_devices);
    free(data);
    
    // Now get the data 
    data = malloc(num_devices * sizeof(uint16_t));
    fread(data, sizeof(uint16_t), num_devices, input);
    for(index = 0; index < num_devices * sizeof(uint16_t); index += sizeof(uint16_t))
    {
        device = *(uint16_t *)&data[index];
        fprintf(stderr, "Device         %s\n", convert_device_id(device));
    }
    free(data);
    
    // Now get second part of set sized data
    data = malloc(OTA_UPDATE_V2_PART_2_BLOCK_SIZE * sizeof(char));
    fread(data, sizeof(char), OTA_UPDATE_V2_PART_2_BLOCK_SIZE, input);
    index = 0;
    
    critical = *(uint16_t *)&data[index];
    index += sizeof(uint16_t);
    fprintf(stderr, "Critical       %hd\n", critical);
    md5_sum = &data[index];
    dm((unsigned char*)md5_sum, MD5_HASH_LENGTH);
    index += MD5_HASH_LENGTH;
    fprintf(stderr, "MD5 Hash       %.*s\n", MD5_HASH_LENGTH, md5_sum);
    num_metadata = *(uint16_t *)&data[index];
    index += sizeof(uint16_t);
    fprintf(stderr, "Metadata       %hd\n", num_metadata);
    free(data);
    
    // Finally, get the metastrings
    for(index = 0; index < num_metadata; index++)
    {
        fread(&metastring_length, sizeof(uint16_t), 1, input);
        metastring = malloc(metastring_length);
        fread(metastring, sizeof(char), metastring_length, input);
        fprintf(stderr, "Metastring     %.*s\n", metastring_length, metastring);
        free(metastring);
    }
    
    if(ferror(input) != 0)
    {
        fprintf(stderr, "Cannot read update correctly.\n");
        return -1;
    }
    
    if(output == NULL)
    {
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
    fprintf(stderr, "Cert number    %u\n", cert_num);
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
    fprintf(stderr, "Cert file      %s\n", cert_name);
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
    fprintf(stderr, "MD5 Hash       %.*s\n", MD5_HASH_LENGTH, header->data.ota_update.md5_sum);
    fprintf(stderr, "Minimum OTA    %d\n", header->data.ota_update.source_revision);
    fprintf(stderr, "Target OTA     %d\n", header->data.ota_update.target_revision);
    fprintf(stderr, "Device         %s\n", convert_device_id(header->data.ota_update.device));
    fprintf(stderr, "Optional       %d\n", header->data.ota_update.optional);
    
    if(output == NULL)
    {
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
    fprintf(stderr, "MD5 Hash       %.*s\n", MD5_HASH_LENGTH, header->data.recovery_update.md5_sum);
    fprintf(stderr, "Magic 1        %d\n", header->data.recovery_update.magic_1);
    fprintf(stderr, "Magic 2        %d\n", header->data.recovery_update.magic_2);
    fprintf(stderr, "Minor          %d\n", header->data.recovery_update.minor);
    fprintf(stderr, "Device         %s\n", convert_device_id(header->data.recovery_update.device));
    
    if(output == NULL)
    {
        return 0;
    }
    
    return demunger(input, output, 0);
}

int kindle_convert_main(int argc, char *argv[])
{
    int opt;
    int opt_index;
    static const struct option opts[] = {
        { "stdout", no_argument, NULL, 'c' },
        { "info", no_argument, NULL, 'i' },
        { "sig", required_argument, NULL, 's' }
    };
    FILE *input;
    FILE *output;
    FILE *sig_output;
    const char *in_name;
    char *out_name;
    int info_only;

    sig_output = NULL;
    out_name = NULL;
    output = NULL;
    info_only = 0;
    optind = -1; // hack to get around the fact that we skipped some arguments
    while((opt = getopt_long(argc, argv, "ics:", opts, &opt_index)) != -1)
    {
        switch(opt)
        {
            case 'i':
                info_only = 1;
                break;
            case 'c':
                output = stdout;
                break;
            case 's':
                if((sig_output = fopen(optarg, "wb")) == NULL)
                {
                    fprintf(stderr, "Cannot open signature output for writing.\n");
                    free(out_name);
                    return -1;
                }
                break;
            default:
                break;
        }
    }
    if(argc < 1)
    {
        fprintf(stderr, "No input specified.\n");
        fclose(sig_output);
        return -1;
    }
    argc -= (optind-1); argv += optind; // next argument
    in_name = argv[0];
    if(!info_only && output == NULL) // not info AND not stdout
    {
        out_name = malloc(strlen(in_name) + 7);
        strcpy(out_name, in_name);
        strcat(out_name, ".tar.gz");
        if((output = fopen(out_name, "wb")) == NULL)
        {
            fprintf(stderr, "Cannot open output for writing.\n");
            free(out_name);
            fclose(sig_output);
            return -1;
        }
    }
    if((input = fopen(in_name, "rb")) == NULL)
    {
        fprintf(stderr, "Cannot open input for reading.\n");
        free(out_name);
        fclose(sig_output);
        fclose(output);
        return -1;
    }
    if(kindle_convert(input, output, sig_output) < 0)
    {
        fprintf(stderr, "Error converting update.\n");
        remove(out_name); // clean up our mess
        free(out_name);
        fclose(sig_output);
        fclose(output);
        fclose(input);
        return -1;
    }
    if(output != stdout && !info_only) // if output was some file, delete the original
        remove(in_name);
    free(out_name);
    fclose(sig_output);
    fclose(output);
    fclose(input);
    return 0;
}

int kindle_extract_main(int argc, char *argv[])
{
    FILE *bin_input;
    FILE *gz_output;
    FILE *tar_input;
    TAR *tar;
    
    if(argc < 2)
    {
	fprintf(stderr, "Invalid number of arguments.\n");
	return -1;
    }
    if((bin_input = fopen(argv[0], "rb")) == NULL)
    {
	fprintf(stderr, "Cannot open update input.\n");
	return -1;
    }
    if((gz_output = tmpfile()) == NULL)
    {
        fprintf(stderr, "Cannot create temporary file.\n");
        fclose(bin_input);
        return -1;
    }
    if(kindle_convert(bin_input, gz_output, NULL) < 0)
    {
        fprintf(stderr, "Error converting update.\n");
        fclose(bin_input);
        fclose(gz_output);
        return -1;
    }
    rewind(gz_output);
    if((tar_input = gunzip_file(gz_output)) == NULL)
    {
        fprintf(stderr, "Error decompressing update.\n");
        fclose(bin_input);
        fclose(gz_output);
        return -1;
    }
    if(tar_fdopen(&tar, fileno(tar_input), NULL, NULL, O_RDONLY, 0644, TAR_GNU) < 0)
    {
        fprintf(stderr, "Error opening update tar.\n");
        fclose(bin_input);
        fclose(gz_output);
        fclose(tar_input);
        return -1;
    }
    if(tar_extract_all(tar, argv[1]) < 0)
    {
        fprintf(stderr, "Error extracting tar.\n");
        tar_close(tar);
        fclose(bin_input);
        fclose(gz_output);
        fclose(tar_input);
        return -1;
    }
    tar_close(tar);
    fclose(bin_input);
    fclose(gz_output);
    fclose(tar_input);
    return 0;
}
