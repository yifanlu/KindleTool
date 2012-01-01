//
//  main.c
//  KindleTool
//
//  Created by Yifan Lu on 10/26/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#include "kindle_tool.h"

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
	unsigned char bytes[BUFFER_SIZE];
	size_t bytes_read;
	size_t bytes_written;
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
	unsigned char bytes[BUFFER_SIZE];
	size_t bytes_read;
	size_t bytes_written;
	while((bytes_read = fread(bytes, sizeof(char), (length < BUFFER_SIZE && length > 0 ? length : BUFFER_SIZE), input)) > 0)
	{
		dm(bytes, bytes_read);
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

int md5_sum(FILE *input, char output_string[MD5_DIGEST_LENGTH*2+1])
{
    unsigned char bytes[BUFFER_SIZE];
    size_t bytes_read;
    MD5_CTX md5;
    unsigned char output[MD5_DIGEST_LENGTH];
    int i;
    
    MD5_Init(&md5);
    while((bytes_read = fread(bytes, sizeof(char), BUFFER_SIZE, input)) > 0)
    {
        MD5_Update(&md5, bytes, bytes_read);
    }
    if(ferror(input) != 0)
    {
		fprintf(stderr, "Error reading input.\n");
		return -1;
    }
    MD5_Final(output, &md5);
    for(i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        sprintf(output_string+(i*2), "%02x", output[i]);
    }
    output_string[MD5_DIGEST_LENGTH*2] = 0;
    return 0;
}

RSA *get_default_key()
{
    static RSA *rsa_pkey = NULL;
    BIO *bio;
    if(rsa_pkey == NULL)
    {
        bio = BIO_new_mem_buf((void*)SIGN_KEY, -1);
        if(PEM_read_bio_RSAPrivateKey(bio, &rsa_pkey, NULL, NULL) == NULL)
        {
            fprintf(stderr, "Error loading RSA Private Key File\n");
            return NULL;
        }
    }
    return rsa_pkey;
}

int main (int argc, const char * argv[])
{
    const char *dirname = "/Users/yifanlu/Downloads/testupdate";
    const char *tarname = "/Users/yifanlu/Downloads/testupdate.tar";
    //BIO *in = BIO_new_file("/Users/yifanlu/Downloads/key.pem", "r");
    kindle_create_tar_from_directory(dirname, tarname, get_default_key());
    return 0;
    /*
    FILE *input, *output, *output_sig;
    input = fopen("/Users/yifanlu/Development/Other/kindle-touch-usbnet/installer.tgz", "r");
    output = fopen("/Users/yifanlu/Development/Other/kindle-touch-usbnet/installer.bin", "w");
    munger(input, output, 0);
    return 0;
    
    // Test OTA Update
    input = fopen("/Users/yifanlu/Downloads/Update_kindle_3.3_B006.bin", "r");
    output = fopen("/Users/yifanlu/Downloads/Update_kindle_3.3_B006.tgz", "w");
    output_sig = fopen("/Users/yifanlu/Downloads/Update_kindle_3.3_B006.tgz.sig", "w");
    extract(input, output, output_sig);
    // Test Manual Update
    input = fopen("/Users/yifanlu/Development/Other/update_kindle_3.2.1.bin", "r");
    output = fopen("/Users/yifanlu/Downloads/update_kindle_3.2.1.tgz", "w");
    output_sig = fopen("/Users/yifanlu/Downloads/update_kindle_3.2.1.tgz.sig", "w");
    extract(input, output, output_sig);
    // Test V2 OTA Update
    input = fopen("/Users/yifanlu/Downloads/Update_Kindle_4.0.1_B00E.bin", "r");
    output = fopen("/Users/yifanlu/Downloads/Update_Kindle_4.0.1_B00E.tgz", "w");
    output_sig = fopen("/Users/yifanlu/Downloads/Update_Kindle_4.0.1_B00E.tgz.sig", "w");
    extract(input, output, output_sig);
     return 0;
     */
}
