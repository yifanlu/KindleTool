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
        case Kindle5Touch:
            return "Kindle 5 Touch";
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

int kindle_print_help()
{
    return 0;
}

int kindle_deobfuscate_main(int argc, const char *argv[])
{
    FILE *input;
    FILE *output;
    input = stdin;
    output = stdout;
    if(argc > 1)
    {
        if((output = fopen(argv[1], "wb")) == NULL)
        {
            fprintf(stderr, "Cannot open output for writing.\n");
            return -1;
        }
    }
    if(argc > 0)
    {
        if((input = fopen(argv[0], "rb")) == NULL)
        {
            fprintf(stderr, "Cannot open input for reading.\n");
            return -1;
        }
    }
    return munger(input, output, 0);
}

int kindle_obfuscate_main(int argc, const char *argv[])
{
    FILE *input;
    FILE *output;
    input = stdin;
    output = stdout;
    if(argc > 1)
    {
        if((output = fopen(argv[1], "wb")) == NULL)
        {
            fprintf(stderr, "Cannot open output for writing.\n");
            return -1;
        }
    }
    if(argc > 0)
    {
        if((input = fopen(argv[0], "rb")) == NULL)
        {
            fprintf(stderr, "Cannot open input for reading.\n");
            return -1;
        }
    }
    return demunger(input, output, 0);
}

int kindle_convert_main(int argc, const char *argv[])
{
    static const struct option opts[] = {
        { "stdout", no_argument, NULL, 'c' },
        { "info", no_argument, NULL, 'i' },
        { "sig", required_argument, NULL, 's' }
    };
    int opt;
    int opt_index;
    FILE *input;
    FILE *output;
    FILE *sig_output;
    const char *in_name;
    char *out_name;

    
    if(argc < 1)
    {
        fprintf(stderr, "No input specified.\n");
        return -1;
    }
    in_name = argv[0];
    out_name = malloc(strlen(in_name) + 7);
    strcpy(out_name, in_name);
    strcat(out_name, ".tar.gz");
    if((input = fopen(in_name, "rb")) == NULL)
    {
        fprintf(stderr, "Cannot open input for reading.\n");
        free(out_name);
        return -1;
    }
    if((output = fopen(out_name, "wb")) == NULL)
    {
        fprintf(stderr, "Cannot open output for writing.\n");
        free(out_name);
        return -1;
    }
    sig_output = NULL;
    while((opt = getopt_long(argc, (char **)argv, "ics:", opts, &opt_index)) != -1)
    {
        switch(opt)
        {
            case 'i':
                output = NULL;
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
            default:
                break;
        }
    }
    if(kindle_convert(input, output, sig_output) < 0)
    {
        fprintf(stderr, "Error converting update.\n");
        free(out_name);
        return -1;
    }
    if(output != stdout)
        remove(in_name);
    free(out_name);
    return 0;
}

int main (int argc, const char * argv[])
{
    if(argc < 2 || strncmp(argv[0], "help", 4) == 0)
        return kindle_print_help();
    if(strncmp(argv[0], "dm", 2) == 0)
        return kindle_deobfuscate_main(argc--, (&argv)[1]);
    if(strncmp(argv[0], "md", 2) == 0)
        return kindle_obfuscate_main(argc--, (&argv)[1]);
    if(strncmp(argv[0], "convert", 2) == 0)
        return kindle_convert_main(argc--, (&argv)[1]);
}
