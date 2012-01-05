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
        case Kindle5TouchWifi:
            return "Kindle 5 Touch Wifi";
        case Kindle5TouchWifi3G:
            return "Kindle 5 Touch Wifi+3G";
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

int md5_sum(FILE *input, char output_string[MD5_HASH_LENGTH])
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

int kindle_print_help(const char *prog_name)
{
    return 0;
}

int kindle_deobfuscate_main(int argc, char *argv[])
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

int kindle_obfuscate_main(int argc, char *argv[])
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
    while((opt = getopt_long(argc, argv, "ics:", opts, &opt_index)) != -1)
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

int kindle_create_main(int argc, char *argv[])
{
    static char *temp_name;
    int opt;
    int opt_index;
    static const struct option opts[] = {
        { "device", required_argument, NULL, 'd' },
        { "key", required_argument, NULL, 'k' },
        { "bundle", required_argument, NULL, 'b' },
        { "srcrev", required_argument, NULL, 's' },
        { "tgtrev", required_argument, NULL, 't' },
        { "magic1", required_argument, NULL, '1' },
        { "magic2", required_argument, NULL, '2' },
        { "minor", required_argument, NULL, 'm' },
        { "cert", required_argument, NULL, 'c' },
        { "opt", required_argument, NULL, 'o' },
        { "crit", required_argument, NULL, 'r' },
        { "meta", required_argument, NULL, 's' }
    };
    UpdateInformation info = {"\0\0\0\0", UnknownUpdate, get_default_key(), 0, 0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0, NULL, CertificateDeveloper, 0, 0, 0, NULL };
    struct stat st_buf;
    FILE *input;
    FILE *temp;
    FILE *output;
    BIO *bio;
    int i;
    
    // defaults
    output = stdout;
    input = NULL;
    temp = NULL;
    if(temp_name == NULL)
        temp_name = tmpnam(temp_name);
    // update type
    if(argc < 2)
    {
        fprintf(stderr, "Not enough arguments");
        return -1;
    }
    if(strncmp(argv[0], "ota", 3) == 0)
    {
        info.version = OTAUpdate;
        strncpy(info.magic_number, "FB02", 4);
    }
    else if(strncmp(argv[0], "ota2", 4) == 0)
    {
        info.version = OTAUpdateV2;
    }
    else if(strncmp(argv[0], "recovery", 8) == 0)
    {
        info.version = RecoveryUpdate;
        strncpy(info.magic_number, "FC02", 4);
    }
    else
    {
        fprintf(stderr, "Invalid update type.");
        return -1;
    }
    argc--; argv++; // next argument
    // arguments
    while((opt = getopt_long(argc, argv, "d:k:b:s:t:1:2:m:c:o:r:x:", opts, &opt_index)) != -1)
    {
        switch(opt)
        {
            case 'd':
                info.devices = realloc(info.devices, ++info.num_devices * sizeof(Device));
                if(strncmp(optarg, "k1", 2) == 0)
                    info.devices[info.num_devices-1] = Kindle1;
                else if(strncmp(optarg, "k2", 2) == 0)
                    info.devices[info.num_devices-1] = Kindle2US;
                else if(strncmp(optarg, "k2i", 3) == 0)
                    info.devices[info.num_devices-1] = Kindle2International;
                else if(strncmp(optarg, "dx", 2) == 0)
                    info.devices[info.num_devices-1] = KindleDXUS;
                else if(strncmp(optarg, "dxi", 3) == 0)
                    info.devices[info.num_devices-1] = KindleDXInternational;
                else if(strncmp(optarg, "dxg", 3) == 0)
                    info.devices[info.num_devices-1] = KindleDXGraphite;
                else if(strncmp(optarg, "k3w", 3) == 0)
                    info.devices[info.num_devices-1] = Kindle3Wifi;
                else if(strncmp(optarg, "k3g", 2) == 0)
                    info.devices[info.num_devices-1] = Kindle3Wifi3G;
                else if(strncmp(optarg, "k3gb", 3) == 0)
                    info.devices[info.num_devices-1] = Kindle3Wifi3GEurope;
                else if(strncmp(optarg, "k4", 2) == 0)
                {
                    info.devices[info.num_devices-1] = Kindle4NonTouch;
                    strncpy(info.magic_number, "FC04", 4);
                }
                else if(strncmp(optarg, "k5w", 3) == 0)
                {
                    info.devices[info.num_devices-1] = Kindle5TouchWifi;
                    strncpy(info.magic_number, "FD04", 4);
                }
                else if(strncmp(optarg, "k5g", 2) == 0)
                {
                    info.devices[info.num_devices-1] = Kindle5TouchWifi3G;
                    strncpy(info.magic_number, "FD04", 4);
                }
                else
                {
                    info.num_devices--;
                    fprintf(stderr, "Unknown device %s, ignoring.\n", optarg);
                }
                break;
            case 'k':
                if((bio = BIO_new_file(optarg, "rb")) == NULL || PEM_read_bio_RSAPrivateKey(bio, &info.sign_pkey, NULL, NULL) == NULL)
                {
                    fprintf(stderr, "Key %s cannot be loaded.\n", optarg);
                    goto do_error;
                }
                break;
            case 'b':
                strncpy(info.magic_number, optarg, 4);
                break;
            case 's':
                info.source_revision = atol(optarg);
                break;
            case 't':
                info.target_revision = atol(optarg);
                break;
            case '1':
                info.magic_1 = atoi(optarg);
                break;
            case '2':
                info.magic_2 = atoi(optarg);
                break;
            case 'm':
                info.minor = atoi(optarg);
                break;
            case 'c':
                info.certificate_number = (CertificateNumber)atoi(optarg);
                break;
            case 'o':
                info.optional = (uint16_t)atoi(optarg);
                break;
            case 'r':
                info.critical = (uint16_t)atoi(optarg);
                break;
            case 'x':
                info.metastrings = realloc(info.metastrings, ++info.num_meta * sizeof(char*));
                info.metastrings[info.num_meta-1] = strdup(optarg);
                break;
        }
    }
    // validation
    if(info.num_devices < 1 || (info.version != OTAUpdateV2 && info.num_devices > 1))
    {
        fprintf(stderr, "Invalid number of supported devices, %d, for this update type.\n", info.num_devices);
        goto do_error;
    }
    argc -= (optind-1); argv += optind; // next argument
    // input
    if(argc < 1)
    {
        fprintf(stderr, "No input found.\n");
        goto do_error;
    }
    if(stat(argv[0], &st_buf) != 0)
    {
        fprintf(stderr, "Cannot read input.\n");
        goto do_error;
    }
    if(S_ISDIR (st_buf.st_mode))
    {
        // input is a directory
        if(kindle_create_tar_from_directory(argv[0], temp_name, info.sign_pkey) < 0 || (temp = fopen(temp_name, "rb")) == NULL)
        {
            fprintf(stderr, "Cannot create archive.\n");
            goto do_error;
        }
        if((input = gzip_file(temp)) == NULL)
        {
            fprintf(stderr, "Cannot compress archive.\n");
            goto do_error;
        }
    }
    else
    {
        // input is a file
        if((input = fopen(argv[0], "rb")) == NULL)
        {
            fprintf(stderr, "Cannot read input.\n");
            goto do_error;
        }
    }
    argc--; argv++; // next argument
    // output
    if(argc > 0)
    {
        if((output = fopen(argv[0], "wb")) == NULL)
        {
            fprintf(stderr, "Cannot create output.\n");
            goto do_error;
        }
    }
    return 0;
do_error:
    free(info.devices);
    for(i = 0; i < info.num_meta; i++)
        free(info.metastrings[i]);
    free(info.metastrings);
    return -1;
}

int main (int argc, char *argv[])
{
    char *prog_name;
    prog_name = argv[0];
    argc--; argv++; // discard program name for easier parsing
    if(argc < 2 || strncmp(argv[0], "help", 4) == 0)
        return kindle_print_help(prog_name);
    if(strncmp(argv[0], "dm", 2) == 0)
        return kindle_deobfuscate_main(argc--, argv++);
    if(strncmp(argv[0], "md", 2) == 0)
        return kindle_obfuscate_main(argc--,argv++);
    if(strncmp(argv[0], "convert", 2) == 0)
        return kindle_convert_main(argc--, argv++);
    if(strncmp(argv[0], "create", 6) == 0)
        return kindle_create_main(argc, argv++);
}
