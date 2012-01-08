//
//  main.c
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
    char output_string_temp[MD5_HASH_LENGTH+1]; // sprintf adds trailing null, we do not want that!
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
        sprintf(output_string_temp+(i*2), "%02x", output[i]);
    }
    memcpy(output_string, output_string_temp, MD5_HASH_LENGTH); // remove the trailing null. any better way to do this?
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
    printf(
           "usage:\n"
           "  %s dm [ <input> ] [ <output> ]\n"
           "    Obfuscates data using Amazon's update algorithm.\n"
           "    If no input is provided, input from stdin\n"
           "    If no output is provided, output to stdout\n"
           "    \n"
           "  %s md [ <input> ] [ <output> ]\n"
           "    Deobfuscates data using Amazon's update algorithm.\n"
           "    If no input is provided, input from stdin\n"
           "    If no output is provided, output to stdout\n"
           "    \n"
           "  %s convert [options] <input>\n"
           "    Converts a Kindle update package to a gzipped TAR file, and delete input\n"
           "    \n"
           "    Options:\n"
           "      -c, --stdout                Write to standard output, keeping original files unchanged\n"
           "      -i, --info                  Just print the package information, no conversion done\n"
           "      -s, --sig <output>          OTA V2 updates only. Extract the package signature to <output> file.\n"
           "      \n"
           "  %s extract <input> <output>\n"
           "    Extracts a Kindle update package to a directory\n"
           "    \n"
           "  %s create <type> <devices> [options] <dir|file> [ <output> ]\n"
           "    Creates a Kindle update package\n"
           "    If input is a directory, all files in it will be packed into an update\n"
           "    If input is a GZIP file, it will be converted to an update.\n"
           "    If no output is provided, output to stdout.\n"
           "    In case of OTA updates, all files with the extension \".ffs\" and will be treated as update scripts\n"
           "    \n"
           "    Type:\n"
           "      ota                         OTA V1 update package. Works on Kindle 3.0 and below.\n"
           "      ota2                        OTA V2 signed update package. Works on Kindle 4.0 and up.\n"
           "      recovery                    Recovery package for restoring partitions.\n"
           "    \n"
           "    Devices:\n"
           "      OTA V1 packages only support one device. OTA V2 packages can support multiple devices.\n"
           "      \n"
           "      -d, --device k1             Kindle 1\n"
           "      -d, --device k2             Kindle 2 US\n"
           "      -d, --device k2i            Kindle 2 International\n"
           "      -d, --device dx             Kindle DX US\n"
           "      -d, --device dxi            Kindle DX International\n"
           "      -d, --device dxg            Kindle DX Graphite\n"
           "      -d, --device k3w            Kindle 3 Wifi\n"
           "      -d, --device k3g            Kindle 3 Wifi+3G\n"
           "      -d, --device k3gb           Kindle 3 Wifi+3G Europe\n"
           "      -d, --device k4             Kindle 4 (No Touch)\n"
           "      -d, --device k5w            Kindle 5 (Kindle Touch) Wifi\n"
           "      -d, --device k5g            Kindle 5 (Kindle Touch) Wifi+3G\n"
           "      \n"
           "    Options:\n"
           "      All the following options are optional and advanced.\n"
           "      -k, --key <file>            PEM file containing RSA private key to sign update. Default is popular jailbreak key.\n"
           "      -b, --bundle <type>         Manually specify package magic number. Overrides \"type\". Valid bundle versions:\n"
           "                                    FB01, FB02 = recovery; FC02, FD03 = ota; FC04, FD04, FL01 = ota2\n"
           "      -s, --srcrev <ulong|uint>   OTA updates only. Source revision. OTA V1 uses uint, OTA V2 uses ulong.\n"
           "                                    Lowest version of device that package supports. Default is 0.\n"
           "      -t, --tgtrev <ulong|uint>   OTA updates only. Target revision. OTA V1 uses uint, OTA V2 uses ulong.\n"
           "                                    Highest version of device that package supports. Default is max int value.\n"
           "      -1, --magic1 <uint>         Recovery updates only. Magic number 1. Default is 0.\n"
           "      -2, --magic2 <uint>         Recovery updates only. Magic number 2. Default is 0.\n"
           "      -m, --minor <uint>          Recovery updates only. Minor number. Default is 0.\n"
           "      -c, --cert <ushort>         OTA V2 updates only. The number of the certificate to use (found in /etc/uks on device). Default is 0.\n"
           "                                    0 = pubdevkey01.pem, 1 = pubprodkey01.pem, 2 = pubprodkey02.pem\n"
           "      -o, --opt <uchar>           OTA V1 updates only. One byte optional data expressed as a number. Default is 0.\n"
           "      -r, --crit <uchar>          OTA V2 updates only. One byte optional data expressed as a number. Default is 0.\n"
           "      -x, --meta <str>            OTA V2 updates only. An optional string to add. Multiple \"--meta\" options supported.\n"
           "                                    Format of metastring must be: key=value\n"
           "      \n"
           "  %s info <serialno>\n"
           "    Get the default root password\n"
           "    \n"
           "notices:\n"
           "  1)  Kindle 4.0+ has a known bug that prevents some updates with meta-strings to run.\n"
           "  2)  Currently, even though OTA V2 supports updates that run on multiple devices, it is not possible to create a update package that will run on both the Kindle 4 (No Touch) and Kindle 5 (Kindle Touch).\n"
           , prog_name, prog_name, prog_name, prog_name, prog_name, prog_name);
    return 0;
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
            fclose(output);
            return -1;
        }
    }
    if(demunger(input, output, 0) < 0)
    {
        fprintf(stderr, "Cannot obfuscate.\n");
        fclose(input);
        fclose(output);
        return -1;
    }
    fclose(input);
    fclose(output);
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
            fclose(output);
            return -1;
        }
    }
    if(munger(input, output, 0) < 0)
    {
        fprintf(stderr, "Cannot deobfuscate.\n");
        fclose(input);
        fclose(output);
        return -1;
    }
    fclose(input);
    fclose(output);
    return 0;
}

int kindle_info_main(int argc, char *argv[])
{
    char *serial_no;
    char md5[MD5_HASH_LENGTH];
    FILE *temp;
    int i;
    if(argc < 1)
    {
        fprintf(stderr, "No serial number found in input.\n");
        return -1;
    }
    serial_no = argv[0];
    temp = tmpfile();
    if(strlen(serial_no) != SERIAL_NO_LENGTH)
    {
        fprintf(stderr, "Serial number must be 16 digits long (no spaces). Example: %s\n", "B00XXXXXXXXXXXXX");
        return -1;
    }
    for(i = 0; i < SERIAL_NO_LENGTH; i++)
    {
        if(islower(serial_no[i]))
        {
            serial_no[i] = toupper(serial_no[i]);
        }
    }
    // find root password
    if(fprintf(temp, "%s\n", serial_no) < SERIAL_NO_LENGTH)
    {
        fprintf(stderr, "Cannot write serial to temporary file.\n");
        fclose(temp);
        return -1;
    }
    rewind(temp);
    if(md5_sum(temp, md5) < 0)
    {
        fprintf(stderr, "Cannot calculate MD5 of serial number.\n");
        fclose(temp);
        return -1;
    }
    fprintf(stderr, "Root PW        %s%.*s\n", "fiona", 4, &md5[7]);
    fclose(temp);
    return 0;
}

int main (int argc, char *argv[])
{
    char *prog_name;
    prog_name = argv[0];
    argc--; argv++; // discard program name for easier parsing
    if(freopen(NULL, "rb", stdin) == NULL)
    {
        fprintf(stderr, "Cannot set stdin to binary mode.\n");
        return -1;
    }
    if(freopen(NULL, "wb", stdout) == NULL)
    {
        fprintf(stderr, "Cannot set stdout to binary mode.\n");
        return -1;
    }
    if(argc < 1 || strncmp(argv[0], "help", 4) == 0)
        return kindle_print_help(prog_name);
    if(strncmp(argv[0], "dm", 2) == 0)
        return kindle_obfuscate_main(--argc, ++argv);
    if(strncmp(argv[0], "md", 2) == 0)
        return kindle_deobfuscate_main(--argc,++argv);
    if(strncmp(argv[0], "convert", 7) == 0)
        return kindle_convert_main(--argc, ++argv);
    if(strncmp(argv[0], "extract", 7) == 0)
        return kindle_extract_main(--argc, ++argv);
    if(strncmp(argv[0], "create", 6) == 0)
        return kindle_create_main(--argc, ++argv);
    if(strncmp(argv[0], "info", 4) == 0)
        return kindle_info_main(--argc, ++argv);
}
