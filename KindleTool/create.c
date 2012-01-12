//
//  create.c
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

int sign_file(FILE *in_file, RSA *rsa_pkey, FILE *sigout_file)
{
    /* Taken from: http://stackoverflow.com/a/2054412/91422 */
    EVP_PKEY *pkey;
    EVP_MD_CTX ctx;
    unsigned char buffer[BUFFER_SIZE];
    size_t len;
    unsigned char *sig;
    uint32_t siglen;
    pkey = EVP_PKEY_new();
    
    if(EVP_PKEY_set1_RSA(pkey, rsa_pkey) == 0)
    {
        fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
        return -2;
    }
    EVP_MD_CTX_init(&ctx);
    if(!EVP_SignInit(&ctx, EVP_sha256()))
    {
        fprintf(stderr, "EVP_SignInit: failed.\n");
        EVP_PKEY_free(pkey);
        return -3;
    }
    while((len = fread(buffer, sizeof(char), BUFFER_SIZE, in_file)) > 0)
    {
        if (!EVP_SignUpdate(&ctx, buffer, len))
        {
            fprintf(stderr, "EVP_SignUpdate: failed.\n");
            EVP_PKEY_free(pkey);
            return -4;
        }
    }
    if(ferror(in_file))
    {
        fprintf(stderr, "Error reading file.\n");
        EVP_PKEY_free(pkey);
        return -5;
    }
    sig = malloc(EVP_PKEY_size(pkey));
    if(!EVP_SignFinal(&ctx, sig, &siglen, pkey))
    {
        fprintf(stderr, "EVP_SignFinal: failed.\n");
        free(sig);
        EVP_PKEY_free(pkey);
        return -6;
    }
    
    if(fwrite(sig, sizeof(char), siglen, sigout_file) < siglen)
    {
        fprintf(stderr, "Error writing signature file.\n");
        free(sig);
        EVP_PKEY_free(pkey);
        return -7;
    }
    
    free(sig);
    EVP_PKEY_free(pkey);
    return 0;
}

FILE *gzip_file(FILE *input)
{
    gzFile gz_file;
    unsigned char buffer[BUFFER_SIZE];
    size_t count;
    FILE *gz_input;
    
    // create a temporary file and open it in gzip
    if((gz_input = tmpfile()) == NULL || (gz_file = gzdopen(fileno(gz_input), "wb")) == NULL)
    {
        fprintf(stderr, "Cannot create temporary file to compress input.\n");
        return NULL;
    }
    // read the input and compress it
    while((count = fread(buffer, sizeof(char), BUFFER_SIZE, input)) > 0)
    {
        if(gzwrite(gz_file, buffer, (uint32_t)count) != count)
        {
            fprintf(stderr, "Cannot compress input.\n");
            gzclose(gz_file);
            return NULL;
        }
    }
    if(ferror(input) != 0)
    {
        fprintf(stderr, "Error reading input.\n");
        gzclose(gz_file);
        return NULL;
    }
    gzflush(gz_file, Z_FINISH); // we cannot gzclose yet, or temp file is deleted
    // move the file pointer back to the beginning
    rewind(gz_input);
    return gz_input;
}

int kindle_create_tar_from_directory(const char *path, FILE *tar_out, RSA *rsa_pkey)
{
    char temp_index[L_tmpnam];
    char temp_index_sig[L_tmpnam];
    char *cwd;
    DIR *dir;
    FILE *index_file;
    FILE *index_sig_file;
    TAR *tar;
    
    // save current directory
    cwd = getcwd(NULL, 0);
    // move to new directory
    if(chdir(path) < 0)
    {
        fprintf(stderr, "Cannot access input directory.\n");
        chdir((const char*)cwd);
        return -1;
    }
    if((dir = opendir(".")) == NULL)
    {
        fprintf(stderr, "Cannot access input directory.\n");
        chdir((const char*)cwd);
        return -1;
    }
    // create index file
    tmpnam(temp_index);
    if((index_file = fopen(temp_index, "w+")) == NULL)
    {
        fprintf(stderr, "Cannot create index file.\n");
        chdir((const char*)cwd);
        return -1;
    }
    // create tar file
    if(tar_fdopen(&tar, fileno(tar_out), NULL, NULL, O_WRONLY | O_CREAT, 0644, TAR_GNU) < 0)
    {
        fprintf(stderr, "Cannot create TAR file.\n");
        chdir((const char*)cwd);
        fclose(index_file);
        remove(temp_index);
        return -1;
    }
    // sign and add files to tar
    if(kindle_sign_and_add_files(dir, "", rsa_pkey, index_file, tar) < 0)
    {
        fprintf(stderr, "Cannot add files to TAR.\n");
        chdir((const char*)cwd);
        fclose(index_file);
        tar_close(tar);
        remove(temp_index);
        return -1;
    }
    // sign index
    rewind(index_file);
    tmpnam(temp_index_sig);
    if((index_sig_file = fopen(temp_index_sig, "wb")) == NULL || sign_file(index_file, rsa_pkey, index_sig_file) < 0)
    {
        fprintf(stderr, "Cannot sign index.\n");
        chdir((const char*)cwd);
        fclose(index_file);
        fclose(index_sig_file);
        tar_close(tar);
        remove(temp_index);
        return -1;
    }
    // add index to tar
    fclose(index_file);
    fclose(index_sig_file);
    if(tar_append_file(tar, temp_index, INDEX_FILE_NAME) < 0 || tar_append_file(tar, temp_index_sig, INDEX_SIG_FILE_NAME) < 0)
    {
        fprintf(stderr, "Cannot add index to tar archive.\n");
        chdir((const char*)cwd);
        fclose(index_file);
        remove(temp_index);
        remove(temp_index_sig);
        return -1;
    }
    remove(temp_index);
    remove(temp_index_sig);
    
    // clean up
    tar_append_eof(tar);
    // we cannot close the tar file yet because it will delete the temp file
    remove(INDEX_FILE_NAME);
    closedir(dir);
    chdir((const char*)cwd);
    free(cwd);
	return 0;
}

int kindle_sign_and_add_files(DIR *dir, char *dirname, RSA *rsa_pkey_file, FILE *out_index, TAR *out_tar)
{
    char temp_sig[L_tmpnam];
    size_t pathlen;
	struct dirent *ent = NULL;
	struct stat st;
	DIR *next = NULL;
	char *absname = NULL;
    char *signame = NULL;
    FILE *file = NULL;
    FILE *sigfile = NULL;
    char md5[MD5_HASH_LENGTH+1];
	
    tmpnam(temp_sig);
	while ((ent = readdir (dir)) != NULL)
	{
        pathlen = strlen(dirname) + strlen(ent->d_name);
        absname = realloc(absname, pathlen + 1);
        absname[0] = 0;
        strcat(absname, dirname);
        strcat(absname, ent->d_name);
        absname[pathlen] = 0;
        if(stat(ent->d_name, &st) != 0)
        {
            fprintf(stderr, "Cannot stat %s.\n", absname);
            goto on_error;
        }
		if(S_ISDIR(st.st_mode))
		{
			if(strcmp(ent->d_name, "..") == 0 || strcmp(ent->d_name, ".") == 0)
			{
				continue;
			}
			absname = realloc(absname, pathlen + 2);
			strcat(absname, "/");
            absname[pathlen+1] = 0;
			if(chdir(ent->d_name) < 0)
            {
                fprintf(stderr, "Cannot access input directory.\n");
                goto on_error;
            }
			if((next = opendir (".")) == NULL)
            {
                fprintf(stderr, "Cannot access input directory.\n");
                goto on_error;
            }
			if(kindle_sign_and_add_files(next,absname,rsa_pkey_file,out_index,out_tar) < 0)
            {
                goto on_error;
            }
            closedir(next);
		}
		else
		{
            // open file
            if((file = fopen(ent->d_name, "r")) == NULL)
            {
                fprintf(stderr, "Cannot open %s for reading!\n", absname);
                goto on_error;
            }
			// calculate md5 hashsum
            if(md5_sum(file, md5) != 0)
            {
                fprintf(stderr, "Cannot calculate hash sum for %s\n", absname);
                goto on_error;
            }
            md5[MD5_HASH_LENGTH] = 0;
            rewind(file);
			// use openssl to sign file
            signame = realloc(signame, strlen(absname) + 5);
            signame[0] = 0;
            strcat(signame, absname);
            strcat(signame, ".sig\0");
            if((sigfile = fopen(temp_sig, "w")) == NULL) // we want a rel path, signame is abs since tar wants abs
            {
                fprintf(stderr, "Cannot create signature file %s\n", signame);
                goto on_error;
            }
            if(sign_file(file, rsa_pkey_file, sigfile) < 0)
            {
                fprintf(stderr, "Cannot sign %s\n", absname);
                goto on_error;
            }
			// chmod +x if script
            if(IS_SCRIPT(ent->d_name))
            {
                if(chmod(ent->d_name, 0777) < 0)
                {
                    fprintf(stderr, "Cannot set executable permission for %s\n", absname);
                    goto on_error;
                }
            }
			// add file to index
            if(fprintf(out_index, "%d %s %s %lld %s\n", (IS_SCRIPT(ent->d_name) ? 129 : 128), md5, absname, st.st_size / BLOCK_SIZE, ent->d_name) < 0)
            {
                fprintf(stderr, "Cannot write to index file.\n");
                goto on_error;
            }
			// add file to tar
            fclose(file);
            if(tar_append_file(out_tar, ent->d_name, absname) < 0)
            {
                fprintf(stderr, "Cannot add %s to tar archive.\n", absname);
                goto on_error;
            }
			// add sig to tar
            fclose(sigfile);
            if(tar_append_file(out_tar, temp_sig, signame) < 0)
            {
                fprintf(stderr, "Cannot add %s to tar archive.\n", signame);
                goto on_error;
            }
            remove(temp_sig);
		}
	}
	chdir("..");
    free(signame);
    free(absname);
    return 0;
on_error: // Yes, I know GOTOs are bad, but it's more readable than typing what's below for each error above
    free(signame);
    free(absname);
    if(file != NULL)
        fclose(file);
    if(sigfile != NULL)
        fclose(sigfile);
    if(next != NULL)
        closedir(next);
    remove(temp_sig);
    return -1;
}

int kindle_create(UpdateInformation *info, FILE *input_tgz, FILE *output)
{
    char buffer[BUFFER_SIZE];
    size_t count;
    FILE *temp;
    
    switch(info->version)
    {
        case OTAUpdateV2:
            if((temp = tmpfile()) == NULL)
            {
                fprintf(stderr, "Error opening temp file.\n");
                return -1;
            }
            if(kindle_create_ota_update_v2(info, input_tgz, temp) < 0) // create the update
            {
                fprintf(stderr, "Error creating update package.\n");
                fclose(temp);
                return -1;
            }
            rewind(temp); // rewind the file before reading back
            if(kindle_create_signature(info, temp, output) < 0) // write the signature
            {
                fprintf(stderr, "Error signing update package.\n");
                fclose(temp);
                return -1;
            }
            rewind(temp); // rewind the file before writing it to output
            // write the update
            while((count = fread(buffer, sizeof(char), BUFFER_SIZE, temp)) > 0)
            {
                if(fwrite(buffer, sizeof(char), count, output) < count)
                {
                    fprintf(stderr, "Error writing update to output.\n");
                    fclose(temp);
                    return -1;
                }
            }
            if(ferror(temp) != 0)
            {
                fprintf(stderr, "Error reading generated update.\n");
                fclose(temp);
                return -1;
            }
            fclose(temp);
            return 0;
            break;
        case OTAUpdate:
            return kindle_create_ota_update(info, input_tgz, output);
            break;
        case RecoveryUpdate:
            return kindle_create_recovery(info, input_tgz, output);
            break;
        case UnknownUpdate:
        default:
            fprintf(stderr, "Unknown update type.\n");
            break;
    }
    return -1;
}

int kindle_create_ota_update_v2(UpdateInformation *info, FILE *input_tgz, FILE *output)
{
    int header_size;
    unsigned char *header;
    int index;
    int i;
    size_t str_len;
    
    // first part of the set sized data
    header_size = MAGIC_NUMBER_LENGTH + OTA_UPDATE_V2_BLOCK_SIZE;
    header = malloc(header_size);
    index = 0;
    strncpy((char*)header, info->magic_number, MAGIC_NUMBER_LENGTH);
    index += MAGIC_NUMBER_LENGTH;
    memcpy(&header[index], &info->source_revision, sizeof(uint64_t)); // source
    index += sizeof(uint64_t);
    memcpy(&header[index], &info->target_revision, sizeof(uint64_t)); // target
    index += sizeof(uint64_t);
    memcpy(&header[index], &info->num_devices, sizeof(uint16_t)); // device count
    index += sizeof(uint16_t);
    
    // next, we write the devices
    header_size += info->num_devices * sizeof(uint16_t);
    header = realloc(header, header_size);
    for(i = 0; i < info->num_devices; i++)
    {
        memcpy(&header[index], &info->devices[i], sizeof(uint16_t)); // device
        index += sizeof(uint16_t);
    }
    
    // part two of the set sized data
    header_size += OTA_UPDATE_V2_PART_2_BLOCK_SIZE;
    header = realloc(header, header_size);
    memcpy(&header[index], &info->critical, sizeof(uint8_t)); // critical
    index += sizeof(uint8_t);
    memset(&header[index], 0, sizeof(uint8_t)); // 1 byte padding
    index += sizeof(uint8_t);
    if(md5_sum(input_tgz, (char*)&header[index]) < 0) // md5 hash
    {
        fprintf(stderr, "Error calculating MD5 of package.\n");
        free(header);
        return -1;
    }
    rewind(input_tgz); // reset input for later reading
    md(&header[index], MD5_HASH_LENGTH); // obfuscate md5 hash
    index += MD5_HASH_LENGTH;
    memcpy(&header[index], &info->num_meta, sizeof(uint16_t)); // num meta, cannot be casted
    index += sizeof(uint16_t);
    
    // next, we write the meta strings
    for(i = 0; i < info->num_meta; i++)
    {
        str_len = strlen(info->metastrings[i]);
        header_size += str_len + sizeof(uint16_t);
        header = realloc(header, header_size);
        // string length: little endian -> big endian
        memcpy(&header[index], &((uint8_t*)&str_len)[1], sizeof(uint8_t));
        index += sizeof(uint8_t);
        memcpy(&header[index], &((uint8_t*)&str_len)[0], sizeof(uint8_t));
        index += sizeof(uint8_t);
        strncpy((char*)&header[index], info->metastrings[i], str_len);
        index += str_len;
    }
    
    // now, we write the header to the file
    if(fwrite(header, sizeof(char), header_size, output) < header_size)
    {
        fprintf(stderr, "Error writing update header.\n");
        free(header);
        return -1;
    }
    
    // write the actual update
    free(header);
    return munger(input_tgz, output, 0);
}

int kindle_create_signature(UpdateInformation *info, FILE *input_bin, FILE *output)
{
	UpdateHeader header; // header to write
    
    memset(&header, 0, sizeof(UpdateHeader)); // set them to zero
    strncpy(header.magic_number, "SP01", 4); // write magic number
    header.data.signature.certificate_number = (uint32_t)info->certificate_number; // 4 byte certificate number
	if(fwrite(&header, sizeof(char), MAGIC_NUMBER_LENGTH+UPDATE_SIGNATURE_BLOCK_SIZE, output) < MAGIC_NUMBER_LENGTH+UPDATE_SIGNATURE_BLOCK_SIZE)
	{
        fprintf(stderr, "Error writing update header.\n");
        return -1;
	}
    // write signature to output
    if(sign_file(input_bin, info->sign_pkey, output) < 0)
    {
        fprintf(stderr, "Error signing update package.\n");
        return -1;
    }
    return 0;
}

int kindle_create_ota_update(UpdateInformation *info, FILE *input_tgz, FILE *output)
{
	UpdateHeader header;
	
	memset(&header, 0, sizeof(UpdateHeader)); // set them to zero
	strncpy(header.magic_number, info->magic_number, 4); // magic number
	header.data.ota_update.source_revision = (uint32_t)info->source_revision; // source
    header.data.ota_update.target_revision = (uint32_t)info->target_revision; // target
    header.data.ota_update.device = (uint16_t)info->devices[0]; // device
    header.data.ota_update.optional = (unsigned char)info->optional; // optional
    if(md5_sum(input_tgz, header.data.ota_update.md5_sum) < 0)
    {
        fprintf(stderr, "Error calculating MD5 of input tgz.\n");
        return -1;
    }
    rewind(input_tgz); // rewind input
    md((unsigned char*)header.data.ota_update.md5_sum, MD5_HASH_LENGTH); // obfuscate md5 hash
    
    // write header to output
    if(fwrite(&header, sizeof(char), MAGIC_NUMBER_LENGTH+OTA_UPDATE_BLOCK_SIZE, output) < MAGIC_NUMBER_LENGTH+OTA_UPDATE_BLOCK_SIZE)
    {
        fprintf(stderr, "Error writing update header.\n");
        return -1;
    }
    
    // write package to output
    return munger(input_tgz, output, 0);
}

int kindle_create_recovery(UpdateInformation *info, FILE *input_tgz, FILE *output)
{
    UpdateHeader header;
	
	memset(&header, 0, sizeof(UpdateHeader)); // set them to zero
	strncpy(header.magic_number, info->magic_number, 4); // magic number
	header.data.recovery_update.magic_1 = (uint32_t)info->magic_1; // magic 1
    header.data.recovery_update.magic_2 = (uint32_t)info->magic_2; // magic 2
    header.data.recovery_update.minor = (uint32_t)info->minor; // minor
    header.data.recovery_update.device = (uint32_t)info->devices[0]; // device
    if(md5_sum(input_tgz, header.data.recovery_update.md5_sum) < 0)
    {
        fprintf(stderr, "Error calculating MD5 of input tgz.\n");
        return -1;
    }
    rewind(input_tgz); // rewind input
    md((unsigned char*)header.data.recovery_update.md5_sum, MD5_HASH_LENGTH); // obfuscate md5 hash
    
    // write header to output
    if(fwrite(&header, sizeof(char), MAGIC_NUMBER_LENGTH+RECOVERY_UPDATE_BLOCK_SIZE, output) < MAGIC_NUMBER_LENGTH+RECOVERY_UPDATE_BLOCK_SIZE)
    {
        fprintf(stderr, "Error writing update header.\n");
        return -1;
    }
    
    // write package to output
    return munger(input_tgz, output, 0);
}

int kindle_create_main(int argc, char *argv[])
{
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
        { "meta", required_argument, NULL, 'x' }
    };
    UpdateInformation info = {"\0\0\0\0", UnknownUpdate, get_default_key(), 0, UINT32_MAX, 0, 0, 0, 0, NULL, CertificateDeveloper, 0, 0, 0, NULL };
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
    // update type
    if(argc < 2)
    {
        fprintf(stderr, "Not enough arguments.\n");
        return -1;
    }
    if(strncmp(argv[0], "ota2", 4) == 0)
    {
        info.version = OTAUpdateV2;
    }
    else if(strncmp(argv[0], "ota", 3) == 0)
    {
        info.version = OTAUpdate;
        strncpy(info.magic_number, "FC02", 4);
    }
    else if(strncmp(argv[0], "recovery", 8) == 0)
    {
        info.version = RecoveryUpdate;
        strncpy(info.magic_number, "FB02", 4);
    }
    else
    {
        fprintf(stderr, "Invalid update type.\n");
        return -1;
    }
    argc--; argv++; // next argument
    // arguments
    optind = -1; // hack to get around the fact that we skipped some arguments
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
                    fprintf(stderr, "Unknown device %s.\n", optarg);
                    goto do_error;
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
                if((info.version = get_bundle_version(optarg)) == UnknownUpdate)
                {
                    fprintf(stderr, "Invalid bundle version %s.\n", optarg);
                    goto do_error;
                }
                break;
            case 's':
                info.source_revision = strtoul(optarg, NULL, 0);
                break;
            case 't':
                info.target_revision = strtoul(optarg, NULL, 0);
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
                if(strchr(optarg, '=') == NULL) // metastring must contain =
                {
                    fprintf(stderr, "Invalid metastring. Format: key=value, input: %s\n", optarg);
                    goto do_error;
                }
                if(strlen(optarg) > 0xFFFF)
                {
                    fprintf(stderr, "Metastring too long. Max length: %d, input: %s\n", 0xFFFF, optarg);
                    goto do_error;
                }
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
    if(info.version != OTAUpdateV2 && (info.source_revision > UINT32_MAX || info.target_revision > UINT32_MAX))
    {
        fprintf(stderr, "Source/target revision for this update type cannot exceed %u\n", UINT32_MAX);
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
        if((temp = tmpfile()) == NULL || kindle_create_tar_from_directory(argv[0], temp, info.sign_pkey) < 0)
        {
            fprintf(stderr, "Cannot create archive.\n");
            goto do_error;
        }
        rewind(temp);
	
        if((input = gzip_file(temp)) == NULL)
        {
            fprintf(stderr, "Cannot compress archive.\n");
            goto do_error;
        }
        fclose(temp);
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
    // write it all to the output
    if(kindle_create(&info, input, output) < 0)
    {
        fprintf(stderr, "Cannot write update to output.\n");
        goto do_error;
    }
    fclose(input);
    return 0;
do_error:
    free(info.devices);
    for(i = 0; i < info.num_meta; i++)
        free(info.metastrings[i]);
    free(info.metastrings);
    fclose(temp);
    fclose(input);
    return -1;
}
