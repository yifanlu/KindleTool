//
//  create.c
//  KindleTool
//
//  Created by Yifan Lu on 12/31/11.
//  Copyright (c) 2011 __MyCompanyName__. All rights reserved.
//

#include "kindle_tool.h"

int is_script(char *filename)
{
    size_t n;
    n = strlen(filename);
    return strncmp(filename+(n-4), ".ffs", 4) == 0 || strncmp(filename+(n-3), ".sh", 3) == 0;
}

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

int kindle_create_tar_from_directory(const char *path, const char *tar_out_name, RSA *rsa_pkey)
{
    static char *temp_index;
    static char *temp_index_sig;
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
    temp_index = tmpnam(temp_index);
    temp_index_sig = tmpnam(temp_index_sig);
    if((index_file = fopen(temp_index, "w+")) == NULL || (index_sig_file = fopen(temp_index_sig, "w")) == NULL)
    {
        fprintf(stderr, "Cannot create index file.\n");
        chdir((const char*)cwd);
        return -1;
    }
    // create tar file
    if(tar_open(&tar, (char*)tar_out_name, NULL, O_WRONLY | O_CREAT, 0644, TAR_GNU) < 0)
    {
        fprintf(stderr, "Cannot create TAR file.\n");
        chdir((const char*)cwd);
        return -1;
    }
    // sign and add files to tar
    if(kindle_sign_and_add_files(dir, "", rsa_pkey, index_file, tar) < 0)
    {
        fprintf(stderr, "Cannot add files to TAR.\n");
        chdir((const char*)cwd);
        return -1;
    }
    // sign index
    rewind(index_file);
    if(sign_file(index_file, rsa_pkey, index_sig_file) < 0)
    {
        fprintf(stderr, "Cannot sign index.\n");
        chdir((const char*)cwd);
        return -1;
    }
    // add index to tar
    fclose(index_file);
    fclose(index_sig_file);
    if(tar_append_file(tar, temp_index, INDEX_FILE_NAME) < 0 || tar_append_file(tar, temp_index_sig, INDEX_SIG_FILE_NAME) < 0)
    {
        fprintf(stderr, "Cannot add index to tar archive.\n");
        chdir((const char*)cwd);
        return -1;
    }
    
    // clean up
    tar_append_eof(tar);
    remove(INDEX_FILE_NAME);
    closedir(dir);
    chdir((const char*)cwd);
    free(cwd);
	return 0;
}

int kindle_sign_and_add_files(DIR *dir, char *dirname, RSA *rsa_pkey_file, FILE *out_index, TAR *out_tar)
{
    static char *temp_sig;
    size_t pathlen;
	struct dirent *ent = NULL;
	struct stat st;
	DIR *next = NULL;
	char *absname = NULL;
    char *signame = NULL;
    FILE *file = NULL;
    FILE *sigfile = NULL;
    char md5[MD5_HASH_LENGTH+1];
	
    if(temp_sig == NULL)
        temp_sig = tmpnam(temp_sig);
	while ((ent = readdir (dir)) != NULL)
	{
        pathlen = strlen(dirname) + strlen(ent->d_name);
        absname = realloc(absname, pathlen + 1);
        absname[0] = 0;
        strcat(absname, dirname);
        strcat(absname, ent->d_name);
        absname[pathlen] = 0;
		if(ent->d_type == DT_DIR)
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
			if(stat(ent->d_name, &st) != 0)
            {
                if(errno == ENOENT)
                    continue; // This file has been deleted since the start of the process, ignoring
                fprintf(stderr, "Cannot get file size for %s.\n", absname);
                goto on_error;
            }
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
            if(is_script(ent->d_name))
            {
                if(chmod(ent->d_name, 0777) < 0)
                {
                    fprintf(stderr, "Cannot set executable permission for %s\n", absname);
                    goto on_error;
                }
            }
			// add file to index
            if(fprintf(out_index, "%d %s %s %lld %s\n", (is_script(ent->d_name) ? 129 : 128), md5, absname, st.st_size / BLOCK_SIZE, ent->d_name) < 0)
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
    return -1;
}

FILE *kindle_compress_tar(FILE *tar_input)
{
    static char *temp_name = NULL;
    gzFile gz_file;
    unsigned char buffer[BUFFER_SIZE];
    size_t count;
    FILE *gz_input;
    
    // create a temporary file and open it in gzip
    temp_name = tmpnam(temp_name);
    if((gz_file = gzopen(temp_name, "wb")) == NULL)
    {
        fprintf(stderr, "Cannot create temporary file to compress input.\n");
        return NULL;
    }
    // just to be safe, no compression
    if(gzsetparams(gz_file, Z_NO_COMPRESSION, Z_DEFAULT_STRATEGY) != Z_OK)
    {
        fprintf(stderr, "Cannot set compression level for input.\n");
        gzclose(gz_file);
        return NULL;
    }
    // read the input and compress it
    while((count = fread(buffer, sizeof(char), BUFFER_SIZE, tar_input)) > 0)
    {
        if(gzwrite(gz_file, buffer, (uint32_t)count) != count)
        {
            fprintf(stderr, "Cannot compress input.\n");
            gzclose(gz_file);
            return NULL;
        }
    }
    if(ferror(tar_input) != 0)
    {
        fprintf(stderr, "Error reading input.\n");
        gzclose(gz_file);
        return NULL;
    }
    gzclose(gz_file);
    // open the data we just compressed
    if((gz_input = fopen(temp_name, "r")) == NULL)
    {
        fprintf(stderr, "Error reading input.\n");
        return NULL;
    }
    return gz_input;
}

int kindle_create(UpdateInformation *info, FILE *input_tgz, FILE *output)
{
    static char *temp_name = NULL;
    char buffer[BUFFER_SIZE];
    size_t count;
    FILE *temp;
    
    if(temp_name == NULL)
        temp_name = tmpnam(temp_name);
    switch(info->version)
    {
        case OTAUpdateV2:
            if((temp = fopen(temp_name, "w+b")) == NULL)
            {
                fprintf(stderr, "Error opening temp file.\n");
                return -1;
            }
            if(kindle_create_ota_update_v2(info, input_tgz, temp) < 0) // create the update
            {
                fprintf(stderr, "Error creating update package.\n");
                return -1;
            }
            rewind(temp); // rewind the file before reading back
            if(kindle_create_signature(info, temp, output) < 0) // write the signature
            {
                fprintf(stderr, "Error signing update package.\n");
                return -1;
            }
            rewind(temp); // rewind the file before writing it to output
            // write the update
            while((count = fread(buffer, sizeof(char), BUFFER_SIZE, temp)) > 0)
            {
                if(fwrite(buffer, sizeof(char), count, output) < count)
                {
                    fprintf(stderr, "Error writing update to output.\n");
                    return -1;
                }
            }
            if(ferror(temp) != 0)
            {
                fprintf(stderr, "Error reading generated update.\n");
                return -1;
            }
            break;
        case OTAUpdate:
            return kindle_create_ota_update(info, input_tgz, output);
            break;
        case RecoveryUpdate:
            return kindle_create_recovery(info, input_tgz, output);
            break;
        default:
            break;
    }
    fprintf(stderr, "Unknown update type.\n");
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
    header[index] = (uint64_t)info->source_revision; // source
    index += sizeof(uint64_t);
    header[index] = (uint64_t)info->source_revision; // target
    index += sizeof(uint64_t);
    header[index] = (uint16_t)info->num_devices; // device count
    index += sizeof(uint16_t);
    
    // next, we write the devices
    header_size += info->num_devices * sizeof(uint16_t);
    header = realloc(header, header_size);
    for(i = 0; i < info->num_devices; i++)
    {
        header[index] = (uint16_t)info->devices[i]; // device
        index += sizeof(uint16_t);
    }
    
    // part two of the set sized data
    header_size += OTA_UPDATE_V2_PART_2_BLOCK_SIZE;
    header[index] = (uint8_t)info->critical; // critical
    index += sizeof(uint8_t);
    header[index] = (uint8_t)0; // 1 byte padding
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
    header[index] = (uint16_t)info->num_meta; // num meta
    
    // next, we write the meta strings
    for(i = 0; i < info->num_meta; i++)
    {
        str_len = strlen(info->metastrings[i]);
        header_size += str_len + sizeof(uint16_t);
        header = realloc(header, header_size);
        header[index] = SWITCHENDIAN(str_len);
        index += sizeof(uint16_t);
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
