//
//  create.c
//  KindleTool
//
//  Created by Yifan Lu on 12/31/11.
//  Copyright (c) 2011 __MyCompanyName__. All rights reserved.
//

#include "kindle_tool.h"

int kindle_create()
{
	TAR *tar;
	tar_open(&tar, "/tmp/test.tar", NULL, O_WRONLY | O_CREAT, 0644, TAR_GNU);
}

int kindle_create_from_directory(DIR *input, TAR *output)
{
	static char *base_dir = ".";
	struct dirent *input_info;
	
	input_info = readdir(input);
	
	// create index called from context
	// sign files
    // add index to tar
    // delete index
	
	tar_append_tree(output, input_info->d_name, base_dir);
	
	close(tar_fd(output));
	return 0;
}

int print_dir(DIR *dir, char *dirname, FILE *out_index, TAR *out_tar)
{
	struct dirent *ent;
	struct stat st;
	DIR *next;
	char *nextname;
    char *signame;
    FILE *file;
    FILE *sigfile;
    char md5[MD5_DIGEST_LENGTH*2+1];
	
	while ((ent = readdir (dir)) != NULL)
	{
		if(ent->d_type == DT_DIR)
		{
			if(strcmp(ent->d_name, "..") == 0 || strcmp(ent->d_name, ".") == 0)
			{
				continue;
			}
			nextname = strdup(dirname);
			nextname = realloc(nextname, (strlen(nextname) + strlen(ent->d_name) + 2) * sizeof(char));
			strcat(nextname, ent->d_name);
			strcat(nextname, "/");
			chdir(ent->d_name);
			next = opendir (".");
			print_dir(next,nextname,out_index,out_tar);
            free(nextname);
            free(next);
		}
		else
		{
			if(stat(ent->d_name, &st) != 0)
            {
                fprintf(stderr, "Cannot get file size for %s%s.\n", dirname, ent->d_name);
                closedir (dir);
                return -1;
            }
            // open file
            if((file = fopen(ent->d_name, "r")) == NULL)
            {
                fprintf(stderr, "Cannot open %s%s for reading!\n", dirname, ent->d_name);
                closedir (dir);
                return -1;
            }
			// calculate md5 hashsum
            if(md5_sum(file, md5) != 0)
            {
                fprintf(stderr, "Cannot calculate hash sum for %s%s\n", dirname, ent->d_name);
                closedir (dir);
                fclose(file);
                return -1;
            }
            rewind(file);
			// use openssl to sign file
            signame = strdup(ent->d_name);
            signame = realloc(signame, (strlen(signame) + 4) * sizeof(char));
            if((sigfile = fopen(signame, "w")) != 0)
            {
                fprintf(stderr, "Cannot create signature file %s\n", signame);
                closedir (dir);
                fclose(file);
                free(signame);
                return -1;
            }
            strcat(signame, ".sig");
            if(sign_file(file, sigfile) != 0)
            {
                fprintf(stderr, "Cannot sign %s%s\n", dirname, ent->d_name);
                closedir (dir);
                fclose(file);
                free(signame);
                fclose(sigfile);
                return -1;
            }
			// chmod +x if script
            if(is_script(ent->d_name) || (chmod(ent->d_name, 0777) != 0))
            {
                fprintf(stderr, "Cannot set executable permission for %s%s\n", dirname, ent->d_name);
                closedir (dir);
                fclose(file);
                free(signame);
                fclose(sigfile);
                return -1;
            }
			// add file to index
            if(fprintf(out_index, "%d %s %s%s %lldl %s\n", (is_script(ent->d_name) ? 129 : 128), md5, dirname, ent->d_name, st.st_size / BLOCK_SIZE, ent->d_name) < 0)
            {
                fprintf(stderr, "Cannot write to index file.\n");
                closedir (dir);
                fclose(file);
                free(signame);
                fclose(sigfile);
                return -1;
            }
			// add file to tar
			// add sig to tar
            // clean up
            fclose(file);
            free(signame);
            fclose(sigfile);
            remove(signame);
		}
	}
	chdir("..");
	closedir(dir);
    return 0;
}

int sign_file(FILE *in_file, FILE *rsa_pkey_file, FILE *sigout_file)
{
    /* Taken from: http://stackoverflow.com/a/2054412/91422 */
    RSA *rsa_pkey;
    EVP_PKEY *pkey;
    EVP_MD_CTX ctx;
    unsigned char buffer[BUFFER_SIZE];
    size_t len;
    unsigned char *sig;
    unsigned int siglen;
    int i;
    
    pkey = EVP_PKEY_new();
    if(!PEM_read_RSAPrivateKey(rsa_pkey_file, &rsa_pkey, NULL, NULL))
    {
        fprintf(stderr, "Error loading RSA Private Key File.\n");
        return -1;
    }
    if(!EVP_PKEY_assign_RSA(pkey, rsa_pkey))
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

int is_script(char *filename)
{
    size_t n;
    n = strlen(filename);
    return strncmp(filename+(n-4), ".ffs", 4) == 0 || strncmp(filename+(n-3), ".sh", 3) == 0;
}

int kindle_create_from_tar(TAR *tar)
{
	return 0;
}
