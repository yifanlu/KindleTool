//
//  create.c
//  KindleTool
//
//  Created by Yifan Lu on 12/31/11.
//  Copyright (c) 2011 __MyCompanyName__. All rights reserved.
//

#include "kindle_tool.h"
#include <errno.h>

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
    unsigned int siglen;
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

int kindle_create()
{
	TAR *tar;
	tar_open(&tar, "/tmp/test.tar", NULL, O_WRONLY | O_CREAT, 0644, TAR_GNU);
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
    size_t pathlen;
	struct dirent *ent = NULL;
	struct stat st;
	DIR *next = NULL;
	char *absname = NULL;
    char *signame = NULL;
    char *signamerel = NULL;
    FILE *file = NULL;
    FILE *sigfile = NULL;
    char md5[MD5_DIGEST_LENGTH*2+1];
	
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
            rewind(file);
			// use openssl to sign file
            signame = realloc(signame, strlen(absname) + 5);
            signame[0] = 0;
            strcat(signame, absname);
            strcat(signame, ".sig\0");
            signamerel = signame+strlen(dirname);
            if((sigfile = fopen(signamerel, "w")) == NULL) // we want a rel path, signame is abs since tar wants abs
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
            if(tar_append_file(out_tar, signamerel, signame) < 0)
            {
                fprintf(stderr, "Cannot add %s to tar archive.\n", signame);
                goto on_error;
            }
            // clean up
            remove(signamerel);
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

int kindle_create_from_tar(TAR *tar)
{
	return 0;
}
