#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>  
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>

#define BUF_SIZE 32768

void compute_sha256(const char *path, unsigned char output[SHA256_DIGEST_LENGTH]) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        perror("EVP_MD_CTX_new");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        perror("EVP_DigestInit_ex");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    unsigned char buffer[BUF_SIZE];
    int bytesRead = 0;
    while ((bytesRead = fread(buffer, 1, BUF_SIZE, file))) {
        if (EVP_DigestUpdate(mdctx, buffer, bytesRead) != 1) {
            perror("EVP_DigestUpdate");
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            exit(EXIT_FAILURE);
        }
    }

    unsigned int output_len;
    if (EVP_DigestFinal_ex(mdctx, output, &output_len) != 1) {
        perror("EVP_DigestFinal_ex");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdctx);
    fclose(file);
}

void print_sha256(unsigned char hash[SHA256_DIGEST_LENGTH]) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

void scan_directory(const char *dir_path, FILE *output_file) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        perror("opendir");
        exit(EXIT_FAILURE);
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            char filepath[PATH_MAX];
            snprintf(filepath, sizeof(filepath), "%s/%s", dir_path, entry->d_name);

            unsigned char hash[SHA256_DIGEST_LENGTH];
            compute_sha256(filepath, hash);

            fprintf(output_file, "%s$", filepath);
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                fprintf(output_file, "%02x", hash[i]);
            }
            fprintf(output_file, "\n");
        }
    }

    closedir(dir);
}

int validate_integrity_list(const char *integrity_file) {
    FILE *file = fopen(integrity_file, "r");
    if (!file) {
        perror("fopen");
        return 0;
    }

    char line[PATH_MAX + 2 * SHA256_DIGEST_LENGTH + 2];
    while (fgets(line, sizeof(line), file)) {
        char *hash_pos = strrchr(line, '$');
        if (hash_pos == NULL || strlen(hash_pos + 2) != 2 * SHA256_DIGEST_LENGTH) {
            syslog(LOG_ERR, "Invalid integrity list format");
            fclose(file);
            return 0;
        }
    }
    fclose(file);
    return 1;
}

void check_integrity(const char *integrity_file) {
    FILE *file = fopen(integrity_file, "r");
    if (!file) {
        perror("fopen");
        fprintf(stderr, "Integrity file validation failed.\n");
        return;
    }

    char filepath[PATH_MAX];
    char hash_str[2 * SHA256_DIGEST_LENGTH + 1];
    unsigned char expected_hash[SHA256_DIGEST_LENGTH];

    int integrity_ok = 1;

    while (fscanf(file, "%[^$]$%s\n", filepath, hash_str) == 2) {
        unsigned char actual_hash[SHA256_DIGEST_LENGTH];
        FILE *file_check = fopen(filepath, "r");
        if (!file_check) {
            perror("fopen");
            fprintf(stderr, "Integrity file validation failed.\n");
            return;
        } 
        fclose(file_check);
        compute_sha256(filepath, actual_hash);

        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sscanf(&hash_str[i * 2], "%02hhx", &expected_hash[i]);
        }

        if (memcmp(expected_hash, actual_hash, SHA256_DIGEST_LENGTH) != 0) {
            syslog(LOG_ERR, "Integrity violation detected: %s", filepath);
            integrity_ok = 0;
        }
    }

    fclose(file);

    if (integrity_ok) {
        printf("Integrity verified.\n");
        syslog(LOG_INFO, "Integrity verified.");
    } else {
        printf("Integrity violation detected.\n");
        syslog(LOG_ERR, "Integrity violation detected.");
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <mode> <directory> <integrity_file>\n", argv[0]);
        fprintf(stderr, "Modes: set check\n");
        return EXIT_FAILURE;
    }

    const char *mode_str = argv[1];
    const char *dir_path = argv[2];
    const char *integrity_file = argv[3];

    int mode;
    if (strcmp(mode_str, "set") == 0) {
        mode = 0;
    } else if (strcmp(mode_str, "check") == 0) {
        mode = 1;
    } else {
        fprintf(stderr, "Invalid mode: %s\n", mode_str);
        return EXIT_FAILURE;
    }

    openlog("file-integrity-checker", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

    if (mode == 0) {
        FILE *output_file = fopen(integrity_file, "w");
        if (!output_file) {
            perror("fopen");
            return EXIT_FAILURE;
        }
        scan_directory(dir_path, output_file);
        fclose(output_file);
        syslog(LOG_INFO, "Integrity list created for directory: %s", dir_path);
    } else if (mode == 1) {
        if (!validate_integrity_list(integrity_file)) {
            fprintf(stderr, "Integrity file validation failed.\n");
            return EXIT_FAILURE;
        }
        check_integrity(integrity_file);
    }

    closelog();
    return EXIT_SUCCESS;
}
