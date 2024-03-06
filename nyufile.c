#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

#include <openssl/sha.h>
#define SHA_DIGEST_LENGTH 20

unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);

#include "nyufile.h"

void *disk;
BootEntry *boot;
unsigned int sector_size;
unsigned int cluster_size;
char sha1[SHA_DIGEST_LENGTH];

void print_fs_info();
void list_root_dir();
void recover_file(unsigned char *file_name, char flag, bool has_sha);
int recurse(int *possibilities, int *result, int cur, int size, unsigned int file_size);

int main(int argc, char *argv[])
{
    if (argc <= 2)
    {
        printf("Usage: ./nyufile disk <options>\n");
        printf("  -i                     Print the file system information.\n");
        printf("  -l                     List the root directory.\n");
        printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
        printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
        exit(1);
    }
    // *** GET FLAGS
    int ch;
    char flag;
    unsigned char *filename = NULL;
    bool has_sha = false;
    while ((ch = getopt(argc, argv, "ilr:s:R:")) != -1)
    {
        switch (ch)
        {
        case 'i':
            flag = 'i';
            break;
        case 'l':
            flag = 'l';
            break;
        case 's':
            for (int j = 0; j < SHA_DIGEST_LENGTH * 2; j += 2)
            {
                sscanf(optarg + j, "%2x", (unsigned int *)(sha1 + j / 2));
            }
            has_sha = true;
            break;
        case 'r':
            flag = 'r';
            filename = (unsigned char *)optarg;
            break;
        case 'R':
            flag = 'R';
            filename = (unsigned char *)optarg;
            break;
        default:
            printf("Usage: ./nyufile disk <options>\n");
            printf("  -i                     Print the file system information.\n");
            printf("  -l                     List the root directory.\n");
            printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
            printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
            exit(1);
        }
    }



    //File MMAP
    int fd = open(argv[optind], O_RDWR, 0777);
    if (fd == -1)
    {
        fprintf(stderr, "error opening file");
        exit(-1);
    }

   
    struct stat sb; 
    if (fstat(fd, &sb) == -1)
        fprintf(stderr, "error with file stat");

  
    disk = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (disk == MAP_FAILED)
        fprintf(stderr, "error with mmap");

    boot = (BootEntry *)disk;
    sector_size = boot->BPB_BytsPerSec;
    cluster_size = sector_size * boot->BPB_SecPerClus;

    if (flag == 'R' && !has_sha)
    {
        printf("Usage: ./nyufile disk <options>\n");
        printf("  -i                     Print the file system information.\n");
        printf("  -l                     List the root directory.\n");
        printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
        printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
        exit(1);
    }

    switch (flag)
    {
    case 'i': 
        print_fs_info();
        break;
    case 'l':
        list_root_dir();
        break;
    case 'r':
        recover_file(filename, flag, has_sha);
        break;
    case 'R':
        recover_file(filename, flag, has_sha);
        break;
    }

    munmap(disk, sb.st_size);
}

void print_fs_info()
{
    printf("Number of FATs = %d\n", boot->BPB_NumFATs);
    printf("Number of bytes per sector = %d\n", boot->BPB_BytsPerSec);
    printf("Number of sectors per cluster = %d\n", boot->BPB_SecPerClus);
    printf("Number of reserved sectors = %d\n", boot->BPB_RsvdSecCnt);
// Function to list the root directory entries
void list_root_dir()
{
    int *fat = (int *)((char *)disk + boot->BPB_RsvdSecCnt * sector_size);
    unsigned int root_dir_cluster = boot->BPB_RootClus;

    int total_count = 0;
    int deleted = 0;
    do
    {
        int count = 0;
        DirEntry *dir = (DirEntry *)((char *)disk + boot->BPB_RsvdSecCnt * sector_size + boot->BPB_NumFATs * boot->BPB_FATSz32 * sector_size + (root_dir_cluster - 2) * cluster_size);
        while (dir->DIR_Name[0] != 0x00 && count * sizeof(DirEntry) < cluster_size)
        {
            if (dir->DIR_Name[0] == 0xE5)  
            {
                deleted++;
                count++;
                total_count++;
                dir++;
                continue;
            }

            // PARSE NAME
            unsigned char *name = (unsigned char *)malloc(13 * sizeof(char)); 
            int i = 0;
            while (dir->DIR_Name[i] != ' ' && i < 8)
            {
                name[i] = dir->DIR_Name[i];
                i++;
            }

            unsigned int size = dir->DIR_FileSize;
            unsigned int st_cluster = dir->DIR_FstClusHI << 16 | dir->DIR_FstClusLO;

            if (dir->DIR_Attr == 0x10) // if is folder
                printf("%s/ (starting cluster = %d)\n", name, st_cluster);
            else
            { 
                if (dir->DIR_Name[8] == ' ')
                    ;
                else
                {
                    name[i] = '.';
                    i++;
                    if (dir->DIR_Name[8] != ' ')
                    {
                        name[i] = dir->DIR_Name[8];
                        i++;
                    }
                    if (dir->DIR_Name[9] != ' ')
                    {
                        name[i] = dir->DIR_Name[9];
                        i++;
                    }
                    if (dir->DIR_Name[10] != ' ')
                    {
                        name[i] = dir->DIR_Name[10];
                        i++;
                    }
                }
                name[i] = '\0';
                if (size == 0) // if is empty file
                    printf("%s (size = %d)\n", name, size);
                else
                    printf("%s (size = %d, starting cluster = %d)\n", name, size, st_cluster);
            }
            count++;
            total_count++;
            dir++;
            free(name);
        }
    } while ((root_dir_cluster = fat[root_dir_cluster]) < 0x0FFFFFF8);
    printf("Total number of entries = %d\n", total_count - deleted);
}

// Function to recover a deleted file
void recover_file(unsigned char *file_name, char flag, bool has_sha)
{
    // fat
    int *fat = (int *)((char *)disk + boot->BPB_RsvdSecCnt * sector_size);
    unsigned int root_dir_cluster = boot->BPB_RootClus; // cluster -> root directory

    DirEntry *del_dir = NULL;

    do
    {
        int count = 0;
        // current cluster of the root directory's address
        DirEntry *dir = (DirEntry *)((char *)disk + boot->BPB_RsvdSecCnt * sector_size + boot->BPB_NumFATs * boot->BPB_FATSz32 * sector_size + (root_dir_cluster - 2) * cluster_size);
        while (dir->DIR_Name[0] != 0x00 && count * sizeof(DirEntry) < cluster_size)
        {
            if (dir->DIR_Name[0] != 0xE5) // not a deleted file, so skip
            {
                count++;
                dir++;
                continue;
            }

            // PARSE NAME
            unsigned char *name = (unsigned char *)malloc(13 * sizeof(char)); 
            int i = 0;
            while (dir->DIR_Name[i] != ' ' && i < 8)
            {
                name[i] = dir->DIR_Name[i];
                i++;
            }
            if (dir->DIR_Name[8] == ' ')
                ;
            else
            {
                name[i] = '.';
                i++;
                if (dir->DIR_Name[8] != ' ')
                {
                    name[i] = dir->DIR_Name[8];
                    i++;
                }
                if (dir->DIR_Name[9] != ' ')
                {
                    name[i] = dir->DIR_Name[9];
                    i++;
                }
                if (dir->DIR_Name[10] != ' ')
                {
                    name[i] = dir->DIR_Name[10];
                    i++;
                }
            }
            name[i] = '\0';

            if (strncmp((char *)(file_name + 1), (char *)(name + 1), 11) != 0)
            {
                // not the same file
                count++;
                dir++;
                free(name);
                continue;
            }

            // recovery check sha1
            if (has_sha)
            {
                if (flag == 'R')
                {
                    unsigned int st_cluster = dir->DIR_FstClusHI << 16 | dir->DIR_FstClusLO;
                    unsigned int file_size = dir->DIR_FileSize;

                    unsigned int *fat = (unsigned int *)((char *)disk + boot->BPB_RsvdSecCnt * sector_size);

                    int del_clusters[19];
                    int count = 0;
                    for (int i = boot->BPB_RootClus; i <= 20; i++)
                    {
                        if (fat[i] == 0 && fat[i] != st_cluster)
                        {
                            del_clusters[count] = i;
                            count++;
                        }
                    }

                    int num_del_clusters = (int)ceil(1.0 * file_size / cluster_size);

                    int result[num_del_clusters];
                    result[0] = st_cluster;

                    if (recurse(del_clusters, result, 0, num_del_clusters, file_size) == 1)
                    {
                        // modify ƒirst character of filename to restore file
                        dir->DIR_Name[0] = file_name[0];

                        // for (int p = 0; p < num_del_clusters; p++) {
                        //     printf("%d*", result[p]);
                        // }
                        // printf("\n");

                        if (file_size == 0) // handle empty files
                        {
                            printf("%s: successfully recovered with SHA-1\n", file_name);
                            free(name);
                            return;
                        }

                        for (int cur_fat = 0; cur_fat < boot->BPB_NumFATs; cur_fat++)
                        {
                            int *fat = (int *)((char *)disk + boot->BPB_RsvdSecCnt * sector_size + cur_fat * sector_size * boot->BPB_FATSz32);

                            int n;
                            for (n = 0; n < num_del_clusters - 1; n++)
                            {
                                fat[result[n]] = result[n + 1];
                            }
                            fat[result[n]] = 0x0FFFFFFF;
                        }

                        printf("%s: successfully recovered with SHA-1\n", file_name);

                        free(name);
                        return;
                    }
                }
                else
                {
                    unsigned int st_cluster = dir->DIR_FstClusHI << 16 | dir->DIR_FstClusLO;
                    unsigned int file_size = dir->DIR_FileSize;

                    unsigned char *cluster = (unsigned char *)disk +
                                             boot->BPB_RsvdSecCnt * sector_size +
                                             boot->BPB_NumFATs * boot->BPB_FATSz32 * sector_size +
                                             (st_cluster - 2) * cluster_size;

                    unsigned char file_sha1[SHA_DIGEST_LENGTH];
                    SHA1(cluster, file_size, file_sha1);

                    if (strncmp((char *)file_sha1, (char *)sha1, SHA_DIGEST_LENGTH) == 0)
                    {
                        // sha1 is the same!
                        del_dir = dir;
                        free(name);
                        break;
                    }
                }
            }
            else // no sha1 supplied
            {
                if (del_dir != NULL)
                {
                    printf("%s: multiple candidates found\n", file_name);
                    free(name);
                    return;
                }
                del_dir = dir;
            }
            free(name);
            count++;
            dir++;
        }
    } while ((root_dir_cluster = fat[root_dir_cluster]) < 0x0FFFFFF8);

    if (del_dir != NULL)
    {
        del_dir->DIR_Name[0] = file_name[0];

        unsigned int st_cluster = del_dir->DIR_FstClusHI << 16 | del_dir->DIR_FstClusLO; 
        unsigned int file_size = del_dir->DIR_FileSize;                                  

        if (file_size == 0)
        {
            ;
        }
        else
        {
            int num_cluster_restored = 0;

            for (int cur_fat = 0; cur_fat < boot->BPB_NumFATs; cur_fat++)
            {
                int *fat = (int *)((char *)disk + boot->BPB_RsvdSecCnt * sector_size + cur_fat * sector_size * boot->BPB_FATSz32);

                num_cluster_restored = 0;
                while ((num_cluster_restored + 1) * cluster_size < file_size)
                {
                    // curr cluster points to next one
                    fat[st_cluster + num_cluster_restored] = st_cluster + num_cluster_restored + 1;
                    num_cluster_restored++;
                }
                fat[st_cluster + num_cluster_restored] = 0x0FFFFFFF; 
            }
        }
        // print success message
        if (has_sha)
            printf("%s: successfully recovered with SHA-1\n", file_name);
        else
            printf("%s: successfully recovered\n", file_name);
        return;
    }

    printf("%s: file not found\n", file_name);
}

// Function to recursively check for possible clusters to recover a file
int recurse(int *possibilities, int *result, int cur, int size, unsigned int file_size)
{
    if (cur == size)
    {
        unsigned char test_file[cluster_size * 5]; 
        for (int i = 0; i < size; i++)
        {
            char *cluster = (char *)disk +
                            boot->BPB_RsvdSecCnt * sector_size +
                            boot->BPB_NumFATs * boot->BPB_FATSz32 * sector_size +
                            (result[i] - 2) * cluster_size;

            memcpy(test_file + i * cluster_size, cluster, cluster_size);
        }
        
        unsigned char file_sha1[SHA_DIGEST_LENGTH];
        SHA1(test_file, file_size, file_sha1);

        if (strncmp((char *)file_sha1, (char *)sha1, SHA_DIGEST_LENGTH) == 0)
        {
            return 1;
        }
        return 0;
    }
    for (int i = 0; i < size; i++)
    {
        int temp;

        if (possibilities[i] == -1)
            continue;

        temp = possibilities[i];
        result[cur] = temp;

        possibilities[i] = -1;

        if (recurse(possibilities, result, cur + 1, size, file_size) == 1)
            return 1;
        possibilities[i] = temp;
    }

    return 0;
}