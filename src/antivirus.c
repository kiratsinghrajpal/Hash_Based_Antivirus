#include <dirent.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h> 
#include <math.h>

#define STR_VALUE(val) #val
#define STR(name) STR_VALUE(name)
#define PATH_LEN 256
#define MD5_LEN 32

char *hash;
int hex(char c)
{
    if(c>'0' && c<'9')
    return c-48;
    if(c>'A' && c<'F')
    return c-57;
}

void swap(char *s)
{
    int len = strlen(s);
    char temp = s[len-1];
    s[len-1] = s[0];
    s[0] = temp;
    temp = s[(int)(len/3)];
    s[(int)(len/3)] = s[(int)(2*len/3)];
    s[(int)(2*len/3)] = temp; 
}


int isFile(const char* name)
{
    DIR* directory = opendir(name);
    if(directory != NULL)
    {
    closedir(directory);
    return 0;
    }
    if(errno == ENOTDIR)
    {
        return 1;
    }
    return -1;
}

//md5 hash function
/*int CalcFileMD5(char *file_name, char *md5_sum)
{
    #define MD5SUM_CMD_FMT "md5sum %." STR(PATH_LEN) "s 2>/dev/null"
    char cmd[PATH_LEN + sizeof (MD5SUM_CMD_FMT)];
    sprintf(cmd, MD5SUM_CMD_FMT, file_name);
    #undef MD5SUM_CMD_FMT

    FILE *p = popen(cmd, "r");
    if (p == NULL) return 0;
    int i, ch;
    for (i = 0; i < MD5_LEN && isxdigit(ch = fgetc(p)); i++) 
    {
        *md5_sum++ = ch;
    }

    *md5_sum = '\0';
    pclose(p);
    return i == MD5_LEN;
}
*/



/**
 * Lists all files and sub-directories recursively 
 * considering path as base path.
 */
 void scan(char *basePath)
{
    int virus_flag=0;
    char path[1000], choice[5];
    struct dirent *dp;
    DIR *dir = opendir(basePath);
    int status,flag;
    // Unable to open directory stream
    if (!dir)
        return;

    while ((dp = readdir(dir)) != NULL)
    {
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0)
        {
            virus_flag=0;
            // Construct new path from our base path
            strcpy(path, basePath);
            strcat(path, "/");
            strcat(path, dp->d_name);

            //check for virus
            char file1[100];
            printf("Current directory/file -> %s\n",path);      
            char md5[MD5_LEN + 1];
            
            if(isFile(path)==1)
            {
			//custom hash
			    FILE *fo = fopen(path,"r");
			    FILE *fw = fopen("hex.txt","w+");
			    
			    while(!feof(fo))
			    {
			        unsigned char c = fgetc(fo);
			        fprintf(fw,"%02X",c);
			    }
			    fseek(fw,0,SEEK_END);
			    int filesize = ftell(fw);
			    rewind(fw);
			       while(filesize>16)
			    {
			        rewind(fw);
			        hash = (char *)calloc(filesize,sizeof(char));
			        
			        for(int i=0;i<filesize;)
			        {
			            int out = 0;
			            for(int j = 3;(j>=0)&&i<(filesize);j--,i++)
			            {
			                int A = 0;
			                unsigned char cc;
			                cc = fgetc(fw);
			                A = hex(cc);
			                float rad = (70+(A%15))*3.14159/180;
			                float tang = tan(rad);
			                tang = (tang>0)?tang:(-tang);
			                out+=(int)(A*pow(tang,j));
			            }
			            char sum[8] = "";
			            sprintf(sum,"%X",out);
			            strcat(hash,sum);
			        }
			        hash+=3;
			        swap(hash);
			        filesize = strlen(hash);
			        fclose(fw);
			        fw = fopen("hex.txt","w+");
			        fputs(hash,fw);

			    }
			    while(strlen(hash)<16)
			    {
			        strcat((hash),"0");
			    }  
			    printf("Success! Hash value is: %s\n",hash);

			    fclose(fo);
			    fclose(fw);

				//hash finish

                char num[100];
                FILE *fptr;
                if ((fptr = fopen("database.txt","r")) == NULL)
                {
                    printf("Error! opening file");
                    // Program exits if the file pointer returns NULL.
                    exit(0);
                }       
                
                while(fscanf(fptr,"%16s", &num)!=EOF)
                { 
                    if(strcmp(hash,num) == 0)
                    {   
                        flag =0;
                        printf("VIRUS!! found at %s\n\n", path);
                        virus_flag=1;
                        //Delete virus
                        do 
                        {
                            printf("Do you want to delete this malicious file? (yes or no)  :-  %s\t",path);
                            scanf("%s",&choice);
                            //convert to lowercase
                            for(int i=0; choice[i]!='\0'; i++)
                            {
                                if(choice[i]>='A' && choice[i]<='Z')
                                {
                                    choice[i] = choice[i] + 32;
                                }
                            }
                            //
                            if(!strcmp(choice, "yes"))
                            {
                                status = remove(path);
                                if (status == 0)
                                printf("%s file deleted successfully.\n\n", path);
                                else
                                {
                                    printf("Unable to delete the file\n");
                                    perror("Following error occurred\n");
                                }
                            }
                            else if(!strcmp(choice, "no"))
                            {
                                printf("\n\n");
                            }
                            else
                            {
                                printf("Incorrect choice\n");
                                flag=1;
                            }
                        }while(flag==1);
                        //delete file end
                    }
                }
                if(virus_flag==0)
                {
                    printf("Not a Virus\n\n");
                }
                fclose(fptr);   
            }
            scan(path);
        }
    }
    closedir(dir);
}

int main()
{
    // Directory path to list files
    char path[100];

    // Input path from user
    printf("Enter folder to scan : ");
    scanf("%s", path);
    printf("\n");
    clock_t t; 
    t = clock(); 
    scan(path);
    t = clock()-t; 
    double time_taken = ((double)t)/CLOCKS_PER_SEC;
    printf("\nScan Complete!\n");
    printf("Total time taken to scan : %f seconds \n", time_taken); 
    return 0;
}