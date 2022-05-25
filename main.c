#include <stdio.h>

int plugin_main()
{
    char *cni_command = getenv("CNI_COMMAND");
    if (cni_command == NULL)
    {
        printf("CNI_COMMAND is not set\n");
        return 1;
    }

    if (strcmp(cni_command, "ADD") == 0)
    {
        FILE *fp = fopen("/tmp/whatever.txt", "w");
        char buf[1024];
        while (fgets(buf, sizeof(buf), stdin))
        {
            fputs(buf, fp);
        }
        fclose(fp);
        return 0;
    }
    else if (strcmp(cni_command, "DEL") == 0)
    {
        printf("CNI_COMMAND is DEL\n");
    }
    else
    {
        printf("CNI_COMMAND is %s\n", cni_command);
    }
}

int main(int argc, char const *argv[])
{
    return 0;
}