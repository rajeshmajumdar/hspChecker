#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

#define UNRESTRICTED_FS     (1 << 1)
#define UNRESTRICTED_NVRAM  (1 << 6)
#define UNTRUSTED_KEXT      (1 << 0)

typedef uint32_t status_t;
status_t current = 0;
extern int csr_get_active_config(status_t *current);

kern_return_t priviliges() {
    if(geteuid() != 0) {
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

task_t kernel_task_port() {
    task_t kernel_task;
    host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &kernel_task);
    return kernel_task;
}

kern_return_t SIP_status() {
    FILE *sip = popen("csrutil status", "r");
    char sip_sts[100];
    char ctl[100] = "System Integrity Protection status: disabled.";
    while (fgets(sip_sts, sizeof(sip_sts), sip) != 0) {

    }
    pclose(sip);
    printf("\n%s", sip_sts);
    return KERN_SUCCESS;
}

int main() {
    task_t kernel_port;
    csr_get_active_config(&current);
    if (priviliges() == KERN_SUCCESS) {
        SIP_status();
        int kext_flag = UNTRUSTED_KEXT;
        int nvram_flag = UNRESTRICTED_NVRAM;
        int fs_flag = UNRESTRICTED_FS;
        bool test_kext_flag = (current & kext_flag);
        bool test_nvram_flag = (current & nvram_flag);
        bool test_fs_flag = (current & fs_flag);
        if(test_kext_flag) {
            printf("SIP Kext Signing Restrictions: Disabled\n");
        }
        else {
            printf("SIP Kext Signing Restrictions: Enabled\n");
        }
        if(test_nvram_flag) {
            printf("SIP NVRAM Restrictions: Disabled\n");
        }
        else {
            printf("SIP NVRAM Restrictions: Enabled\n");
        }
        if(test_fs_flag) {
            printf("SIP File System Restrictions: Disabled\n");
        }
        else {
            printf("SIP File System Restrictions: Enabled\n");
        }
        kernel_port = kernel_task_port();
        if(kernel_port != 0) {
            printf("Got kernel task port: %u\n", kernel_port);
        }
        else {
            printf("Couldn't get the kernel task port.\n");
        }
    }
    else {
        exit(EXIT_FAILURE);
    }
    return 0;
}
