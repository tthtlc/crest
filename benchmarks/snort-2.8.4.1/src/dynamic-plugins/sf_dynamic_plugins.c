/* $Id: */
/*
 * sf_dynamic_plugins.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) 2005-2009 Sourcefire, Inc.
 *
 * Author: Steven Sturges
 *
 * Dynamic Library Loading for Snort
 *
 */
#ifdef DYNAMIC_PLUGIN

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef WIN32
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <limits.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fnmatch.h>
#if defined(HPUX)
#define EXT "*.sl"
#elif defined(MACOS)
#define EXT "*.dylib"
#elif defined(OPENBSD)
#define EXT "*.so"
#define EXT2 "*.so.*"
#else
#define EXT "*.so"
#endif
typedef void * PluginHandle;
#else /* !WIN32 */
#include <windows.h>
#define EXT "dll"
typedef HANDLE PluginHandle;
/* Of course, WIN32 couldn't do things the unix way...
 * Define a few of these to get around portability issues.
 */
#define getcwd _getcwd  
#define PATH_MAX MAX_PATH
#endif /* !WIN32 */

#include <errno.h>

#include "config.h"
#include "decode.h"
#include "debug.h"
#include "detect.h"
extern u_int8_t DecodeBuffer[DECODE_BLEN]; /* decode.c */
extern HttpUri UriBufs[URI_COUNT]; /* detect.c */
#include "util.h"
#include "snort.h"
#include "sf_dynamic_engine.h"
#include "sf_dynamic_detection.h"
#include "sf_dynamic_preprocessor.h"
#include "sp_dynamic.h"
#include "sp_preprocopt.h"
#include "util.h"
#include "event_queue.h"
#include "plugbase.h"
#include "sfthreshold.h"
#include "inline.h"
#include "mstring.h"
#include "sfsnprintfappend.h"
#include "stream_api.h"
#include "sf_iph.h"
#include <pcre.h>

#ifdef TARGET_BASED
#include "target-based/sftarget_protocol_reference.h"
#include "target-based/sftarget_reader.h"
#endif


#ifndef DEBUG
char *no_file = "unknown";
int no_line = 0;
#endif

/* Predeclare this */
void VerifySharedLibUniqueness();
typedef int (*LoadLibraryFunc)(char *path, int indent);

typedef struct _DynamicEnginePlugin
{
    PluginHandle handle;
    DynamicPluginMeta metaData;
    InitEngineLibFunc initFunc;
    CompatibilityFunc versCheck;
    struct _DynamicEnginePlugin *next;
    struct _DynamicEnginePlugin *prev;
} DynamicEnginePlugin;

static DynamicEnginePlugin *loadedEngines = NULL;

typedef struct _DynamicDetectionPlugin
{
    PluginHandle handle;
    DynamicPluginMeta metaData;
    InitDetectionLibFunc initFunc;
    struct _DynamicDetectionPlugin *next;
    struct _DynamicDetectionPlugin *prev;
} DynamicDetectionPlugin;

static DynamicDetectionPlugin *loadedDetectionPlugins = NULL;

typedef struct _DynamicPreprocessorPlugin
{
    PluginHandle handle;
    DynamicPluginMeta metaData;
    InitPreprocessorLibFunc initFunc;
    struct _DynamicPreprocessorPlugin *next;
    struct _DynamicPreprocessorPlugin *prev;
} DynamicPreprocessorPlugin;

static DynamicPreprocessorPlugin *loadedPreprocessorPlugins = NULL;

void CloseDynamicLibrary(PluginHandle handle)
{
#ifndef WIN32
    dlclose(handle);
#else
    FreeLibrary(handle);
#endif
}

#define NONFATAL 0
#define FATAL 1

void *getSymbol(PluginHandle handle, char *symbol, DynamicPluginMeta *meta, int fatal)
{
    void *symbolPtr = NULL;

    if (!handle)
        return symbolPtr;

#ifndef WIN32
    symbolPtr = dlsym(handle, symbol);
#else
    symbolPtr = GetProcAddress(handle, symbol);
#endif

    if (!symbolPtr)
    {
        if (fatal)
        {
#ifndef WIN32
            FatalError("Failed to find %s() function in %s: %s\n",
                symbol, meta->libraryPath, dlerror());
#else
            FatalError("Failed to find %s() function in %s: %d\n",
                symbol, meta->libraryPath, GetLastError());
#endif
        }
        else
        {
#ifndef WIN32
            ErrorMessage("Failed to find %s() function in %s: %s\n",
                symbol, meta->libraryPath, dlerror());
#else
            ErrorMessage("Failed to find %s() function in %s: %d\n",
                symbol, meta->libraryPath, GetLastError());
#endif
        }
    }

    return symbolPtr;
}

void GetPluginVersion(PluginHandle handle, DynamicPluginMeta* meta)
{
    LibVersionFunc libVersionFunc = NULL;

    libVersionFunc = (LibVersionFunc)getSymbol(handle, "LibVersion", meta, FATAL);

    if (libVersionFunc != NULL)
    {
        libVersionFunc(meta);
    }
}

PluginHandle openDynamicLibrary(char *library_name, int useGlobal)
{
    PluginHandle handle;
#ifndef WIN32
    handle = dlopen(library_name, RTLD_NOW | (useGlobal ? RTLD_GLOBAL: 0));
#else
    handle = LoadLibrary(library_name);
#endif
    if (handle == NULL)
    {
#ifndef WIN32
        FatalError("Failed to load %s: %s\n", library_name, dlerror());
#else
        FatalError("Failed to load %s: %d\n", library_name, GetLastError());
#endif
    }
    return handle;
}

void LoadAllLibs(char *path, LoadLibraryFunc loadFunc)
{
#ifndef WIN32
    char path_buf[PATH_MAX];
    struct dirent *dirEntry;
    DIR *directory;
    int  count = 0;

    directory = opendir(path);
    if (directory)
    {
        dirEntry = readdir(directory);
        while (dirEntry)
        {
            if (dirEntry->d_reclen &&
                !fnmatch(EXT, dirEntry->d_name, FNM_PATHNAME | FNM_PERIOD))
            {
                SnortSnprintf(path_buf, PATH_MAX, "%s%s%s", path, "/", dirEntry->d_name);
                loadFunc(path_buf, 1);
                count++;
            }
            dirEntry = readdir(directory);
        }
        closedir(directory);
#ifdef OPENBSD
        directory = opendir(path);
        if (directory)
        {
            dirEntry = readdir(directory);
            while (dirEntry)
            {
                if (dirEntry->d_reclen &&
                    !fnmatch(EXT2, dirEntry->d_name, FNM_PATHNAME | FNM_PERIOD))
                {
                    SnortSnprintf(path_buf, PATH_MAX, "%s%s%s", path, "/", dirEntry->d_name);
                    loadFunc(path_buf, 1);
                    count++;
                }
                dirEntry = readdir(directory);
            }
        }
        closedir(directory);
#endif
        if ( count == 0 )
        {
            LogMessage("Warning: No dynamic libraries found in directory %s!\n", path);
        }
    }
    else
    {
        LogMessage("Warning: Directory %s does not exist!\n", path);
    }
#else
    /* Find all shared library files in path */
    char path_buf[PATH_MAX];
    char dyn_lib_name[PATH_MAX];
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    char fname[_MAX_FNAME];
    char ext[_MAX_EXT];
    HANDLE fSearch;
    WIN32_FIND_DATA FindFileData;
    int pathLen = 0;
    char *directory;
    int useDrive = 0;

    if (SnortStrncpy(path_buf, path, PATH_MAX) != SNORT_STRNCPY_SUCCESS)
        FatalError("Path is too long: %s\n", path);

    pathLen = SnortStrnlen(path_buf, PATH_MAX);
    if ((path_buf[pathLen - 1] == '\\') ||
        (path_buf[pathLen - 1] == '/'))
    {
        /* A directory was specified with trailing dir character */
        _splitpath(path_buf, drive, dir, fname, ext);
        _makepath(path_buf, drive, dir, "*", EXT);
        directory = &dir[0];
        useDrive = 1;
    }
    else /* A directory was specified */
    {
        _splitpath(path_buf, drive, dir, fname, ext);
        if (strcmp(ext, ""))
        {
            FatalError("Improperly formatted directory name: %s\n", path);
        }
        _makepath(path_buf, "", path_buf, "*", EXT);
        directory = path;
    }

    fSearch = FindFirstFile(path_buf, &FindFileData);
    while (fSearch != NULL && fSearch != (HANDLE)-1)
    {
        if (useDrive)
            _makepath(dyn_lib_name, drive, directory, FindFileData.cFileName, NULL);
        else
            _makepath(dyn_lib_name, NULL, directory, FindFileData.cFileName, NULL);

        loadFunc(dyn_lib_name, 1);

        if (!FindNextFile(fSearch, &FindFileData))
        {
            break;
        }
    }
    FindClose(fSearch);
#endif
}

void AddEnginePlugin(PluginHandle handle,
                     InitEngineLibFunc initFunc,
                     CompatibilityFunc compatFunc,
                     DynamicPluginMeta *meta)
{
    DynamicEnginePlugin *newPlugin = NULL;
    newPlugin = (DynamicEnginePlugin *)SnortAlloc(sizeof(DynamicEnginePlugin));
    newPlugin->handle = handle;

    if (!loadedEngines)
    {
        loadedEngines = newPlugin;
    }
    else
    {
        newPlugin->next = loadedEngines;
        loadedEngines->prev = newPlugin;
        loadedEngines = newPlugin;
    }

    memcpy(&(newPlugin->metaData), meta, sizeof(DynamicPluginMeta));
    newPlugin->metaData.libraryPath = strdup(meta->libraryPath);
    newPlugin->initFunc = initFunc;
    newPlugin->versCheck = compatFunc;
}

void RemoveEnginePlugin(DynamicEnginePlugin *plugin)
{
    if (!plugin)
        return;

    if (plugin == loadedEngines)
    {
        loadedEngines = loadedEngines->next;
        loadedEngines->prev = NULL;
    }
    else
    {
        if (plugin->prev)
            plugin->prev->next = plugin->next;
        if (plugin->next)
            plugin->next->prev = plugin->prev;
    }
    CloseDynamicLibrary(plugin->handle);
    free(plugin);
}

int ValidateDynamicEngines()
{
    int testNum = 0;
    DynamicEnginePlugin *curPlugin = loadedEngines;
    CompatibilityFunc versFunc = NULL;
	
    while( (void *)curPlugin != NULL)
    {
        versFunc = (CompatibilityFunc)curPlugin->versCheck;
        /* if compatibility checking func is absent, skip validating */
        if( (void *)versFunc != NULL)
        {
            DynamicDetectionPlugin *lib = loadedDetectionPlugins;
            while( (void *)lib != NULL)
            {				
                if (lib->metaData.type == TYPE_DETECTION)					
                {
                    RequiredEngineLibFunc engineFunc;
                    DynamicPluginMeta reqEngineMeta;
					            
                    engineFunc = (RequiredEngineLibFunc) getSymbol(lib->handle, "EngineVersion", &(lib->metaData), 1);
                    if( (void *)engineFunc != NULL)
                    {
                        engineFunc(&reqEngineMeta);
                    }
                    testNum = versFunc(&curPlugin->metaData, &reqEngineMeta);
                    if( testNum ) 
                    {
                        FatalError("Dynamic detection lib %s %d.%d isn't compatible with the current dynamic engine library "
                                "%s %d.%d.\n"
                                "The dynamic detection lib is compiled with an older version of the dynamic engine.\n",
                                lib->metaData.libraryPath, lib->metaData.major, lib->metaData.minor,
                                curPlugin->metaData.libraryPath, curPlugin->metaData.major, curPlugin->metaData.minor);
                    }

                }
                lib = lib->next;
            }
        }
        if( testNum ) break;
        curPlugin = curPlugin->next;
    }
	
    return(testNum);	
}

int LoadDynamicEngineLib(char *library_name, int indent)
{
    /* Presume here, that library name is full path */
    InitEngineLibFunc engineInit;
    CompatibilityFunc compatFunc;
    DynamicPluginMeta metaData;
    PluginHandle handle;

#if 0
#ifdef SUP_IP6
    LogMessage("%sDynamic engine will not be loaded since dynamic detection "
                 "libraries are not yet supported with IPv6.\n", 
                indent?"  ":"");
    return 0;
#endif
#endif

    LogMessage("%sLoading dynamic engine %s... ",
               indent ? "  " : "", library_name);

    handle = openDynamicLibrary(library_name, 1);
    metaData.libraryPath = library_name;

    GetPluginVersion(handle, &metaData);

    /* Just to ensure that the function exists */
    engineInit = (InitEngineLibFunc)getSymbol(handle, "InitializeEngine", &metaData, FATAL);
    compatFunc = (CompatibilityFunc)getSymbol(handle, "CheckCompatibility", &metaData, NONFATAL);

    if (metaData.type != TYPE_ENGINE)
    {
        CloseDynamicLibrary(handle);
        LogMessage("failed, not an Engine\n");
        return 0;
    }   
    
    AddEnginePlugin(handle, engineInit, compatFunc, &metaData);
  
    LogMessage("done\n");
    return 0;
}

void LoadAllDynamicEngineLibs(char *path)
{
    LogMessage("Loading all dynamic engine libs from %s...\n", path);
    LoadAllLibs(path, LoadDynamicEngineLib);
    LogMessage("  Finished Loading all dynamic engine libs from %s\n", path);
}

void CloseDynamicEngineLibs()
{
    DynamicEnginePlugin *tmpplugin, *plugin = loadedEngines;
    while (plugin)
    {
        tmpplugin = plugin->next;
        if (!(plugin->metaData.type & TYPE_DETECTION))
        {
            CloseDynamicLibrary(plugin->handle);
            free(plugin->metaData.libraryPath);
            free(plugin);
        }
        else
        {
            /* NOP, handle will be closed when we close the DetectionLib */
            ;
        }
        plugin = tmpplugin;
    }
    loadedEngines = NULL;
}

void RemovePreprocessorPlugin(DynamicPreprocessorPlugin *plugin)
{
    if (!plugin)
        return;

    if (plugin == loadedPreprocessorPlugins)
    {
        loadedPreprocessorPlugins = loadedPreprocessorPlugins->next;
        loadedPreprocessorPlugins->prev = NULL;
    }
    else
    {
        if (plugin->prev)
            plugin->prev->next = plugin->next;
        if (plugin->next)
            plugin->next->prev = plugin->prev;
    }
    CloseDynamicLibrary(plugin->handle);
    free(plugin);
}

void AddPreprocessorPlugin(PluginHandle handle,
                        InitPreprocessorLibFunc initFunc,
                        DynamicPluginMeta *meta)
{
    DynamicPreprocessorPlugin *newPlugin = NULL;
    newPlugin = (DynamicPreprocessorPlugin *)SnortAlloc(sizeof(DynamicPreprocessorPlugin));
    newPlugin->handle = handle;

    if (!loadedPreprocessorPlugins)
    {
        loadedPreprocessorPlugins = newPlugin;
    }
    else
    {
        newPlugin->next = loadedPreprocessorPlugins;
        loadedPreprocessorPlugins->prev = newPlugin;
        loadedPreprocessorPlugins = newPlugin;
    }

    memcpy(&(newPlugin->metaData), meta, sizeof(DynamicPluginMeta));
    newPlugin->metaData.libraryPath = strdup(meta->libraryPath);
    newPlugin->initFunc = initFunc;
}

void AddDetectionPlugin(PluginHandle handle,
                        InitDetectionLibFunc initFunc,
                        DynamicPluginMeta *meta)
{
    DynamicDetectionPlugin *newPlugin = NULL;
    newPlugin = (DynamicDetectionPlugin *)SnortAlloc(sizeof(DynamicDetectionPlugin));
    newPlugin->handle = handle;

    if (!loadedDetectionPlugins)
    {
        loadedDetectionPlugins = newPlugin;
    }
    else
    {
        newPlugin->next = loadedDetectionPlugins;
        loadedDetectionPlugins->prev = newPlugin;
        loadedDetectionPlugins = newPlugin;
    }

    memcpy(&(newPlugin->metaData), meta, sizeof(DynamicPluginMeta));
    newPlugin->metaData.libraryPath = strdup(meta->libraryPath);
    newPlugin->initFunc = initFunc;
}

void RemoveDetectionPlugin(DynamicDetectionPlugin *plugin)
{
    if (!plugin)
        return;

    if (plugin == loadedDetectionPlugins)
    {
        loadedDetectionPlugins = loadedDetectionPlugins->next;
        loadedDetectionPlugins->prev = NULL;
    }
    else
    {
        if (plugin->prev)
            plugin->prev->next = plugin->next;
        if (plugin->next)
            plugin->next->prev = plugin->prev;
    }
    LogMessage("Unloading dynamic detection library %s version %d.%d.%d\n",
            plugin->metaData.uniqueName,
            plugin->metaData.major,
            plugin->metaData.minor,
            plugin->metaData.build);
    CloseDynamicLibrary(plugin->handle);
    free(plugin);
}

int LoadDynamicDetectionLib(char *library_name, int indent)
{
    DynamicPluginMeta metaData;
    /* Presume here, that library name is full path */
    InitDetectionLibFunc detectionInit;
    PluginHandle handle;

#if 0
#ifdef SUP_IP6
    LogMessage("%sDynamic detection library \"%s\" will not be loaded. Not "
                 "supported with IPv6.\n", indent ? "  " : "", library_name);
    return 0;
#endif
#endif

    LogMessage("%sLoading dynamic detection library %s... ",
               indent ? "  " : "", library_name);

    handle = openDynamicLibrary(library_name, 0);
    metaData.libraryPath = library_name;

    GetPluginVersion(handle, &metaData);

    /* Just to ensure that the function exists */
    detectionInit = (InitDetectionLibFunc)getSymbol(handle, "InitializeDetection", &metaData, FATAL);

    if (!(metaData.type & TYPE_DETECTION))
    {
        CloseDynamicLibrary(handle);
        LogMessage("failed, not a detection library\n");
        return 0;
    }

    if (metaData.type & TYPE_ENGINE)
    {
        /* Do the engine initialization as well */
        InitEngineLibFunc engineInit = (InitEngineLibFunc)getSymbol(handle, "InitializeEngine", &metaData, FATAL);
        CompatibilityFunc compatFunc = (CompatibilityFunc)getSymbol(handle, "CheckCompatibility", &metaData, NONFATAL);

        AddEnginePlugin(handle, engineInit, compatFunc, &metaData);
    }

    AddDetectionPlugin(handle, detectionInit, &metaData);

    LogMessage("done\n");
    return 0;
}

void CloseDynamicDetectionLibs()
{
    DynamicDetectionPlugin *tmpplugin, *plugin = loadedDetectionPlugins;
    while (plugin)
    {
        tmpplugin = plugin->next;
        CloseDynamicLibrary(plugin->handle);
        free(plugin->metaData.libraryPath);
        free(plugin);
        plugin = tmpplugin;
    }
    loadedDetectionPlugins = NULL;
}

void LoadAllDynamicDetectionLibs(char *path)
{
    LogMessage("Loading all dynamic detection libs from %s...\n", path);
    LoadAllLibs(path, LoadDynamicDetectionLib);
    LogMessage("  Finished Loading all dynamic detection libs from %s\n", path);
}

void LoadAllDynamicDetectionLibsCurrPath()
{
    char path_buf[PATH_MAX];
    char *ret = NULL;

    ret = getcwd(path_buf, PATH_MAX);
    if (ret == NULL)
    {
        FatalError("Path to current working directory longer than %d bytes: %s\n"
                   "Could not load dynamic detection libs\n",
                   PATH_MAX, strerror(errno));
    }

    LoadAllDynamicDetectionLibs(path_buf);
}

void RemoveDuplicateEngines()
{
    int removed = 0;
    DynamicEnginePlugin *engine1;
    DynamicEnginePlugin *engine2;
    DynamicPluginMeta *meta1;
    DynamicPluginMeta *meta2;

    /* First the Detection Engines */
    do
    {
        removed = 0;
        engine1 = loadedEngines;
        while (engine1 != NULL)
        {
            engine2 = loadedEngines;
            while (engine2 != NULL)
            {
                /* Obviously, the same ones will be the same */
                if (engine1 != engine2)
                {
                    meta1 = &engine1->metaData;
                    meta2 = &engine2->metaData;
                    if (!strcmp(meta1->uniqueName, meta2->uniqueName))
                    {
                        /* Uh, same uniqueName. */
                        if ((meta1->major > meta2->major) ||
                            ((meta1->major == meta2->major) && (meta1->minor > meta2->minor)) ||
                            ((meta1->major == meta2->major) && (meta1->minor == meta2->minor) && (meta1->build > meta2->build)) )
                        {
                            /* Lib1 is newer */
                            RemoveEnginePlugin(engine2);
                            removed = 1;
                            break;
                        }
                        else if ((meta2->major > meta1->major) ||
                            ((meta2->major == meta1->major) && (meta2->minor > meta1->minor)) ||
                            ((meta2->major == meta1->major) && (meta2->minor == meta1->minor) && (meta2->build > meta1->build)) )
                        {
                            /* Lib2 is newer */
                            RemoveEnginePlugin(engine1);
                            removed = 1;
                            break;
                        }
                        else if ((meta1->major == meta2->major) && (meta1->minor == meta2->minor) && (meta1->build == meta2->build) )
                        {
                            /* Duplicate */
                            RemoveEnginePlugin(engine2);
                            removed = 1;
                            break;
                        }
                    }
                }
                /* If we removed anything, start back at the beginning */
                if (removed)
                    break;
                engine2 = engine2->next;
            }
            /* If we removed anything, start back at the beginning */
            if (removed)
                break;
            engine1 = engine1->next;
        }
    } while (removed);
}

void RemoveDuplicateDetectionPlugins()
{
    int removed = 0;
    DynamicDetectionPlugin *lib1 = NULL;
    DynamicDetectionPlugin *lib2 = NULL;
    DynamicPluginMeta *meta1;
    DynamicPluginMeta *meta2;

    /* Detection Plugins */
    do
    {
        removed = 0;
        lib1 = loadedDetectionPlugins;
        while (lib1 != NULL)
        {
            lib2 = loadedDetectionPlugins;
            while (lib2 != NULL)
            {
                /* Obviously, the same ones will be the same */
                if (lib1 != lib2)
                {
                    meta1 = &lib1->metaData;
                    meta2 = &lib2->metaData;
                    if (!strcmp(meta1->uniqueName, meta2->uniqueName))
                    {
                        /* Uh, same uniqueName. */
                        if ((meta1->major > meta2->major) ||
                            ((meta1->major == meta2->major) && (meta1->minor > meta2->minor)) ||
                            ((meta1->major == meta2->major) && (meta1->minor == meta2->minor) && (meta1->build > meta2->build)) )
                        {
                            /* Lib1 is newer */
                            RemoveDetectionPlugin(lib2);
                            removed = 1;
                            break;
                        }
                        else if ((meta2->major > meta1->major) ||
                            ((meta2->major == meta1->major) && (meta2->minor > meta1->minor)) ||
                            ((meta2->major == meta1->major) && (meta2->minor == meta1->minor) && (meta2->build > meta1->build)) )
                        {
                            /* Lib2 is newer */
                            RemoveDetectionPlugin(lib1);
                            removed = 1;
                            break;
                        }
                        else if ((meta1->major == meta2->major) && (meta1->minor == meta2->minor) && (meta1->build == meta2->build) )
                        {
                            /* Duplicate */
                            RemoveDetectionPlugin(lib2);
                            removed = 1;
                            break;
                        }
                    }
                }
                /* If we removed anything, start back at the beginning */
                if (removed)
                    break;
                lib2 = lib2->next;
            }
            /* If we removed anything, start back at the beginning */
            if (removed)
                break;
            lib1 = lib1->next;
        }
    } while (removed);
}

void RemoveDuplicatePreprocessorPlugins()
{
    int removed = 0;
    DynamicPreprocessorPlugin *pp1 = NULL;
    DynamicPreprocessorPlugin *pp2 = NULL;
    DynamicPluginMeta *meta1;
    DynamicPluginMeta *meta2;

    /* The Preprocessor Plugins */
    do
    {
        removed = 0;
        pp1 = loadedPreprocessorPlugins;
        while (pp1 != NULL)
        {
            pp2 = loadedPreprocessorPlugins;
            while (pp2 != NULL)
            {
                /* Obviously, the same ones will be the same */
                if (pp1 != pp2)
                {
                    meta1 = &pp1->metaData;
                    meta2 = &pp2->metaData;
                    if (!strcmp(meta1->uniqueName, meta2->uniqueName))
                    {
                        /* Uh, same uniqueName. */
                        if ((meta1->major > meta2->major) ||
                            ((meta1->major == meta2->major) && (meta1->minor > meta2->minor)) ||
                            ((meta1->major == meta2->major) && (meta1->minor == meta2->minor) && (meta1->build > meta2->build)) )
                        {
                            /* Lib1 is newer */
                            RemovePreprocessorPlugin(pp2);
                            removed = 1;
                            break;
                        }
                        else if ((meta2->major > meta1->major) ||
                            ((meta2->major == meta1->major) && (meta2->minor > meta1->minor)) ||
                            ((meta2->major == meta1->major) && (meta2->minor == meta1->minor) && (meta2->build > meta1->build)) )
                        {
                            /* Lib2 is newer */
                            RemovePreprocessorPlugin(pp1);
                            removed = 1;
                            break;
                        }
                        else if ((meta1->major == meta2->major) && (meta1->minor == meta2->minor) && (meta1->build == meta2->build) )
                        {
                            /* Duplicate */
                            RemovePreprocessorPlugin(pp2);
                            removed = 1;
                            break;
                        }
                    }
                }
                /* If we removed anything, start back at the beginning */
                if (removed)
                    break;
                pp2 = pp2->next;
            }
            /* If we removed anything, start back at the beginning */
            if (removed)
                break;
            pp1 = pp1->next;
        }
    } while (removed);
}

void VerifyDetectionPluginRequirements()
{
    DynamicDetectionPlugin *lib1 = NULL;

    /* Remove all the duplicates */
    RemoveDuplicateDetectionPlugins();

    /* Cycle through all of them, and ensure that the required
     * detection engine is loaded.
     */
    lib1 = loadedDetectionPlugins;
    while (lib1 != NULL)
    {
        /* Do this check if this library is a DETECTION plugin only.
         * If it also has an internal engine, we're fine.
         */
        if (lib1->metaData.type == TYPE_DETECTION)
        {
            RequiredEngineLibFunc engineFunc;
            DynamicPluginMeta reqEngineMeta;
            DynamicEnginePlugin *plugin = loadedEngines;
            int detectionLibOkay = 0;

            engineFunc = (RequiredEngineLibFunc) getSymbol(lib1->handle, "EngineVersion", &(lib1->metaData), FATAL);

            engineFunc(&reqEngineMeta);
            while (plugin != NULL)
            {
                /* Exact match.  Yes! */
                if (!strcmp(plugin->metaData.uniqueName, reqEngineMeta.uniqueName) &&
                    plugin->metaData.major == reqEngineMeta.major &&
                    plugin->metaData.minor == reqEngineMeta.minor)
                {
                    detectionLibOkay = 1;
                    break;
                }
    
                /* Major match, minor must be >= */
                if (!strcmp(plugin->metaData.uniqueName, reqEngineMeta.uniqueName) &&
                    plugin->metaData.major == reqEngineMeta.major &&
                    plugin->metaData.minor >= reqEngineMeta.minor)
                {
                    detectionLibOkay = 1;
                    break;
                }

                /* Major must be >= -- this assumes newer engine is
                 * bass-ackwards compatabile */
                if (!strcmp(plugin->metaData.uniqueName, reqEngineMeta.uniqueName) &&
                    plugin->metaData.major > reqEngineMeta.major)
                {
                    detectionLibOkay = 1;
                    break;
                }

                plugin = plugin->next;
            }
            if (!detectionLibOkay)
            {
                FatalError("Loaded dynamic detection plugin %s (version %d:%d:%d) "
                           "could not find required engine plugin %s(version %d:%d)\n",
                            lib1->metaData.uniqueName, lib1->metaData.major, lib1->metaData.minor, lib1->metaData.build,
                            reqEngineMeta.uniqueName, reqEngineMeta.major, reqEngineMeta.minor);
            }
        }

        lib1 = lib1->next;
    }
}

int InitDynamicEnginePlugins(DynamicEngineData *info)
{
    DynamicEnginePlugin *plugin;
    RemoveDuplicateEngines();

    plugin = loadedEngines;
    while (plugin)
    {
        if (plugin->initFunc(info))
        {
            FatalError("Failed to initialize dynamic engine: %s version %d.%d.%d\n", 
                       plugin->metaData.uniqueName, plugin->metaData.major,
                       plugin->metaData.minor, plugin->metaData.build);
            //return -1;
        }

        plugin = plugin->next;
    }
    return 0;
}

void DynamicSetRuleData(void *p, void *data)
{
    Packet *pkt = (Packet *)p;
    if (stream_api && pkt)
    {
        stream_api->set_application_data(pkt->ssnptr, PP_RULES, data, &free);
    }
}

void *DynamicGetRuleData(void *p)
{
    Packet *pkt = (Packet *)p;
    if (stream_api && pkt)
    {
        return stream_api->get_application_data(pkt->ssnptr, PP_RULES);
    }
    return NULL;
}

void *pcreCompile(const char *pattern, int options, const char **errptr, int *erroffset, const unsigned char *tableptr)
{
    options &= ~SNORT_PCRE_OVERRIDE_MATCH_LIMIT;
    return (void *)pcre_compile(pattern, options, errptr, erroffset, tableptr);
}

void *pcreStudy(const void *code, int options, const char **errptr)
{
    pcre_extra *extra_extra;
    int snort_options = options & SNORT_PCRE_OVERRIDE_MATCH_LIMIT;

    extra_extra = pcre_study((const pcre*)code, 0, errptr);

#define SNORT_PCRE_MATCH_LIMIT pv.pcre_match_limit
#define SNORT_PCRE_MATCH_LIMIT_RECURSION pv.pcre_match_limit_recursion
    if (extra_extra)
    {
        if ((SNORT_PCRE_MATCH_LIMIT != -1) && !(snort_options & SNORT_PCRE_OVERRIDE_MATCH_LIMIT))
        {
            if (extra_extra->flags & PCRE_EXTRA_MATCH_LIMIT)
            {
                extra_extra->match_limit = SNORT_PCRE_MATCH_LIMIT;
            }
            else
            {
                extra_extra->flags |= PCRE_EXTRA_MATCH_LIMIT;
                extra_extra->match_limit = SNORT_PCRE_MATCH_LIMIT;
            }
        }

#ifdef PCRE_EXTRA_MATCH_LIMIT_RECURSION
        if ((SNORT_PCRE_MATCH_LIMIT_RECURSION != -1) && !(snort_options & SNORT_PCRE_OVERRIDE_MATCH_LIMIT))
        {
            if (extra_extra->flags & PCRE_EXTRA_MATCH_LIMIT_RECURSION)
            {
                extra_extra->match_limit_recursion = SNORT_PCRE_MATCH_LIMIT_RECURSION;
            }
            else
            {
                extra_extra->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
                extra_extra->match_limit_recursion = SNORT_PCRE_MATCH_LIMIT_RECURSION;
            }
        }
#endif
    }
    else
    {
        if (!(snort_options & SNORT_PCRE_OVERRIDE_MATCH_LIMIT) &&
            ((SNORT_PCRE_MATCH_LIMIT != -1) || (SNORT_PCRE_MATCH_LIMIT_RECURSION != -1)))
        {
            extra_extra = (pcre_extra *)SnortAlloc(sizeof(pcre_extra));
            if (SNORT_PCRE_MATCH_LIMIT != -1)
            {
                extra_extra->flags |= PCRE_EXTRA_MATCH_LIMIT;
                extra_extra->match_limit = SNORT_PCRE_MATCH_LIMIT;
            }

#ifdef PCRE_EXTRA_MATCH_LIMIT_RECURSION
            if (SNORT_PCRE_MATCH_LIMIT_RECURSION != -1)
            {
                extra_extra->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
                extra_extra->match_limit_recursion = SNORT_PCRE_MATCH_LIMIT_RECURSION;
            }
#endif
        }
    }

    return extra_extra;
}

int pcreExec(const void *code, const void *extra, const char *subj, int len, int start, int options, int *ovec, int ovecsize)
{
    return pcre_exec((const pcre *)code, (const pcre_extra *)extra, subj, len, start, options, ovec, ovecsize);
}

int InitDynamicEngines()
{
    int i;
    DynamicEngineData engineData;

    engineData.version = ENGINE_DATA_VERSION;
    engineData.altBuffer = &DecodeBuffer[0];
    for (i=0;i<MAX_URIINFOS;i++)
        engineData.uriBuffers[i] = (UriInfo*)&UriBufs[i];
    /* This is defined in dynamic-plugins/sp_dynamic.h */
    engineData.ruleRegister = &RegisterDynamicRule;
    engineData.flowbitRegister = &DynamicFlowbitRegister;
    engineData.flowbitCheck = &DynamicFlowbitCheck;
    engineData.asn1Detect = &DynamicAsn1Detect;

    /* Pull this out of pv.dynamic_rules_path */
    engineData.dataDumpDirectory = pv.dynamic_rules_path;
    engineData.logMsg = &LogMessage;
    engineData.errMsg = &ErrorMessage;
    engineData.fatalMsg = &FatalError;

    engineData.getPreprocOptFuncs = &GetPreprocessorRuleOptionFuncs;

    engineData.setRuleData = &DynamicSetRuleData;
    engineData.getRuleData = &DynamicGetRuleData;

    engineData.debugMsg = &DebugMessageFunc;
#ifdef HAVE_WCHAR_H
    engineData.debugWideMsg = &DebugWideMessageFunc;
#endif
#ifdef DEBUG
    engineData.debugMsgFile = &DebugMessageFile;
    engineData.debugMsgLine = &DebugMessageLine;
#else
    engineData.debugMsgFile = &no_file;
    engineData.debugMsgLine = &no_line;
#endif

    engineData.pcreStudy = &pcreStudy;
    engineData.pcreCompile = &pcreCompile;
    engineData.pcreExec = &pcreExec;

    return InitDynamicEnginePlugins(&engineData);
}

int InitDynamicPreprocessorPlugins(DynamicPreprocessorData *info)
{
    DynamicPreprocessorPlugin *plugin;
    RemoveDuplicatePreprocessorPlugins();

    plugin = loadedPreprocessorPlugins;
    while (plugin)
    {
        if (plugin->initFunc(info))
        {
            FatalError("Failed to initialize dynamic preprocessor: %s version %d.%d.%d\n", 
                       plugin->metaData.uniqueName, plugin->metaData.major,
                       plugin->metaData.minor, plugin->metaData.build);
            //return -1;
        }

        plugin = plugin->next;
    }
    return 0;
}

/* Do this to avoid exposing Packet & PreprocessFuncNode from
 * snort to non-GPL code */
typedef void (*SnortPacketProcessFunc)(Packet *, void *);
void *AddPreprocessor(void (*func)(void *, void *), unsigned short priority,
                      unsigned int preproc_id, uint32_t proto_mask)
{
    SnortPacketProcessFunc preprocessorFunc = (SnortPacketProcessFunc)func;
    return (void *)AddFuncToPreprocList(preprocessorFunc, priority, preproc_id, proto_mask);
}

void *AddPreprocessorCheck(void (*func)(void))
{
    return (void *)AddFuncToConfigCheckList(func);
}

void DynamicDisableDetection(void *p)
{
    DisableDetect((Packet *)p);
}

void DynamicDisableAllDetection(void *p)
{
    DisableAllDetect((Packet *)p);
}

int DynamicDetect(void *p)
{
    return Detect((Packet *)p);
}

int DynamicSetPreprocessorBit(void *p, unsigned int preprocId)
{
    return SetPreprocBit((Packet *)p, preprocId);
}

int DynamicSetPreprocessorGetReassemblyPktBit(void *p, unsigned int preprocId)
{
    return SetPreprocGetReassemblyPktBit((Packet *)p, preprocId);
}

int DynamicDropInline(void *p)
{
    return InlineDrop((Packet *)p);
}

void *DynamicGetRuleClassByName(char *name)
{
    return (void *)ClassTypeLookupByType(name);
}

void *DynamicGetRuleClassById(int id)
{
    return (void *)ClassTypeLookupById(id);
}

void DynamicRegisterPreprocessorProfile(char *keyword, void *stats, int layer, void *parent)
{
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile(keyword, (PreprocStats *)stats, layer, (PreprocStats *)parent);
#endif
}

int DynamicProfilingPreprocs()
{
#ifdef PERF_PROFILING
    return pv.profile_preprocs_flag;
#else
    return 0;
#endif
}

int DynamicPreprocess(void *packet)
{
    return Preprocess((Packet*)packet);
}

void DynamicDisablePreprocessors(void *p)
{
    DisablePreprocessors((Packet *)p);
}

#ifdef SUP_IP6
void DynamicIP6Build(void *p, const void *hdr, int family)
{
    sfiph_build((Packet *)p, hdr, family);
}

static INLINE void DynamicIP6SetCallbacks(void *p, int family, char orig)
{
    set_callbacks((Packet *)p, family, orig);
}
#endif

int DynamicSnortEventqLog(void *p)
{
    return SnortEventqLog((Packet *)p);
}

int InitDynamicPreprocessors()
{
    int i;
    DynamicPreprocessorData preprocData;

    preprocData.version = PREPROCESSOR_DATA_VERSION;
    preprocData.altBuffer = &DecodeBuffer[0];
    preprocData.altBufferLen = DECODE_BLEN;
    for (i=0;i<MAX_URIINFOS;i++)
        preprocData.uriBuffers[i] = (UriInfo*)&UriBufs[i];

    /* Pull this out of pv.dynamic_rules_path */
    preprocData.logMsg = &LogMessage;
    preprocData.errMsg = &ErrorMessage;
    preprocData.fatalMsg = &FatalError;
    preprocData.debugMsg = &DebugMessageFunc;
#ifdef HAVE_WCHAR_H
    preprocData.debugWideMsg = &DebugWideMessageFunc;
#endif
    
    preprocData.registerPreproc = &RegisterPreprocessor;
    preprocData.addPreproc = &AddPreprocessor;
    preprocData.addPreprocRestart = &AddFuncToPreprocRestartList;
    preprocData.addPreprocExit = &AddFuncToPreprocCleanExitList;
    preprocData.addPreprocConfCheck = &AddPreprocessorCheck;
    preprocData.preprocOptRegister = &RegisterPreprocessorRuleOption;
    preprocData.addPreprocProfileFunc = &DynamicRegisterPreprocessorProfile;
    preprocData.profilingPreprocsFunc = &DynamicProfilingPreprocs;
#ifdef PERF_PROFILING
    preprocData.totalPerfStats = &totalPerfStats;
#else
    preprocData.totalPerfStats = NULL;
#endif

    preprocData.alertAdd = &SnortEventqAdd;
    preprocData.thresholdCheck = &sfthreshold_test;

    preprocData.inlineMode = &InlineMode;
    preprocData.inlineDrop = &DynamicDropInline;

    preprocData.detect = &DynamicDetect;
    preprocData.disableDetect = &DynamicDisableDetection;
    preprocData.disableAllDetect = &DynamicDisableAllDetection;
    preprocData.setPreprocBit = &DynamicSetPreprocessorBit;

    preprocData.streamAPI = stream_api;
    preprocData.searchAPI = search_api;

    preprocData.config_file = &file_name;
    preprocData.config_line = &file_line;
    preprocData.printfappend = &sfsnprintfappend;
    preprocData.tokenSplit = &mSplit;
    preprocData.tokenFree = &mSplitFree;

    preprocData.getRuleInfoByName = &DynamicGetRuleClassByName;
    preprocData.getRuleInfoById = &DynamicGetRuleClassById;

    preprocData.preprocess = &DynamicPreprocess;

#ifdef DEBUG
    preprocData.debugMsgFile = &DebugMessageFile;
    preprocData.debugMsgLine = &DebugMessageLine;
#else
    preprocData.debugMsgFile = &no_file;
    preprocData.debugMsgLine = &no_line;
#endif

    preprocData.registerPreprocStats = &RegisterPreprocStats;
    preprocData.addPreprocReset = &AddFuncToPreprocResetList;
    preprocData.addPreprocResetStats = &AddFuncToPreprocResetStatsList;
    preprocData.addPreprocGetReassemblyPkt = &AddFuncToPreprocGetReassemblyPktList;
    preprocData.setPreprocGetReassemblyPktBit = &DynamicSetPreprocessorGetReassemblyPktBit;
    preprocData.disablePreprocessors = &DynamicDisablePreprocessors;

#ifdef SUP_IP6
    preprocData.ip6Build = &DynamicIP6Build;
    preprocData.ip6SetCallbacks = &DynamicIP6SetCallbacks;
#endif

    preprocData.logAlerts = &DynamicSnortEventqLog;
    preprocData.resetAlerts = &SnortEventqReset;

#ifdef TARGET_BASED
    preprocData.findProtocolReference = &FindProtocolReference;
    preprocData.addProtocolReference = &AddProtocolReference;
    preprocData.isAdaptiveConfigured = &IsAdaptiveConfigured;
#endif

    preprocData.preprocOptOverrideKeyword = &RegisterPreprocessorRuleOptionOverride;
    preprocData.isPreprocEnabled = &IsPreprocEnabled;

    return InitDynamicPreprocessorPlugins(&preprocData);
}

int InitDynamicDetectionPlugins()
{
    DynamicDetectionPlugin *plugin;
    VerifyDetectionPluginRequirements();

    plugin = loadedDetectionPlugins;
    while (plugin)
    {
        if (plugin->initFunc())
        {
            ErrorMessage("Failed to initialize dynamic detection library: "
                    "%s version %d.%d.%d\n", 
                    plugin->metaData.uniqueName,
                    plugin->metaData.major,
                    plugin->metaData.minor,
                    plugin->metaData.build);
            return -1;
        }
        plugin = plugin->next;
    }
    return 0;
}

int DumpDetectionLibRules()
{
    DynamicDetectionPlugin *plugin = loadedDetectionPlugins;
    DumpDetectionRules ruleDumpFunc = NULL;
    int retVal = 0;

    LogMessage("Dumping dynamic rules...\n");
    while (plugin)
    {
        ruleDumpFunc = (DumpDetectionRules) getSymbol(plugin->handle, "DumpSkeletonRules", &(plugin->metaData), NONFATAL);

        LogMessage("Dumping dynamic rules for Library %s %d.%d.%d\n",
            plugin->metaData.uniqueName,
            plugin->metaData.major,
            plugin->metaData.minor,
            plugin->metaData.build);
        if (ruleDumpFunc != NULL)
        {
            if (ruleDumpFunc())
            {
                LogMessage("Failed to open rules file %s for writing\n");
            }
        }
        plugin = plugin->next;
    }
    LogMessage("  Finished dumping dynamic rules.\n");
    return retVal;
}

int LoadDynamicPreprocessor(char *library_name, int indent)
{
    DynamicPluginMeta metaData;
    /* Presume here, that library name is full path */
    InitPreprocessorLibFunc preprocInit;
    PluginHandle handle;

    LogMessage("%sLoading dynamic preprocessor library %s... ",
               indent ? "  " : "", library_name);

    handle = openDynamicLibrary(library_name, 1);
    metaData.libraryPath = library_name;

    GetPluginVersion(handle, &metaData);

    /* Just to ensure that the function exists */
    preprocInit = (InitPreprocessorLibFunc) getSymbol(handle, "InitializePreprocessor", &metaData, FATAL);

    if (metaData.type != TYPE_PREPROCESSOR)
    {
        CloseDynamicLibrary(handle);
        LogMessage("failed, not a preprocessor library\n");
        return 0;
    }

    AddPreprocessorPlugin(handle, preprocInit, &metaData);

    LogMessage("done\n");
    return 0;
}

void LoadAllDynamicPreprocessors(char *path)
{
    LogMessage("Loading all dynamic preprocessor libs from %s...\n", path);
    LoadAllLibs(path, LoadDynamicPreprocessor);
    LogMessage("  Finished Loading all dynamic preprocessor libs from %s\n", path);
}

void CloseDynamicPreprocessorLibs()
{
    DynamicPreprocessorPlugin *tmpplugin, *plugin = loadedPreprocessorPlugins;
    while (plugin)
    {
        tmpplugin = plugin->next;
        CloseDynamicLibrary(plugin->handle);
        free(plugin->metaData.libraryPath);
        free(plugin);
        plugin = tmpplugin;
    }
    loadedPreprocessorPlugins = NULL;
}
void *GetNextEnginePluginVersion(void *p)
{
    DynamicEnginePlugin *lib = (DynamicEnginePlugin *) p;

    if ( lib != NULL )
    {
        lib = lib->next;
    }
    else
    {
        lib = loadedEngines;
    }

    if ( lib == NULL )
    {
        return lib;
    }

    return (void *) lib;      
}

void *GetNextDetectionPluginVersion(void *p)
{
    DynamicDetectionPlugin *lib = (DynamicDetectionPlugin *) p;

    if ( lib != NULL )
    {
        lib = lib->next;
    }
    else
    {
        lib = loadedDetectionPlugins;
    }

    if ( lib == NULL )
    {
        return lib;
    }

    return (void *) lib;      
}

void *GetNextPreprocessorPluginVersion(void *p)
{
    DynamicPreprocessorPlugin *lib = (DynamicPreprocessorPlugin *) p;

    if ( lib != NULL )
    {
        lib = lib->next;
    }
    else
    {
        lib = loadedPreprocessorPlugins;
    }

    if ( lib == NULL )
    {
        return lib;
    }

    return (void *) lib;      
}

DynamicPluginMeta *GetDetectionPluginMetaData(void *p)
{
    DynamicDetectionPlugin *lib = (DynamicDetectionPlugin *) p;
    DynamicPluginMeta *meta;

    meta = &(lib->metaData);

    return meta;    
}

DynamicPluginMeta *GetEnginePluginMetaData(void *p)
{
    DynamicEnginePlugin *lib = (DynamicEnginePlugin *) p;
    DynamicPluginMeta *meta;

    meta = &(lib->metaData);

    return meta;    
}

DynamicPluginMeta *GetPreprocessorPluginMetaData(void *p)
{
    DynamicPreprocessorPlugin *lib = (DynamicPreprocessorPlugin *) p;
    DynamicPluginMeta *meta;

    meta = &(lib->metaData);

    return meta;    
}

#endif /* DYNAMIC_PLUGIN */
