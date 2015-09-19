/*
 *  Collin's Dynamic Dalvik Instrumentation Toolkit for Android
 *  Collin Mulliner <collin[at]mulliner.org>
 *
 *  (c) 2012,2013
 *
 *  License: LGPL v2.1
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <string.h>
#include <termios.h>
#include <pthread.h>
#include <jni.h>
#include <stdlib.h>
#include "dexstuff.h"
#include "dalvik_hook.h"
#include "log.h"

static struct hook_t eph;
static struct dexstuff_t d;
static struct dalvik_hook_t dpdu;

// switch for debug output of dalvikhook and dexstuff code
static int debug;

static jstring my_dispatch(JNIEnv *env, jobject obj, jstring pdu)
{
	/*
	LOGI("env = 0x%x\n", env)
	LOGI("obj = 0x%x\n", obj)
	LOGI("pdu = 0x%x\n", pdu)
	*/
		
	// load dex classes
	int cookie = dexstuff_loaddex(&d, "/data/local/tmp/injectclasses.dex");
	LOGI("libsmsdispatch: loaddex res = %x\n", cookie);
	if (!cookie)
		LOGI("libsmsdispatch: make sure /data/dalvik-cache/ is world writable and delete data@local@tmp@ddiclasses.dex\n");
	void *clazz = dexstuff_defineclass(&d, "com/list3nt0/dalvikhookmethod/InjectClass", cookie);
	LOGI("libsmsdispatch: clazz = 0x%x\n", clazz);

	// call constructor and passin the pdu
	jclass smsd = (*env)->FindClass(env, "com/list3nt0/dalvikhookmethod/InjectClass");
	jmethodID constructor = (*env)->GetMethodID(env, smsd, "<init>", "(Ljava/lang/String;)V");
	if (constructor) { 
        jvalue args[1];
        args[0].l = pdu;

		jobject obj = (*env)->NewObjectA(env, smsd, constructor, args);      
		LOGI("libsmsdispatch: new obj = 0x%x\n", obj);
		
		if (!obj)
			LOGI("libsmsdispatch: failed to create smsdispatch class, FATAL!\n");
	}
	else {
		LOGI("libsmsdispatch: constructor not found!\n");
	}

	// call original SMS dispatch method
	jvalue args[1];
	args[0].l = pdu;
    dalvik_prepare(&d, &dpdu, env);
    (*env)->CallObjectMethod(env, obj, dpdu.mid, pdu);
	LOGI("success calling : %s\n", dpdu.method_name);
	dalvik_postcall(&d, &dpdu);
    jstring re = (*env)->NewStringUTF(env,"233");
    return re;
}

void my_init(void)
{
	LOGI("libsmsdispatch: started\n");
 
 	debug = 1;

	// resolve symbols from DVM
	dexstuff_resolv_dvm(&d);
    LOGI("dexstuff_resolv_dvm done!");	
	// hook
	dalvik_hook_setup(&dpdu, "Lcom/example/ddihookdemo/MainActivity;", "getText", "(Ljava/lang/String;)Ljava/lang/String;", 2, my_dispatch);
	dalvik_hook(&d, &dpdu);
    
}

int hook_entry(char *a)
{
    LOGI("Get In");
    my_init();
    return 0;
}
