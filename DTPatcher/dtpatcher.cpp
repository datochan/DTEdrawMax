#include "dtpatcher.h"

Monitor *g_watch_dog = NULL;
const char g_public_key[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDi/uSF8XFBK7kJTcuO19uu9fO9\n"
        "zoYJqqy86P9lS7axqYogUTmPRORtW7nifW0O2/0y50BGO6CXh9tZZZOIcbg7ZL/O\n"
        "tTL7MVuUM36J3tEJBZ8aIvfgQ84PZmlmGXUvmx0ivZpH1J9VDPMUv/RKOkOtu1Hq\n"
        "BMVqSUXGfYUvGixpdQIDAQAB\n"
        "-----END PUBLIC KEY-----";

Monitor::Monitor()
{
}

void Monitor::patchObjectModuleAddr(u_int64_t *addr, u_int64_t value)
{
    objectMoudleAddr = addr;
    objectMoudleValue = value;
}

void Monitor::run()
{
    while(true)
    {
        // 补丁: 替换原有的公钥
        if ( *objectMoudleAddr != 0 ) {
            *objectMoudleAddr = objectMoudleValue;
            break;
        }

        msleep(10);
    }
}

__attribute__((constructor)) static void EntryPoint()
{
    g_watch_dog = new Monitor();

    QByteArray *publicKey = new QByteArray(QString(g_public_key).toUtf8());

    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        char *image_name = (char *)_dyld_get_image_name(i);

        if ( strstr(image_name, "libObjectModule") ) {
            u_int64_t baseAddr = _dyld_get_image_vmaddr_slide(i);
            u_int64_t offsetAddr = 0x535be0;

            // 定位到要Patch的模块，根据偏移直接计算数据并覆盖
            g_watch_dog->patchObjectModuleAddr((u_int64_t*)(baseAddr+offsetAddr), *(u_int64_t*)publicKey);

            g_watch_dog->start();
        }
    }

}
