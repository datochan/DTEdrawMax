#ifndef DTPATCHER_H
#define DTPATCHER_H

#include <string.h>
#include <QByteArray>
#include <QThread>
#include <dlfcn.h>

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include "dtpatcher_global.h"

class Monitor : public QThread
{
Q_OBJECT
public:
    Monitor();
    void patchObjectModuleAddr(u_int64_t *addr, u_int64_t value);

protected:
    void run();

private:
    u_int64_t *objectMoudleAddr;
    u_int64_t objectMoudleValue;
};

extern const char g_public_key[];

#endif // DTPATCHER_H
