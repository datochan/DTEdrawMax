#-------------------------------------------------
#
# Project created by QtCreator 2018-05-21T15:01:56
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = DTEdrawKeygen
TEMPLATE = app

LIBS += -L /usr/local/Cellar/openssl/1.0.2o_1/lib -lcrypto
LIBS += -L /usr/local/Cellar/openssl/1.0.2o_1/lib -lssl

INCLUDEPATH += $$quote(/usr/local/Cellar/openssl/1.0.2o_1/include)

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

ICON     = app.icns

SOURCES += main.cpp\
        etedrawkeygendialog.cpp \
    rsasignature.cpp

HEADERS  += etedrawkeygendialog.h \
    rsasignature.h

FORMS    += etedrawkeygendialog.ui
