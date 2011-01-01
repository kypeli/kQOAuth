TARGET = ft_kqoauth
TEMPLATE = app

DEFINES += UNIT_TEST
#include(../../kqoauth.prf)

QT += testlib network
QT -= gui
CONFIG += crypto

macx {
    CONFIG -= app_bundle    
    LIBS += -F../../lib -framework kqoauth
}
else:unix {
  # the second argument (after colon) is for
  # being able to run make check from the root source directory
  LIBS += -Wl,-rpath,../../lib:lib
}
else:windows {
  LIBS += -L../../lib -lkqoauthd0
}

INCLUDEPATH += . ../../src
HEADERS += ft_kqoauth.h
SOURCES += ft_kqoauth.cpp
