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
  LIBS += -L../../lib -lkqoauth
}
else:windows {
  LIBS += -L../../lib -lkqoauth0
}

INCLUDEPATH += . ../../src
HEADERS += ft_kqoauth.h
SOURCES += ft_kqoauth.cpp
