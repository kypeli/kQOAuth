TARGET = ut_kqoauth
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

INCLUDEPATH += . ../../src
HEADERS += ut_kqoauth.h
SOURCES += ut_kqoauth.cpp
