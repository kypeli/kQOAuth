TARGET = ut_kqoauth
TEMPLATE = app

DEFINES += UNIT_TEST

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
  LIBS += -Wl,-rpath,../../lib:lib -lkqoauth
}
else:windows {
  LIBS += -L../../lib -lkqoauthd0
}

INCLUDEPATH += . ../../src
HEADERS += ut_kqoauth.h
SOURCES += ut_kqoauth.cpp
