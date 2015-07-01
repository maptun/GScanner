#-------------------------------------------------
#
# Project created by QtCreator 2015-06-16T17:15:45
#
#-------------------------------------------------

QT       += core gui network concurrent

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += C++11
TARGET = Scanner
TEMPLATE = app


SOURCES += main.cpp\
        dialog.cpp

HEADERS  += dialog.h

FORMS    += dialog.ui


RESOURCES += \
    scan.qrc

DISTFILES +=
