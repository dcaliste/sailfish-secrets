TEMPLATE=app
TARGET=pinentry
QT-=gui

LIBS += -lassuan -lgpg-error
LIBS += -L../../lib/Secrets -lsailfishsecrets

INCLUDEPATH += ../../lib

HEADERS += qassuanserver.h
SOURCES += qassuanserver.cpp pinentry.cpp

target.path = $$INSTALL_ROOT/usr/bin
INSTALLS += target
