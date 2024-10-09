QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# 引用 3rd_npcap.pri 文件
include($$PWD/npcap/3rd_npcap.pri)

# 添加源文件
SOURCES += \
    datapackage.cpp \
    main.cpp \
    cmainwind.cpp \
    multhread.cpp \
    readonlydelegate.cpp

# 添加头文件
HEADERS += \
    cmainwind.h \
    datapackage.h \
    format.h \
    multhread.h \
    readonlydelegate.h

# 指定头文件路径
INCLUDEPATH += $$PWD/npcap/Include

# 添加windos系统下用于socket网络编程的动态库
LIBS += -L$$PWD -lws2_32

# 添加静态库
LIBS += -L$$PWD\npcap\Lib\x64\ -lwpcap

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

# 添加资源文件
RESOURCES += \
    res.qrc


