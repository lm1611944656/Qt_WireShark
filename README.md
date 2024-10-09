# Qt_WireShark
## 第1章 项目流程

1. 鼠标点击时, 打开一个网络设备，获取网络句柄(网络句柄相当于文件描述符)

```c
#include <fcntl.h>   // open()
#include <unistd.h>  // read(), write(), close()
#include <stdio.h>   // perror()

int main() {
    int fd;
    char buffer[128];
    ssize_t bytesRead;

    // 打开一个文件，O_RDONLY 表示以只读模式打开
    fd = open("example.txt", O_RDONLY);
    if (fd == -1) {
        perror("Error opening file");
        return 1;
    }

    // 读取文件内容并输出到标准输出
    while ((bytesRead = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytesRead] = '\0';  // 添加字符串结束符
        write(STDOUT_FILENO, buffer, bytesRead);  // STDOUT_FILENO == 1 (标准输出)
    }

    // 关闭文件描述符
    close(fd);

    return 0;
}
```

网络句柄相当于fd(fd就表示文本文件)；所以pointer就是网络句柄

```c++
// 点击按钮，打开网络设备
int res = capture();
			|
            |
            |
           \|/
pointer = pcap_open_live(m_currDevice->name, 65536, 1, 1000, errbuf);
			|
            |
            |
           \|/
// 将网络句柄传递给子线程，并且启动子线程
m_childThread->setFlag();
m_childThread->setPointer(pointer);
m_childThread->start();
isStart = true;
			|
            |
            |
           \|/
// 子线程就开始处理
void MulThread::run(){}
			|
            |
            |
           \|/
// 将文件句柄打开，得到报文头header，得到报文体pkt_data
int res = pcap_next_ex(pointer, &header, &pkt_data);
			|
            |
            |
           \|/
// 该函数就拿着报文体去解析，返回解析到的信息info
int type = ethernetPackageHandle(pkt_data, info);
			|
            |
            |
           \|/
// 解析到的数据就存放到DataPackage对象中
if(type){
    DataPackage data;
    int len = header->len;
    data.setPackageType(type);
    data.setTimeStamp(QString(timeString));
    data.setDataLength(len);
    data.setPackagePointer(pkt_data, len);
    data.setPackageInfo(info);
    
			|
            |
            |
           \|/
// 将自定义对象通过信号返回给主线程
    if(data.pkt_content != nullptr){
        // 返回数据给主线程
        emit sign_send(data);
        number_package++;
    }else {
        continue;
    }
}else{
    continue;
}
			|
            |
            |
           \|/
// 处理子线程的返回的数据(将数据填入表格中)
connect(m_childThread, &MulThread::sign_send, this, &CMainWind::handleMessage);
			|
            |
            |
           \|/
// 当表的某一行被点击时，解析某一行的数据，将解析的数据存放到树中
connect(m_dataPacketTable, &QTableWidget::cellClicked, this, &CMainWind::onTableCellClicked);
```

## 第2章 注意事项

2.1 自定义类，需要在信号和槽中传递需要先注册；

```c++
DataPackage::DataPackage()
{
    //  将自定义类DataPackage，注册到QT中
    qRegisterMetaType<DataPackage>("DataPackage");
    this->timeStamp = "";
    this->data_length = 0;
    this->packageType = 0;
    this->pkt_content = nullptr;
}
```

2.2 禁止表格中的某一项或者某一行，或者树中的某一个item被编辑需要自定义委托类

```c++
#ifndef READONLYDELEGATE_H
#define READONLYDELEGATE_H

#include <QItemDelegate>

class ReadOnlyDelegate : public QItemDelegate
{
public:
    explicit ReadOnlyDelegate(QObject *parent = nullptr);

    ~ReadOnlyDelegate();

    // 重新createEditor
    QWidget *createEditor(QWidget *parent,
                          const QStyleOptionViewItem &option,
                          const QModelIndex &index) const override;

};

#endif // READONLYDELEGATE_H
```



```c++
#include "readonlydelegate.h"


ReadOnlyDelegate::ReadOnlyDelegate(QObject *parent)
    : QItemDelegate{parent}
{

}

ReadOnlyDelegate::~ReadOnlyDelegate()
{

}

QWidget *ReadOnlyDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    Q_UNUSED(parent)
    Q_UNUSED(option)
    Q_UNUSED(index)
    return NULL;
}
```





使用方法

```c++
m_readOnlyDelegate = new ReadOnlyDelegate();

// 为表格的某一列设置只读委托，比如第1列
//table.setItemDelegateForColumn(1, m_readOnlyDelegate);

// 为表格设置只读委托
table.setItemDelegate(m_readOnlyDelegate);
```





