#ifndef MULTHREAD_H
#define MULTHREAD_H

#include <QObject>
#include <QThread>
#include "pcap.h"
#include "datapackage.h"

class MulThread : public QThread
{
    Q_OBJECT

signals:
    void sign_send(DataPackage data);

public:
    explicit MulThread(QObject *parent = nullptr);
    void run() override;
    bool setPointer(pcap_t *pointer);
    void setFlag();
    void resetFlag();

    //
    QString byteToHex(u_char *str, int size);

    // 以太网数据包的处理
    int ethernetPackageHandle(const u_char *pkt_content,QString& info);

    // ip数据包的处理
    int ipPackageHandle(const u_char *pkt_content,int &ipPackge);

    // ICMP数据包的处理
    QString icmpPackageHandle(const u_char *pkt_content);

    // TCP数据包的处理
    int tcpPackageHandle(const u_char *pkt_content,QString &info,int ipPackage);

    // UDP数据包的处理
    int udpPackageHandle(const u_char *pkt_content,QString&info);

    // DNS数据包的处理
    QString dnsPackageHandle(const u_char *pkt_content);

    // ARP数据包的处理
    QString arpPackageHandle(const u_char *pkt_content);


private:
    /*用于描述打开的网络设备的结构*/
    pcap_t *pointer;

    /*pcap_pkthdr 结构包含了关于捕获的数据包的头信息，
     * 包括时间戳、捕获的长度和原始数据包的长度*/
    struct pcap_pkthdr *header;

    /*pkt_data用于指向捕获的数据包的实际数据内容*/
    const u_char *pkt_data;

    /*用于存储和处理网络数据包的捕获时间*/
    time_t local_time_version_sec;

    /*使用此结构来将 time_t 类型的时间戳转换为人类可读的格式，
     * 方便在界面或日志中显示*/
    struct tm local_time;

    /*用于存储时间字符串，通常格式化为可读的时间表示
     * （例如“YYYY-MM-DD HH:MM”）*/
    char timeString[16];

    /*线程是否结束了*/
    volatile bool isDone;// done flag
};

#endif // MULTHREAD_H
