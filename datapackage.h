#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H

#include <QString>
#include "Format.h"


/*
 * 该类用于描述数据包信息
 * +-----+------------+
 * | type| infomation |
 * +-----+------------+
 * |  1  |    arp     |
 * +-----+------------+
 * |  2  |    icmp    |
 * +-----+------------+
 * |  3  |    tcp     |
 * +-----+------------+
 * |  4  |    udp     |
 * +-----+------------+
 * |  5  |    dns     |
 * +-----+------------+
 * |  6  |    tls     |
 * +-----+------------+
 * |  7  |    ssl     |
 * +-----+------------+
*/
class DataPackage
{
private:
    u_int data_length; // 数据包长度
    QString timeStamp; // 数据包的时间戳
    QString info;      // 数据包的简要信息
    int packageType;   // 数据包类型

public:
    const u_char *pkt_content; // 数据包内容的指针

protected:
    /*
     * 将字节数组转换为16进制字符串
    */
    static QString byteToHex(u_char *str, int size);
public:
    // 构造函数和析构函数
    DataPackage();
    ~DataPackage() = default;

    // 设置类的属性
    void setDataLength(unsigned int length);                    // 设置数据包长度
    void setTimeStamp(QString timeStamp);                       // 设置时间戳
    void setPackageType(int type);                              // 设置数据包类型
    void setPackagePointer(const u_char *pkt_content, int size);// 设置数据包指针
    void setPackageInfo(QString info);                          // 设置数据包信息

    // 获取类的属性
    QString getDataLength();                  // 获取数据包长度
    QString getTimeStamp();                   // 获取时间戳
    QString getPackageType();                 // 获取数据包类型
    QString getInfo();                        // 获取简要的数据包信息
    QString getSource();                      // 获取数据包的源地址
    QString getDestination();                 // 获取数据包的目的地址

    // 获取MAC地址信息
    QString getDesMacAddr();                  // 获取目标MAC地址
    QString getSrcMacAddr();                  // 获取源MAC地址
    QString getMacType();                     // 获取MAC地址类型

    // 获取IP信息
    QString getDesIpAddr();                   // 获取目标IP地址
    QString getSrcIpAddr();                   // 获取源IP地址
    QString getIpVersion();                   // 获取IP版本
    QString getIpHeaderLength();              // 获取IP头长度
    QString getIpTos();                       // 获取IP服务类型
    QString getIpTotalLength();               // 获取IP总长度
    QString getIpIdentification();            // 获取IP标识符
    QString getIpFlag();                      // 获取IP标志
    QString getIpReservedBit();               // 获取IP保留位
    QString getIpDF();                        // 获取“禁止分段”标志
    QString getIpMF();                        // 获取“更多分段”标志
    QString getIpFragmentOffset();            // 获取IP分片偏移
    QString getIpTTL();                       // 获取IP的生存时间TTL
    QString getIpProtocol();                  // 获取IP协议类型
    QString getIpCheckSum();                  // 获取IP校验和

    // 获取ICMP信息
    QString getIcmpType();                    // 获取ICMP类型
    QString getIcmpCode();                    // 获取ICMP代码
    QString getIcmpCheckSum();                // 获取ICMP校验和
    QString getIcmpIdentification();          // 获取ICMP标识符
    QString getIcmpSequeue();                 // 获取ICMP序列号
    QString getIcmpData(int size);            // 获取ICMP数据

    // 获取ARP信息
    QString getArpHardwareType();             // 获取ARP硬件类型
    QString getArpProtocolType();             // 获取ARP协议类型
    QString getArpHardwareLength();           // 获取ARP硬件长度
    QString getArpProtocolLength();           // 获取ARP协议长度
    QString getArpOperationCode();            // 获取ARP操作码
    QString getArpSourceEtherAddr();          // 获取ARP源以太网地址
    QString getArpSourceIpAddr();             // 获取ARP源IP地址
    QString getArpDestinationEtherAddr();     // 获取ARP目标以太网地址
    QString getArpDestinationIpAddr();        // 获取ARP目标IP地址

    // 获取TCP信息
    QString getTcpSourcePort();               // 获取TCP源端口
    QString getTcpDestinationPort();          // 获取TCP目标端口
    QString getTcpSequence();                 // 获取TCP序列号
    QString getTcpAcknowledgment();           // 获取TCP确认号
    QString getTcpHeaderLength();             // 获取TCP头部长度
    QString getTcpRawHeaderLength();          // 获取TCP原始头部长度
    QString getTcpFlags();                    // 获取TCP标志位
    QString getTcpPSH();                      // 获取TCP PSH标志
    QString getTcpACK();                      // 获取TCP ACK标志
    QString getTcpSYN();                      // 获取TCP SYN标志
    QString getTcpURG();                      // 获取TCP URG标志
    QString getTcpFIN();                      // 获取TCP FIN标志
    QString getTcpRST();                      // 获取TCP RST标志
    QString getTcpWindowSize();               // 获取TCP窗口大小
    QString getTcpCheckSum();                 // 获取TCP校验和
    QString getTcpUrgentPointer();            // 获取TCP紧急指针
    QString getTcpOperationKind(int kind);    // 获取TCP选项类型
    int getTcpOperationRawKind(int offset);   // 获取TCP原始选项类型

    /*
     * TCP选项部分
    */
    bool getTcpOperationMSS(int offset, u_short& mss);                          // 获取MSS选项
    bool getTcpOperationWSOPT(int offset, u_char& shit);                        // 获取窗口扩大选项
    bool getTcpOperationSACKP(int offset);                                      // 获取SACK许可选项
    bool getTcpOperationSACK(int offset, u_char& length, QVector<u_int>& edge); // 获取SACK选项
    bool getTcpOperationTSPOT(int offset, u_int& value, u_int& reply);          // 获取时间戳选项

    // 获取UDP信息
    QString getUdpSourcePort();               // 获取UDP源端口
    QString getUdpDestinationPort();          // 获取UDP目标端口
    QString getUdpDataLength();               // 获取UDP数据长度
    QString getUdpCheckSum();                 // 获取UDP校验和

    // 获取DNS信息
    QString getDnsTransactionId();            // 获取DNS事务ID
    QString getDnsFlags();                    // 获取DNS标志
    QString getDnsFlagsQR();                  // 获取DNS QR标志
    QString getDnsFlagsOpcode();              // 获取DNS操作码
    QString getDnsFlagsAA();                  // 获取DNS AA标志
    QString getDnsFlagsTC();                  // 获取DNS TC标志
    QString getDnsFlagsRD();                  // 获取DNS RD标志
    QString getDnsFlagsRA();                  // 获取DNS RA标志
    QString getDnsFlagsZ();                   // 获取DNS Z标志（保留）
    QString getDnsFlagsRcode();               // 获取DNS响应代码
    QString getDnsQuestionNumber();           // 获取DNS查询数量
    QString getDnsAnswerNumber();             // 获取DNS答案数量
    QString getDnsAuthorityNumber();          // 获取DNS权威记录数量
    QString getDnsAdditionalNumber();         // 获取DNS附加记录数量
    void getDnsQueriesDomain(QString &name, int &Type, int &Class);             // 获取DNS查询域名
    QString getDnsDomainType(int type);                                        // 获取DNS域名类型
    QString getDnsDomainName(int offset);                                      // 获取DNS域名
    int getDnsAnswersDomain(int offset, QString &name1, u_short &Type, u_short &Class, u_int &ttl, u_short &dataLength, QString &name2); // 获取DNS答案域名

    // 获取TLS信息
    bool getisTlsProtocol(int offset);                                          // 判断是否为TLS协议
    void getTlsBasicInfo(int offset, u_char &contentType, u_short &version, u_short &length); // 获取TLS基本信息
    void getTlsClientHelloInfo(int offset, u_char &handShakeType, int &length, u_short &version, QString &random, u_char &sessionIdLength, QString &sessionId, u_short &cipherLength, QVector<u_short> &cipherSuit, u_char &cmLength, QVector<u_char> &CompressionMethod, u_short &extensionLength); // 获取TLS客户端Hello信息
    void getTlsServerHelloInfo(int offset, u_char &handShakeType, int &length, u_short &version, QString &random, u_char &sessionIdLength, QString &sessionId, u_short &cipherSuit, u_char &compressionMethod, u_short &extensionLength); // 获取TLS服务器Hello信息
    void getTlsServerKeyExchange(int offset, u_char &handShakeType, int &length, QString &sigAndHash, QString &sign, u_short &curve, QString &p, QString &gx, QString &gy); // 获取TLS服务器密钥交换信息
    void getTlsCertificate(int offset, u_char &handShakeType, int &length, int &certificateLength, QVector<QString> &certificate); // 获取TLS证书信息
    void getTlsServerKeyExchange(int offset, u_char &handShakeType, int &length, u_char &curveType, u_short &curveName, u_char &pubLength, QString &pubKey, u_short &sigAlgorithm, u_short &sigLength, QString &sig);

    /*
     * these functions are used to parse the extension parts
     * extension parts are common in handshake parts (client hello,server hello ...)
     * there are some extension types are not included in, maybe you should refer the official API
    */
    void getTlsExtensionServerName(int offset,u_short&type,u_short&length,u_short&listLength,u_char&nameType,u_short&nameLength,QString& name);
    void getTlsExtensionSignatureAlgorithms(int offset,u_short&type,u_short&length,u_short&algorithmLength,QVector<u_short>&signatureAlgorithm);
    void getTlsExtensionSupportGroups(int offset,u_short&type,u_short&length,u_short&groupListLength,QVector<u_short>&group);
    void getTlsExtensionEcPointFormats(int offset,u_short&type,u_short&length,u_char& ecLength,QVector<u_char>&EC);
    void getTlsExtensionSessionTicket(int offset,u_short&type,u_short&length);
    void getTlsExtensionEncryptThenMac(int offset,u_short&type,u_short&length);
    void getTlsExtensionSupportVersions(int offset,u_short&type,u_short&length,u_char&supportLength,QVector<u_short>&supportVersion);
    void getTlsExtensionPskKeyExchangeModes(int offset,u_short&type,u_short&length,u_char&modeLength,QVector<u_char>&mode);
    void getTlsExtensionKeyShare(int offset,u_short&type,u_short&length,u_short&shareLength,u_short&group,u_short&exchangeLength,QString& exchange);
    void getTlsExtensionOther(int offset,u_short&type,u_short&length,QString& data);
    void getTlsExtensionExtendMasterSecret(int offset,u_short&type,u_short&length);
    void getTlsExtensionPadding(int offset,u_short&type,u_short&length,QString&data);

    u_short getTlsExtensionType(int offset);
    /*
     * when transfer data,some types will be encoded,like using 0x01 to represent the MD5 in extension hash part
     * to visual display these types,we need to decode and analysis
     * this functions are used to do these analisis
     * however,some types may be the custom types, so we can't decode
     * also,there are some rules not be included, maybe you should refer the official API
    */
    // Parsing the encode data
    static QString getTlsHandshakeType(int type);                          // Parsing TLS handshake type
    static QString getTlsContentType(int type);                            // Parsing TLS content type
    static QString getTlsVersion(int version);                             // Parsing TLS version
    static QString getTlsHandshakeCipherSuites(u_short code);              // Parsing TLS cipher suite
    static QString getTlsHandshakeCompression(u_char code);                // Parsing TLS compression
    static QString getTlsHandshakeExtension(u_short type);                 // Parsing TLS extension
    static QString getTlsHandshakeExtensionECPointFormat(u_char type);     // Parsing TLS EC point format
    static QString getTlsHandshakeExtensionSupportGroup(u_short type);     // Parsing TLS support group
    static QString getTlsHadshakeExtensionSignature(u_char type);          // Parsing TLS signature
    static QString getTlsHadshakeExtensionHash(u_char type);
    void getTlsHandshakeType(int offset, u_char &type);        // Parsing TLS hash
};

#endif // DATAPACKAGE_H
