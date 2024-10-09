#ifndef CMAINWIND_H
#define CMAINWIND_H

#include <QWidget>
#include "pcap.h"
#include <QDebug>
#include "winsock2.h"
#include <QtWidgets>
#include "datapackage.h"


class ReadOnlyDelegate;

class CMainWind : public QWidget
{
    Q_OBJECT

public:
    CMainWind(QWidget *parent = nullptr);
    ~CMainWind();
private:
    /* 初始化主窗口 */
    void initForm(void);

    /* 初始化数据包列表窗 */
    void initPacketListPane(void);

    /* 初始化数据包详细信息 */
    void initPacketDetailsPane(void);

    /* 初始化状态栏 */
    void initStatusBar(void);

    /* 查找并显示所有网卡设备 */
    void showNetworkCard(void);

    /* 打开网卡(打开文件一样) */
    int capture();

    /* 更新状态栏(1s) */
    void updateStatusBar(void);

    /* 数据包列表设置 */
    void setdataPacketTable(QTableWidget &table);

public slots:
    // 处理子线程返回的数据包
    void handleMessage(DataPackage data);

private slots:
    void onComboBoxChanged(int index);
    void onTableCellClicked(int row, int column);

private:
    QWidget *m_widget1;
    QComboBox *m_comboBox;
    QLineEdit *m_lineEdit;
    QPushButton *m_button;

    QWidget *m_widget2;
    QTableWidget *m_dataPacketTable;
    QTreeWidget *m_dataPacketTree;
    ReadOnlyDelegate *m_readOnlyDelegate;

    QStatusBar *m_statusBar;

    /*用于存储所有可用的网络接口信息，方便用户选择*/
    pcap_if_t *m_allDevice;

    /*用于指向当前用户选择的网络接口*/
    pcap_if_t *m_currDevice;

    /*用于操作当前打开的网络接口，执行数据包捕获操作*/
    pcap_t *pointer;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* 记录程序运行时间 */
    QDateTime m_startTime;

    /* 储存子线程处理好的数据包 */
    QVector<DataPackage> pData;

    /* 记录子线程返回的数据包个数 */
    int countNumber;

    // 线程是否启动
    bool isStart;

    // m_dataPacketTable的行数记录
    int m_rowNumber;
};
#endif // CMAINWIND_H
