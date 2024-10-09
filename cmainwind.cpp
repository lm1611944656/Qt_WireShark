#include "cmainwind.h"
#include "multhread.h"
#include "pcap.h"
#include "readonlydelegate.h"

// 子线程接受到一个数据包时，会处理数据包；
// 子线程处理完数据包时，发送信号通知(信号中包含了处理好的数据)主线程
CMainWind::CMainWind(QWidget *parent)
    : QWidget(parent), m_currDevice(nullptr),
    pointer(nullptr), countNumber(0),
    isStart(false), m_rowNumber(-1)
{
    // 界面初始化
    initForm();

    // 查看可用网络设备
    showNetworkCard();

    // 创建一个分离线程
    MulThread *m_childThread = new MulThread;

    // 按钮点击事件
    static bool index = false;
    connect(m_button, &QPushButton::clicked,
            this, [=](){

                // 鼠标第一次点击时
                index = !index;
                if(index){

                    // 清除表格中的内容
                    m_dataPacketTable->clearContents();

                    //
                    m_dataPacketTable->setRowCount(0);

                    countNumber = 0;

                    int dataSize = this->pData.size();
                    for(int i = 0; i < dataSize; i++){
                        free((char *)(this->pData[i].pkt_content));
                        this->pData[i].pkt_content = nullptr;
                    }
                    QVector<DataPackage>().swap(pData);


                    // 打开网络设备
                    int res = capture();

                    // 打开成功，并且网络的句柄(类似文件描述符)存在
                    if(pointer && res != -1){
                        m_childThread->setFlag();
                        m_childThread->setPointer(pointer);
                        m_comboBox->setEnabled(false);
                        m_childThread->start();
                        m_button->setIcon(QIcon(":/resources/stop.png"));

                        isStart = true;
                    }else{

                        m_rowNumber = -1;
                        isStart = false;
                    }

                // 鼠标再次点击时
                }else{ // fail to start
                    m_childThread->resetFlag();
                    m_childThread->quit();
                    m_childThread->wait();
                    m_button->setIcon(QIcon(":/resources/start.png"));
                    m_comboBox->setEnabled(true);
                    pcap_close(pointer);
                    pointer = nullptr;
                }
            });

    // 处理子线程的返回的数据
    connect(m_childThread, &MulThread::sign_send, this, &CMainWind::handleMessage);

    // 当表的某一行被点击时
    connect(m_dataPacketTable, &QTableWidget::cellClicked, this, &CMainWind::onTableCellClicked);
}

CMainWind::~CMainWind() {}

void CMainWind::initForm()
{
    initPacketListPane();

    initPacketDetailsPane();

    initStatusBar();

    QVBoxLayout *m_mainLayout = new QVBoxLayout(this);
    m_mainLayout->addWidget(m_widget1);
    m_mainLayout->addWidget(m_widget2);
    m_mainLayout->addWidget(m_statusBar);

    // 当前对象添加布局
    this->setLayout(m_mainLayout);
}

void CMainWind::initPacketListPane()
{
    m_widget1 = new QWidget;
    m_widget1->setObjectName(QString::fromUtf8("widget1"));
    QHBoxLayout *m_hBoxLayout = new QHBoxLayout(m_widget1);
    m_comboBox = new QComboBox();
    m_comboBox->setMinimumWidth(350);
    connect(m_comboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &CMainWind::onComboBoxChanged);
    m_lineEdit = new QLineEdit();
    m_button = new QPushButton();
    m_button->setIcon(QIcon(":/resources/start.png"));

    m_hBoxLayout->addWidget(m_comboBox);
    m_hBoxLayout->addWidget(m_lineEdit);
    m_hBoxLayout->addWidget(m_button);
}

void CMainWind::initPacketDetailsPane()
{

    m_widget2 = new QWidget;
    m_widget2->setObjectName(QString::fromUtf8("widget2"));
    QVBoxLayout *m_vBoxLayout = new QVBoxLayout(m_widget2);
    QSplitter *m_splitter = new QSplitter(Qt::Vertical, m_widget2);
    m_dataPacketTable = new QTableWidget();
    m_dataPacketTree = new QTreeWidget();
    m_splitter->addWidget(m_dataPacketTable);
    m_splitter->addWidget(m_dataPacketTree);
    m_vBoxLayout->addWidget(m_splitter);

    setdataPacketTable(*m_dataPacketTable);
}

void CMainWind::initStatusBar()
{
    m_statusBar = new QStatusBar();
    m_startTime = QDateTime::currentDateTime(); // 记录程序启动的时间
    QTimer *timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &CMainWind::updateStatusBar);
    timer->start(1000); // 每秒更新一次
}

void CMainWind::showNetworkCard()
{
    // 查找所有网卡设备，查找到的结果存放在m_allDevice中
    int deviceNum = pcap_findalldevs(&m_allDevice, errbuf);
    if(deviceNum == -1){
        m_comboBox->addItem("Cannot find a matching network card, please restart and test");
        return;
    }

    m_comboBox->clear();
    m_comboBox->addItem("please chose the Network Card!");

    // 遍历链表
    for(m_currDevice = m_allDevice; m_currDevice != nullptr;m_currDevice = m_currDevice->next){
        QString device_name = m_currDevice->name;
        device_name.replace("\\Device\\","");
        QString device_description = m_currDevice->description;
        QString item = device_name + "   " + device_description;
        m_comboBox->addItem(item);
    }
}

/*
 * 当组合框的项目改变时，设备指针也会改变
 * 此函数可以确保设备指针指向所选的网卡*/
void CMainWind::onComboBoxChanged(int index)
{
    qDebug() << index;
    int i = 0;
    if(index != 0){
        for(m_currDevice = m_allDevice; i<index - 1; i++,m_currDevice = m_currDevice->next);
    }else{
        m_currDevice = nullptr;
    }
    return;
}

/*
 * 开始捕获来自卡的数据包
 * 数据链路层的数据包必须符合 IEEE 802.3 协议
 * 否则将被丢弃
*/
int CMainWind::capture(){
    // 打开网络接口
    if(m_currDevice)
        /*
         * 获取网络的句柄(类似于文件描述符)
         * m_currDevice->name：你要打开的设备名称，表示需要捕获网络流量的接口。
         * 65536：表示捕获包的最大字节数，基本上足够捕获完整的以太网数据帧。
         * 1：启用混杂模式，可以捕获经过接口的所有流量。
         * 1000：捕获的超时时间设置为 1 秒。
         * errbuf：用于存储错误信息的缓冲区。*/
        pointer = pcap_open_live(m_currDevice->name, 65536, 1, 1000, errbuf);
    else{
        // m_statusBar->showMessage("pls choose Network Card!");
        return -1;
    }

    if(!pointer){
        // m_statusBar->showMessage(errbuf);
        pcap_freealldevs(m_allDevice);
        m_currDevice = nullptr;
        return -1;
    }else{
        // check the data link IEEE 802.3
        if(pcap_datalink(pointer) != DLT_EN10MB){
            pcap_close(pointer);
            pcap_freealldevs(m_allDevice);
            m_currDevice = nullptr;
            return -1;
        }

        //m_statusBar->showMessage(m_currDevice->name);
    }
    return 0;
}

void CMainWind::updateStatusBar()
{
    // 获取当前时间，格式：yyyy-MM-dd hh:mm:ss
    QString currentTime = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");

    // 计算软件运行时间
    qint64 elapsed = m_startTime.msecsTo(QDateTime::currentDateTime()) / 1000; // 以秒为单位
    int hours = elapsed / 3600;
    int minutes = (elapsed % 3600) / 60;
    int seconds = elapsed % 60;
    QString runtime = QString("运行时间: %1:%2:%3")
                          .arg(hours, 2, 10, QChar('0'))
                          .arg(minutes, 2, 10, QChar('0'))
                          .arg(seconds, 2, 10, QChar('0'));

    // 更新状态栏信息
    m_statusBar->showMessage(QString("当前时间: %1 | %2").arg(currentTime, runtime));
}

void CMainWind::setdataPacketTable(QTableWidget &table)
{
    // 设置表格的行高为30
    table.verticalHeader()->setDefaultSectionSize(30);

    // 显示7列
    table.setColumnCount(7);

    // 不显示网格
    table.setShowGrid(false);

    // 不显示垂直表头
    table.verticalHeader()->setVisible(false);

    m_readOnlyDelegate = new ReadOnlyDelegate();

    // 为表格的某一列设置只读委托，比如第1列
    //table.setItemDelegateForColumn(1, m_readOnlyDelegate);

    // 为表格设置只读委托
    table.setItemDelegate(m_readOnlyDelegate);

    QStringList title = {"NO.","Time","Source","Destination","Protocol","Length","Info"};

    // 设置表头
    table.setHorizontalHeaderLabels(title);
    table.setColumnWidth(0, 50);
    table.setColumnWidth(1, 150);
    table.setColumnWidth(2, 300);
    table.setColumnWidth(3, 300);
    table.setColumnWidth(4, 100);
    table.setColumnWidth(5, 100);
    table.setColumnWidth(6, 1000);

    // 当用户点击或选择某个单元格时，整行都会被选中，而不是仅仅选择单个单元格。
    table.setSelectionBehavior(QAbstractItemView::SelectRows);
}

void CMainWind::handleMessage(DataPackage data) {


    if (!m_dataPacketTable) return; // 确保表格已初始化

    // 检查数据有效性
    if (data.getTimeStamp().isEmpty() || data.getSource().isEmpty()) {
        qDebug() << "Invalid data package!";
        return;
    }

    // 表中插入一行
    m_dataPacketTable->insertRow(countNumber);

    // 保存数据包
    this->pData.push_back(data);

    // 获取数据包的类型
    QString type = data.getPackageType();


    QColor color;
    // show different color
    if(type == TCP){
        color = QColor(216,191,216);
    }else if(type == UDP){
        color = QColor(144,238,144);
    }
    else if(type == ARP){
        color = QColor(238,238,0);
    }
    else if(type == DNS){
        color = QColor(255,255,224);
    }else if(type == TLS || type == SSL){
        color = QColor(210,149,210);
    }else{
        color = QColor(255,218,185);
    }

    m_dataPacketTable->setItem(countNumber,0,new QTableWidgetItem(QString::number(countNumber)));
    m_dataPacketTable->setItem(countNumber,1,new QTableWidgetItem(data.getTimeStamp()));
    m_dataPacketTable->setItem(countNumber,2,new QTableWidgetItem(data.getSource()));
    m_dataPacketTable->setItem(countNumber,3,new QTableWidgetItem(data.getDestination()));
    m_dataPacketTable->setItem(countNumber,4,new QTableWidgetItem(type));
    m_dataPacketTable->setItem(countNumber,5,new QTableWidgetItem(data.getDataLength()));
    m_dataPacketTable->setItem(countNumber,6,new QTableWidgetItem(data.getInfo()));

    // set color
    for(int i = 0;i < 7;i++){
        m_dataPacketTable->item(countNumber, i)->setBackground(color);
    }
    countNumber++;
}

void CMainWind::onTableCellClicked(int row, int column)
{
    if(m_rowNumber == row || row < 0){
        return;
    }else{
        m_dataPacketTree->clear();
        m_rowNumber = row;
        if(m_rowNumber < 0 || m_rowNumber > pData.size())
            return;
        QString desMac = pData[m_rowNumber].getDesMacAddr();
        QString srcMac = pData[m_rowNumber].getSrcMacAddr();
        QString type = pData[m_rowNumber].getMacType();
        QString tree1 = "Ethernet, Src:" +srcMac + ", Dst:" + desMac;
        QTreeWidgetItem*item = new QTreeWidgetItem(QStringList()<<tree1);
        m_dataPacketTree->addTopLevelItem(item);

        item->addChild(new QTreeWidgetItem(QStringList()<<"Destination:" + desMac));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Source:" + srcMac));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Type:" + type));

        QString packageType = pData[m_rowNumber].getPackageType();
        // arp package analysis
        if(packageType == ARP){
            QString ArpType = pData[m_rowNumber].getArpOperationCode();
            QTreeWidgetItem*item2 = new QTreeWidgetItem(QStringList()<<"Address Resolution Protocol " + ArpType);
            m_dataPacketTree->addTopLevelItem(item2);
            QString HardwareType = pData[m_rowNumber].getArpHardwareType();
            QString protocolType = pData[m_rowNumber].getArpProtocolType();
            QString HardwareSize = pData[m_rowNumber].getArpHardwareLength();
            QString protocolSize = pData[m_rowNumber].getArpProtocolLength();
            QString srcMacAddr = pData[m_rowNumber].getArpSourceEtherAddr();
            QString desMacAddr = pData[m_rowNumber].getArpDestinationEtherAddr();
            QString srcIpAddr = pData[m_rowNumber].getArpSourceIpAddr();
            QString desIpAddr = pData[m_rowNumber].getArpDestinationIpAddr();

            item2->addChild(new QTreeWidgetItem(QStringList()<<"Hardware type:" + HardwareType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Protocol type:" + protocolType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Hardware size:" + HardwareSize));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Protocol size:" + protocolSize));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Opcode:" + ArpType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Sender MAC address:" + srcMacAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Sender IP address:" + srcIpAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Target MAC address:" + desMacAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Target IP address:" + desIpAddr));
            return;
        }else { // ip package analysis
            QString srcIp = pData[m_rowNumber].getSrcIpAddr();
            QString desIp = pData[m_rowNumber].getDesIpAddr();

            QTreeWidgetItem*item3 = new QTreeWidgetItem(QStringList()<<"Internet Protocol Version 4, Src:" + srcIp + ", Dst:" + desIp);
            m_dataPacketTree->addTopLevelItem(item3);

            QString version = pData[m_rowNumber].getIpVersion();
            QString headerLength = pData[m_rowNumber].getIpHeaderLength();
            QString Tos = pData[m_rowNumber].getIpTos();
            QString totalLength = pData[m_rowNumber].getIpTotalLength();
            QString id = "0x" + pData[m_rowNumber].getIpIdentification();
            QString flags = pData[m_rowNumber].getIpFlag();
            if(flags.size()<2)
                flags = "0" + flags;
            flags = "0x" + flags;
            QString FragmentOffset = pData[m_rowNumber].getIpFragmentOffset();
            QString ttl = pData[m_rowNumber].getIpTTL();
            QString protocol = pData[m_rowNumber].getIpProtocol();
            QString checksum = "0x" + pData[m_rowNumber].getIpCheckSum();
            int dataLengthofIp = totalLength.toUtf8().toInt() - 20;
            item3->addChild(new QTreeWidgetItem(QStringList()<<"0100 .... = Version:" + version));
            item3->addChild(new QTreeWidgetItem(QStringList()<<".... 0101 = Header Length:" + headerLength));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"TOS:" + Tos));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Total Length:" + totalLength));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Identification:" + id));

            QString reservedBit = pData[m_rowNumber].getIpReservedBit();
            QString DF = pData[m_rowNumber].getIpDF();
            QString MF = pData[m_rowNumber].getIpMF();
            QString FLAG = ",";

            if(reservedBit == "1"){
                FLAG += "Reserved bit";
            }
            else if(DF == "1"){
                FLAG += "Don't fragment";
            }
            else if(MF == "1"){
                FLAG += "More fragment";
            }
            if(FLAG.size() == 1)
                FLAG = "";
            QTreeWidgetItem*bitTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flags + FLAG);
            item3->addChild(bitTree);
            QString temp = reservedBit == "1"?"Set":"Not set";
            bitTree->addChild(new QTreeWidgetItem(QStringList()<<reservedBit + "... .... = Reserved bit:" + temp));
            temp = DF == "1"?"Set":"Not set";
            bitTree->addChild(new QTreeWidgetItem(QStringList()<<"." + DF + ".. .... = Don't fragment:" + temp));
            temp = MF == "1"?"Set":"Not set";
            bitTree->addChild(new QTreeWidgetItem(QStringList()<<".." + MF + ". .... = More fragment:" + temp));

            item3->addChild(new QTreeWidgetItem(QStringList()<<"Fragment Offset:" + FragmentOffset));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Time to Live:" + ttl));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Protocol:" + protocol));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Header checksum:" + checksum));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Source Address:" + srcIp));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Destination Address:" + desIp));

            if(packageType == TCP || packageType == TLS || packageType == SSL){
                QString desPort = pData[m_rowNumber].getTcpDestinationPort();
                QString srcPort = pData[m_rowNumber].getTcpSourcePort();
                QString ack = pData[m_rowNumber].getTcpAcknowledgment();
                QString seq = pData[m_rowNumber].getTcpSequence();
                QString headerLength = pData[m_rowNumber].getTcpHeaderLength();
                int rawLength = pData[m_rowNumber].getTcpRawHeaderLength().toUtf8().toInt();
                dataLengthofIp -= (rawLength * 4);
                QString dataLength = QString::number(dataLengthofIp);
                QString flag = pData[m_rowNumber].getTcpFlags();
                while(flag.size()<2)
                    flag = "0" + flag;
                flag = "0x" + flag;
                QTreeWidgetItem*item4 = new QTreeWidgetItem(QStringList()<<"Transmission Control Protocol, Src Port:" + srcPort + ", Dst Port:" + desPort + ",Seq:" + seq + ", Ack:" + ack + ", Len:" + dataLength);

                m_dataPacketTree->addTopLevelItem(item4);
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:" + srcPort));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:" + desPort));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number (raw) :" + seq));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Ackowledgment Number (raw) :" + ack));


                QString sLength = QString::number(rawLength,2);
                while(sLength.size()<4)
                    sLength = "0" + sLength;
                item4->addChild(new QTreeWidgetItem(QStringList()<<sLength + " .... = Header Length:" + headerLength));

                QString PSH = pData[m_rowNumber].getTcpPSH();
                QString URG = pData[m_rowNumber].getTcpURG();
                QString ACK = pData[m_rowNumber].getTcpACK();
                QString RST = pData[m_rowNumber].getTcpRST();
                QString SYN = pData[m_rowNumber].getTcpSYN();
                QString FIN = pData[m_rowNumber].getTcpFIN();
                QString FLAG = "";

                if(PSH == "1")
                    FLAG += "PSH,";
                if(URG == "1")
                    FLAG += "UGR,";
                if(ACK == "1")
                    FLAG += "ACK,";
                if(RST == "1")
                    FLAG += "RST,";
                if(SYN == "1")
                    FLAG += "SYN,";
                if(FIN == "1")
                    FLAG += "FIN,";
                FLAG = FLAG.left(FLAG.length()-1);
                if(SYN == "1"){
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 0 (relative ack number)"));
                }
                if(SYN == "1" && ACK == "1"){
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 1 (relative ack number)"));
                }
                QTreeWidgetItem*flagTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flag + " (" + FLAG + ")");
                item4->addChild(flagTree);
                QString temp = URG == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .." + URG + ". .... = Urgent(URG):" + temp));
                temp = ACK == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ..." + ACK + " .... = Acknowledgment(ACK):" + temp));
                temp = PSH == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... " + PSH + "... = Push(PSH):" + temp));
                temp = RST == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ." + RST + ".. = Reset(RST):" + temp));
                temp = SYN == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... .." + SYN + ". = Syn(SYN):" + temp));
                temp = FIN == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ..." + FIN + " = Fin(FIN):" + temp));

                QString window = pData[m_rowNumber].getTcpWindowSize();
                QString checksum = "0x" + pData[m_rowNumber].getTcpCheckSum();
                QString urgent = pData[m_rowNumber].getTcpUrgentPointer();
                item4->addChild(new QTreeWidgetItem(QStringList()<<"window:" + window));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"checksum:" + checksum));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Urgent Pointer:" + urgent));
                if((rawLength * 4) > 20){
                    QTreeWidgetItem * optionTree = new QTreeWidgetItem(QStringList()<<"Options: (" + QString::number(rawLength * 4 - 20) + ") bytes");
                    item4->addChild(optionTree);
                    for(int j = 0;j < (rawLength * 4 - 20);){
                        int kind = pData[m_rowNumber].getTcpOperationRawKind(j);
                        switch (kind) {
                        case 0:{
                            QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - End of List (EOL)");
                            optionTree->addChild(subTree);
                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind:End of List (0)"));
                            optionTree->addChild(subTree);
                            j++;
                            break;
                        }case 1:{
                            QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - No-Operation (NOP)");
                            optionTree->addChild(subTree);
                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind: No-Operation (1)"));
                            optionTree->addChild(subTree);
                            j++;
                            break;
                        }
                        case 2:{
                            u_short mss;
                            if(pData[m_rowNumber].getTcpOperationMSS(j,mss)){
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - Maximun Segment Size: " + QString::number(mss) + " bytes");
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind: Maximun Segment Size (2)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 4"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"MSS Value: " + QString::number(mss)));
                                j += 4;
                            }
                            break;
                        }
                        case 3:{
                            u_char shift;
                            if(pData[m_rowNumber].getTcpOperationWSOPT(j,shift)){
                                int factor = 1 << shift;
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - Window scale: " + QString::number(shift) + " (multiply by " + QString::number(factor) + ")");
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind: Window scale (3)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 3"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Shift Count: " + QString::number(shift)));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"[Multiplier: " + QString::number(factor) + "]"));
                                j += 3;
                            }
                            break;
                        }
                        case 4:{
                            if(pData[m_rowNumber].getTcpOperationSACKP(j)){
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - SACK Permitted");
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Kind: SCAK Permitted (4)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 2"));
                                j += 2;
                            }
                            break;
                        }
                        case 5:{
                            u_char length = 0;
                            QVector<u_int>edge;
                            if(pData[m_rowNumber].getTcpOperationSACK(j,length,edge)){
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - SACK");
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Kind: SCAK (5)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(length)));
                                int num = edge.size();
                                for(int k = 0;k < num;k += 2){
                                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"left edge = " + QString::number(edge[k])));
                                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"right edge = " + QString::number(edge[k + 1])));
                                }
                                j += length;
                            }
                            break;
                        }
                        case 8:{
                            u_int value = 0;
                            u_int reply = 0;
                            if(pData[m_rowNumber].getTcpOperationTSPOT(j,value,reply)){
                                QString val = QString::number(value);
                                QString rep = QString::number(reply);
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - TimeStamps: TSval " +val + ", TSecr " + rep);
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Kind: Time Stamp Option (8)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 10"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Timestamp value: " + val));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Timestamp echo reply: " + rep));
                                j += 10;
                            }
                            break;
                        }
                        case 19:{
                            j += 18;
                            break;
                        }
                        case 28:{
                            j += 4;
                            break;
                        }
                        default:{
                            j++;
                            break;
                        }
                        }
                    }
                }
                if(dataLengthofIp > 0){
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"TCP Payload (" + QString::number(dataLengthofIp) + ")"));
                    if(packageType == TLS){
                        QTreeWidgetItem* tlsTree = new QTreeWidgetItem(QStringList()<<"Transport Layer Security");
                        m_dataPacketTree->addTopLevelItem(tlsTree);
                        u_char contentType = 0;
                        u_short version = 0;
                        u_short length = 0;
                        pData[m_rowNumber].getTlsBasicInfo((rawLength * 4),contentType,version,length);
                        QString type = pData[m_rowNumber].getTlsContentType(contentType);
                        QString vs = pData[m_rowNumber].getTlsVersion(version);
                        switch (contentType) {
                        case 20:{
                            // ... TODO
                            break;
                        }
                        case 21:{
                            QTreeWidgetItem* tlsSubree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: Encrypted Alert");
                            tlsTree->addChild(tlsSubree);
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Alert Message: Encrypted Alert"));
                            break;
                        }
                        case 22:{ // handshake
                            u_char handshakeType = 0;
                            pData[m_rowNumber].getTlsHandshakeType((rawLength * 4 + 5),handshakeType);
                            if(handshakeType == 1){ // client hello
                                int tlsLength = 0;
                                u_short rawVersion = 0;
                                QString random = "";
                                u_char sessionLength = 0;
                                QString sessionId = "";
                                u_short cipherLength = 0;
                                QVector<u_short>cipher;
                                u_char cmLength = 0;
                                QVector<u_char>compressionMethod;
                                u_short extensionLength = 0;
                                pData[m_rowNumber].getTlsClientHelloInfo((rawLength * 4 + 5),handshakeType,tlsLength,rawVersion,random,sessionLength,sessionId,cipherLength,cipher,cmLength,compressionMethod,extensionLength);

                                QString type = pData[m_rowNumber].getTlsHandshakeType(handshakeType);
                                QString tlsVersion = pData[m_rowNumber].getTlsVersion(rawVersion);

                                QTreeWidgetItem* tlsSubTree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: " + type);
                                tlsTree->addChild(tlsSubTree);
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));

                                QTreeWidgetItem* handshakeTree = new QTreeWidgetItem(QStringList()<<"Handshake Protocol: " + type);
                                tlsSubTree->addChild(handshakeTree);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Handshake Type: " + type + "(" + QString::number(handshakeType) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(tlsLength)));

                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + tlsVersion + " (0x0" + QString::number(rawVersion) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Random: " + random));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID Length: " + QString::number(sessionLength)));
                                if(sessionLength > 0){
                                    handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID: " + sessionId));
                                }
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Cipher Suites Length: " + QString::number(cipherLength)));
                                if(cipherLength > 0){
                                    QTreeWidgetItem* cipherTree = new QTreeWidgetItem(QStringList()<<"Cipher Suites (" + QString::number(cipherLength/2) + " suites)");
                                    handshakeTree->addChild(cipherTree);
                                    for(int k = 0;k < cipherLength/2;k++){
                                        QString temp = pData[m_rowNumber].getTlsHandshakeCipherSuites(cipher[k]);
                                        cipherTree->addChild(new QTreeWidgetItem(QStringList()<<"Cipher Suite: " + temp));
                                    }
                                }
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Compression Method Length: " + QString::number(cmLength)));
                                if(cmLength > 0){
                                    QTreeWidgetItem* cmTree = new QTreeWidgetItem(QStringList()<<"Compression Methods (" + QString::number(cmLength) + " method)");
                                    handshakeTree->addChild(cmTree);
                                    for(int k = 0;k < cmLength;k++){
                                        QString temp = pData[m_rowNumber].getTlsHandshakeCompression(compressionMethod[k]);
                                        cmTree->addChild(new QTreeWidgetItem(QStringList()<<"Compression Methods: " + temp + " (" + QString::number(compressionMethod[k]) + ")"));
                                    }
                                }
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Extensions Length: " + QString::number(extensionLength)));
                                if(extensionLength > 0){
                                    int exOffset = (rawLength * 4) + (tlsLength - extensionLength + 5 + 4);
                                    for(int k = 0;k < extensionLength;){
                                        int code = pData[m_rowNumber].getTlsExtensionType(exOffset);
                                        u_short exType = 0;
                                        u_short exLength = 0;
                                        switch (code) {
                                        case 0:{ // server_name
                                            u_short listLength = 0;
                                            u_char nameType = 0;
                                            u_short nameLength = 0;
                                            QString name = "";
                                            pData[m_rowNumber].getTlsExtensionServerName(exOffset,exType,exLength,listLength,nameType,nameLength,name);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            if(exLength > 0 && listLength > 0){
                                                QTreeWidgetItem*serverTree = new QTreeWidgetItem(QStringList()<<"Server Name Indication extension");
                                                extensionTree->addChild(serverTree);
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name list length: " + QString::number(listLength)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name Type: " + QString::number(nameType)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name length: " + QString::number(nameLength)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name: " + name));
                                            }
                                            break;
                                        }
                                        case 11:{// ec_point_format
                                            u_char ecLength = 0;
                                            QVector<u_char>EC;
                                            pData[m_rowNumber].getTlsExtensionEcPointFormats(exOffset,exType,exLength,ecLength,EC);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"EC point formats Length: " + QString::number(ecLength)));
                                            QTreeWidgetItem* EXTree = new QTreeWidgetItem(QStringList()<<"Elliptic curves point formats (" + QString::number(ecLength) + ")");
                                            extensionTree->addChild(EXTree);
                                            for(int g = 0;g < ecLength;g++){
                                                QString temp = pData[m_rowNumber].getTlsHandshakeExtensionECPointFormat(EC[g]);
                                                EXTree->addChild(new QTreeWidgetItem(QStringList()<<temp));
                                            }
                                            break;
                                        }
                                        case 10:{// supported_groups
                                            u_short groupListLength = 0;
                                            QVector<u_short>group;
                                            pData[m_rowNumber].getTlsExtensionSupportGroups(exOffset,exType,exLength,groupListLength,group);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Groups List Length: " + QString::number(groupListLength)));
                                            QTreeWidgetItem* sptTree = new QTreeWidgetItem(QStringList()<<"Supported Groups (" + QString::number(groupListLength/2) + " groups)");
                                            extensionTree->addChild(sptTree);
                                            for(int g = 0;g < groupListLength/2;g++){
                                                QString temp = pData[m_rowNumber].getTlsHandshakeExtensionSupportGroup(group[g]);
                                                sptTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Group: " + temp));
                                            }
                                            break;
                                        }
                                        case 35:{// session_ticket
                                            pData[m_rowNumber].getTlsExtensionSessionTicket(exOffset,exType,exLength);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 22:{// encrypt_then_mac
                                            pData[m_rowNumber].getTlsExtensionEncryptThenMac(exOffset,exType,exLength);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 23:{// extended_master_secret
                                            pData[m_rowNumber].getTlsExtensionExtendMasterSecret(exOffset,exType,exLength);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 13:{// signature_algorithms
                                            u_short algorithmLength = 0;
                                            QVector<u_short>algorithm;
                                            pData[m_rowNumber].getTlsExtensionSignatureAlgorithms(exOffset,exType,exLength,algorithmLength,algorithm);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms Length: " + QString::number(algorithmLength)));
                                            QTreeWidgetItem* sigTree = new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms (" + QString::number(algorithmLength/2) + " algorithms)");
                                            extensionTree->addChild(sigTree);
                                            for(int g = 0;g < algorithmLength/2;g++){
                                                QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Signature Algorithm: 0x0" + QString::number(algorithm[g],16));
                                                sigTree->addChild(subTree);
                                                QString hash = pData[m_rowNumber].getTlsHadshakeExtensionHash((algorithm[g] & 0xff00) >> 8);
                                                QString sig = pData[m_rowNumber].getTlsHadshakeExtensionSignature((algorithm[g] & 0x00ff));
                                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Hash: " + hash + " (" + QString::number((algorithm[g] & 0xff00) >> 8) + ")"));
                                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Signature: " + sig + " (" + QString::number(algorithm[g] & 0x00ff) + ")"));
                                            }
                                            break;
                                        }
                                        case 43:{// supported_versions
                                            u_char supportLength = 0;
                                            QVector<u_short>supportVersion;
                                            pData[m_rowNumber].getTlsExtensionSupportVersions(exOffset,exType,exLength,supportLength,supportVersion);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Versions length: " + QString::number(supportLength)));
                                            for(int g = 0;g < supportLength/2;g++){
                                                QString temp = pData[m_rowNumber].getTlsVersion(supportVersion[g]);
                                                extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Version: " + temp));
                                            }
                                            break;
                                        }
                                        case 51:{// key_share
                                            u_short shareLength = 0;
                                            u_short group = 0;
                                            u_short exchangeLength = 0;
                                            QString exchange = "";
                                            pData[m_rowNumber].getTlsExtensionKeyShare(exOffset,exType,exLength,shareLength,group,exchangeLength,exchange);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));

                                            QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Key Share extension");
                                            extensionTree->addChild(subTree);
                                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"Client Key Share Length: " + QString::number(shareLength)));
                                            QTreeWidgetItem* entryTree = new QTreeWidgetItem(QStringList()<<"Key Share Entry: Group ");
                                            subTree->addChild(entryTree);
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Group: " + QString::number(group)));
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange Length: " + QString::number(exchangeLength)));
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange: " + exchange));
                                            break;
                                        }
                                        case 21:{// padding
                                            QString rdata = "";
                                            pData[m_rowNumber].getTlsExtensionPadding(exOffset,exType,exLength,rdata);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (21)"));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Padding Data: " + rdata));
                                            break;
                                        }
                                        default:{
                                            QString rdata = "";
                                            pData[m_rowNumber].getTlsExtensionOther(exOffset,exType,exLength,rdata);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (" + QString::number(exType) + ")"));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Data: " + rdata));

                                            break;
                                        }
                                        }
                                        k += (exLength + 4);
                                        exOffset += (exLength + 4);
                                    }
                                }
                            }
                            else if(handshakeType == 2){// Server hello
                                int tlsLength = 0;
                                u_short rawVersion = 0;
                                QString random = "";
                                u_char sessionLength = 0;
                                QString sessionId = "";
                                u_short cipher = 0;
                                u_char compressionMethod = 0;
                                u_short extensionLength = 0;
                                pData[m_rowNumber].getTlsServerHelloInfo((rawLength * 4 + 5),handshakeType,tlsLength,rawVersion,random,sessionLength,sessionId,cipher,compressionMethod,extensionLength);
                                QString type = pData[m_rowNumber].getTlsHandshakeType(handshakeType);
                                QString tlsVersion = pData[m_rowNumber].getTlsVersion(rawVersion);

                                QTreeWidgetItem* tlsSubTree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: " + type);
                                tlsTree->addChild(tlsSubTree);
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));

                                QTreeWidgetItem* handshakeTree = new QTreeWidgetItem(QStringList()<<"Handshake Protocol: " + type);
                                tlsSubTree->addChild(handshakeTree);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Handshake Type: " + type + "(" + QString::number(handshakeType) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(tlsLength)));

                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + tlsVersion + " (0x0" + QString::number(rawVersion,16) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Random: " + random));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID Length: " + QString::number(sessionLength)));
                                if(sessionLength > 0){
                                    handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID: " + sessionId));
                                }
                                QString temp = pData[m_rowNumber].getTlsHandshakeCipherSuites(cipher);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Cipher Suites: " +temp));
                                temp = pData[m_rowNumber].getTlsHandshakeCompression(compressionMethod);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Compression Methods: " + temp + " (" + QString::number(compressionMethod) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Extensions Length: " + QString::number(extensionLength)));
                                if(extensionLength > 0){
                                    int exOffset = (rawLength * 4) + (tlsLength - extensionLength + 5 + 4);
                                    for(int k = 0;k < extensionLength;){
                                        int code = pData[m_rowNumber].getTlsExtensionType(exOffset);
                                        u_short exType = 0;
                                        u_short exLength = 0;
                                        switch (code) {
                                        case 0:{ // server_name
                                            u_short listLength = 0;
                                            u_char nameType = 0;
                                            u_short nameLength = 0;
                                            QString name = "";
                                            pData[m_rowNumber].getTlsExtensionServerName(exOffset,exType,exLength,listLength,nameType,nameLength,name);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            if(exLength > 0 && listLength > 0){
                                                QTreeWidgetItem*serverTree = new QTreeWidgetItem(QStringList()<<"Server Name Indication extension");
                                                extensionTree->addChild(serverTree);
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name list length: " + QString::number(listLength)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name Type: " + QString::number(nameType)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name length: " + QString::number(nameLength)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name: " + name));
                                            }
                                            break;
                                        }
                                        case 11:{// ec_point_format
                                            u_char ecLength = 0;
                                            QVector<u_char>EC;
                                            pData[m_rowNumber].getTlsExtensionEcPointFormats(exOffset,exType,exLength,ecLength,EC);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"EC point formats Length: " + QString::number(ecLength)));
                                            QTreeWidgetItem* EXTree = new QTreeWidgetItem(QStringList()<<"Elliptic curves point formats (" + QString::number(ecLength) + ")");
                                            extensionTree->addChild(EXTree);
                                            for(int g = 0;g < ecLength;g++){
                                                QString temp = pData[m_rowNumber].getTlsHandshakeExtensionECPointFormat(EC[g]);
                                                EXTree->addChild(new QTreeWidgetItem(QStringList()<<temp));
                                            }
                                            break;
                                        }
                                        case 10:{// supported_groups
                                            u_short groupListLength = 0;
                                            QVector<u_short>group;
                                            pData[m_rowNumber].getTlsExtensionSupportGroups(exOffset,exType,exLength,groupListLength,group);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Groups List Length: " + QString::number(groupListLength)));
                                            QTreeWidgetItem* sptTree = new QTreeWidgetItem(QStringList()<<"Supported Groups (" + QString::number(groupListLength/2) + " groups)");
                                            extensionTree->addChild(sptTree);
                                            for(int g = 0;g < groupListLength/2;g++){
                                                QString temp = pData[m_rowNumber].getTlsHandshakeExtensionSupportGroup(group[g]);
                                                sptTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Group: " + temp));
                                            }
                                            break;
                                        }
                                        case 35:{// session_ticket
                                            pData[m_rowNumber].getTlsExtensionSessionTicket(exOffset,exType,exLength);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 22:{// encrypt_then_mac
                                            pData[m_rowNumber].getTlsExtensionEncryptThenMac(exOffset,exType,exLength);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 23:{// extended_master_secret
                                            pData[m_rowNumber].getTlsExtensionExtendMasterSecret(exOffset,exType,exLength);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 13:{// signature_algorithms
                                            u_short algorithmLength = 0;
                                            QVector<u_short>algorithm;
                                            pData[m_rowNumber].getTlsExtensionSignatureAlgorithms(exOffset,exType,exLength,algorithmLength,algorithm);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms Length: " + QString::number(algorithmLength)));
                                            QTreeWidgetItem* sigTree = new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms (" + QString::number(algorithmLength/2) + " algorithms)");
                                            extensionTree->addChild(sigTree);
                                            for(int g = 0;g < algorithmLength/2;g++){
                                                QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Signature Algorithm: 0x0" + QString::number(algorithm[g],16));
                                                sigTree->addChild(subTree);
                                                QString hash = pData[m_rowNumber].getTlsHadshakeExtensionHash((algorithm[g] & 0xff00) >> 8);
                                                QString sig = pData[m_rowNumber].getTlsHadshakeExtensionSignature((algorithm[g] & 0x00ff));
                                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Hash: " + hash + " (" + QString::number((algorithm[g] & 0xff00) >> 8) + ")"));
                                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Signature: " + sig + " (" + QString::number(algorithm[g] & 0x00ff) + ")"));
                                            }
                                            break;
                                        }
                                        case 43:{// supported_versions
                                            u_char supportLength = 0;
                                            QVector<u_short>supportVersion;
                                            pData[m_rowNumber].getTlsExtensionSupportVersions(exOffset,exType,exLength,supportLength,supportVersion);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Versions length: " + QString::number(supportLength)));
                                            for(int g = 0;g < supportLength/2;g++){
                                                QString temp = pData[m_rowNumber].getTlsVersion(supportVersion[g]);
                                                extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Version: " + temp));
                                            }
                                            break;
                                        }
                                        case 51:{// key_share
                                            u_short shareLength = 0;
                                            u_short group = 0;
                                            u_short exchangeLength = 0;
                                            QString exchange = "";
                                            pData[m_rowNumber].getTlsExtensionKeyShare(exOffset,exType,exLength,shareLength,group,exchangeLength,exchange);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));

                                            QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Key Share extension");
                                            extensionTree->addChild(subTree);
                                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"Client Key Share Length: " + QString::number(shareLength)));
                                            QTreeWidgetItem* entryTree = new QTreeWidgetItem(QStringList()<<"Key Share Entry: Group ");
                                            subTree->addChild(entryTree);
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Group: " + QString::number(group)));
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange Length: " + QString::number(exchangeLength)));
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange: " + exchange));
                                            break;
                                        }
                                        case 21:{// padding
                                            QString rdata = "";
                                            pData[m_rowNumber].getTlsExtensionPadding(exOffset,exType,exLength,rdata);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (21)"));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Padding Data: " + rdata));
                                            break;
                                        }
                                        default:{
                                            QString rdata = "";
                                            pData[m_rowNumber].getTlsExtensionOther(exOffset,exType,exLength,rdata);
                                            QString subType = pData[m_rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (" + QString::number(exType) + ")"));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Data: " + rdata));

                                            break;
                                        }
                                        }
                                        k += (exLength + 4);
                                        exOffset += (exLength + 4);
                                    }
                                }

                            }
                            else if(handshakeType == 12){// Server Key Exchange
                                int tlsLength = 0;
                                u_char curveType = 0;
                                u_short curveName = 0;
                                u_char pubLength = 0;
                                QString pubKey = "";
                                u_short sigAlgorithm = 0;
                                u_short sigLength = 0;
                                QString sig = "";
                                pData[m_rowNumber].getTlsServerKeyExchange((rawLength * 4 + 5),handshakeType,tlsLength,curveType,curveName,pubLength,pubKey,sigAlgorithm,sigLength,sig);
                                QString type = pData[m_rowNumber].getTlsHandshakeType(handshakeType);

                                QTreeWidgetItem* tlsSubTree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: " + type);
                                tlsTree->addChild(tlsSubTree);
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));

                                QTreeWidgetItem* handshakeTree = new QTreeWidgetItem(QStringList()<<"Handshake Protocol: " + type);
                                tlsSubTree->addChild(handshakeTree);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Handshake Type: " + type + "(" + QString::number(handshakeType) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(tlsLength)));

                            }
                            // ... TODO
                            break;
                        }
                        case 23:{
                            QTreeWidgetItem* tlsSubree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: http-over-tls");
                            tlsTree->addChild(tlsSubree);
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Encrypted Application Data: ..."));
                            break;
                        }
                        default:break;
                        }
                    }else if(packageType == SSL){
                        m_dataPacketTree->addTopLevelItem(new QTreeWidgetItem(QStringList()<<"Transport Layer Security"));
                    }
                }
            }else if(packageType == UDP || packageType == DNS){
                QString srcPort = pData[m_rowNumber].getUdpSourcePort();
                QString desPort = pData[m_rowNumber].getUdpDestinationPort();
                QString Length = pData[m_rowNumber].getUdpDataLength();
                QString checksum = "0x" + pData[m_rowNumber].getUdpCheckSum();
                QTreeWidgetItem*item5 = new QTreeWidgetItem(QStringList()<<"User Datagram Protocol, Src Port:" + srcPort + ", Dst Port:" + desPort);
                m_dataPacketTree->addTopLevelItem(item5);
                item5->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:" + srcPort));
                item5->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:" + desPort));
                item5->addChild(new QTreeWidgetItem(QStringList()<<"length:" + Length));
                item5->addChild(new QTreeWidgetItem(QStringList()<<"Checksum:" + checksum));
                int udpLength = Length.toUtf8().toInt();
                if(udpLength > 0){
                    item5->addChild(new QTreeWidgetItem(QStringList()<<"UDP PayLoad (" + QString::number(udpLength - 8) + " bytes)"));
                }
                if(packageType == DNS){
                    QString transaction = "0x" + pData[m_rowNumber].getDnsTransactionId();
                    QString QR = pData[m_rowNumber].getDnsFlagsQR();
                    QString temp = "";
                    if(QR == "0") temp = "query";
                    if(QR == "1") temp = "response";
                    QString flags = "0x" + pData[m_rowNumber].getDnsFlags();
                    QTreeWidgetItem*dnsTree = new QTreeWidgetItem(QStringList()<<"Domain Name System (" + temp + ")");
                    m_dataPacketTree->addTopLevelItem(dnsTree);
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Transaction ID:" + transaction));
                    QTreeWidgetItem* flagTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flags);
                    dnsTree->addChild(flagTree);
                    temp = QR == "1"?"Message is a response":"Message is a query";
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<QR + "... .... .... .... = Response:" + temp));
                    QString Opcode = pData[m_rowNumber].getDnsFlagsOpcode();
                    if(Opcode == "0") temp = "Standard query (0)";
                    else if(Opcode == "1") temp = "Reverse query (1)";
                    else if(Opcode == "2") temp = "Status request (2)";
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".000 " + Opcode + "... .... .... = Opcode:" + temp));
                    if(QR == "1"){
                        QString AA = pData[m_rowNumber].getDnsFlagsAA();
                        temp = AA == "1"?"Server is an authority for domain":"Server is not an authority for domain";
                        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ." + AA + ".. .... .... = Authoritative:" + temp));
                    }
                    QString TC = pData[m_rowNumber].getDnsFlagsTC();
                    temp = TC == "1"?"Message is truncated":"Message is not truncated";
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .." + TC + ". .... .... = Truncated:" + temp));

                    QString RD = pData[m_rowNumber].getDnsFlagsRD();
                    temp = RD == "1"?"Do query recursively":"Do query not recursively";
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ..." + RD + " .... .... = Recursion desired:" + temp));

                    if(QR == "1"){
                        QString RA = pData[m_rowNumber].getDnsFlagsRA();
                        temp = RA == "1"?"Server can do recursive queries":"Server can not do recursive queries";
                        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... " + RA + "... .... = Recursion available:" + temp));
                    }
                    QString Z = pData[m_rowNumber].getDnsFlagsZ();
                    while(Z.size()<3)
                        Z = "0" + Z;
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ." + Z + " .... = Z:reserved(" + Z + ")"));
                    if(QR == "1"){
                        QString Rcode = pData[m_rowNumber].getDnsFlagsRcode();
                        if(Rcode == "0")
                            temp = "No error (0)";
                        else if(Rcode == "1") temp = "Format error (1)";
                        else if(Rcode == "2") temp = "Server failure (2)";
                        else if(Rcode == "3") temp = "Name Error (3)";
                        else if(Rcode == "4") temp = "Not Implemented (4)";
                        else if(Rcode == "5") temp = "Refused (5)";
                        int code = Rcode.toUtf8().toInt();
                        QString bCode = QString::number(code,2);
                        while (bCode.size()<4)
                            bCode = "0" + bCode;
                        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... .... " + bCode + " = Reply code:" + temp));
                    }

                    QString question = pData[m_rowNumber].getDnsQuestionNumber();
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Questions:" + question));
                    QString answer = pData[m_rowNumber].getDnsAnswerNumber();
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Answer RRs:" + answer));
                    QString authority = pData[m_rowNumber].getDnsAuthorityNumber();
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Authority RRs:" + authority));
                    QString additional = pData[m_rowNumber].getDnsAdditionalNumber();
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Additional RRs:" + additional));
                    int offset = 0;
                    if(question == "1"){
                        QString domainInfo;
                        int Type;
                        int Class;
                        pData[m_rowNumber].getDnsQueriesDomain(domainInfo,Type,Class);
                        QTreeWidgetItem*queryDomainTree = new QTreeWidgetItem(QStringList()<<"Queries");
                        dnsTree->addChild(queryDomainTree);
                        offset += (4 + domainInfo.size() + 2);
                        QString type = pData[m_rowNumber].getDnsDomainType(Type);
                        QTreeWidgetItem*querySubTree = new QTreeWidgetItem(QStringList()<<domainInfo + " type " + type + ", class IN");
                        queryDomainTree->addChild(querySubTree);
                        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"Name:" + domainInfo));
                        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"[Name Length:" + QString::number(domainInfo.size()) + "]"));
                        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"Type:" + type + "(" + QString::number(Type) + ")"));
                        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"Class: IN (0x000" + QString::number(Class) + ")"));
                    }
                    int answerNumber = answer.toUtf8().toInt();
                    if(answerNumber > 0){
                        QTreeWidgetItem*answerTree = new QTreeWidgetItem(QStringList()<<"Answers");
                        dnsTree->addChild(answerTree);
                        for(int i = 0;i< answerNumber;i++){
                            QString name1;
                            QString name2;
                            u_short type;
                            u_short Class;
                            u_int ttl;
                            u_short length;

                            int tempOffset = pData[m_rowNumber].getDnsAnswersDomain(offset,name1,type,Class,ttl,length,name2);
                            QString sType = pData[m_rowNumber].getDnsDomainType(type);
                            QString temp = "";
                            if(type == 1) temp = "addr";
                            else if(type == 5) temp = "cname";
                            QTreeWidgetItem*answerSubTree = new QTreeWidgetItem(QStringList()<<name1 + ": type " + sType + ",class IN, " + temp + ":" + name2);
                            answerTree->addChild(answerSubTree);
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Name:" + name1));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Type:" + sType + "(" + QString::number(type) + ")"));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Class: IN (0x000" + QString::number(Class) + ")"));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Time to live:" + QString::number(ttl) + "(" + QString::number(ttl) + " second)"));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Data length:" + QString::number(length)));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<sType + ":" + name2));

                            offset += tempOffset;
                        }
                    }
                }
            }else if(packageType == ICMP){
                dataLengthofIp -= 8;
                QTreeWidgetItem*item6 = new QTreeWidgetItem(QStringList()<<"Internet Message Protocol");
                m_dataPacketTree->addTopLevelItem(item6);
                QString type = pData[m_rowNumber].getIcmpType();
                QString code = pData[m_rowNumber].getIcmpCode();
                QString info = m_dataPacketTable->item(row,6)->text();
                QString checksum = "0x" + pData[m_rowNumber].getIcmpCheckSum();
                QString id = pData[m_rowNumber].getIcmpIdentification();
                QString seq = pData[m_rowNumber].getIcmpSequeue();
                item6->addChild(new QTreeWidgetItem(QStringList()<<"type:" + type + "(" + info + ")"));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"code:" + code));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"Checksum:" + checksum));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"type:" + type + "(" + info + ")"));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"Identifier:" + id));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number:" + seq));
                if(dataLengthofIp > 0){
                    QTreeWidgetItem* dataItem = new QTreeWidgetItem(QStringList()<<"Data (" + QString::number(dataLengthofIp) + ") bytes");
                    item6->addChild(dataItem);
                    QString icmpData = pData[m_rowNumber].getIcmpData(dataLengthofIp);
                    dataItem->addChild(new QTreeWidgetItem(QStringList()<<icmpData));
                }
            }
        }
        // the ethernet may have padding to ensure that the minimum length of the data packet is greater than 46
        int macDataLength = pData[m_rowNumber].getIpTotalLength().toUtf8().toInt();
        int dataPackageLength = pData[m_rowNumber].getDataLength().toUtf8().toInt();
        int delta = dataPackageLength - macDataLength;
        if(delta > 14){
            int padding = delta - 14;
            QString pad = "";
            while (pad.size() < padding * 2) {
                pad += "00";
            }
            item->addChild(new QTreeWidgetItem(QStringList()<<"Padding: " + pad));
        }
    }
}


