#include "dialog.h"
#include "ui_dialog.h"
#include <QDebug>
#include <QMenu>
#include <QUdpSocket>
#include <QDir>
#include <QFuture>
#include <string>
#include <QtConcurrent>
#include <QtConcurrentMap>
#include <functional>

Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
    createTrayIcon();

    // create a QUDP socket
    m_socket = new QUdpSocket(this);
    if(!m_socket->bind(QHostAddress::LocalHost, 3333))
    {
       QApplication::exit(0);
    }
    connect(m_socket, SIGNAL(readyRead()), this, SLOT(readyUdpRead()));
    connect(m_socket, SIGNAL(error(QAbstractSocket::SocketError)),
            this, SLOT(udpError(QAbstractSocket::SocketError)));
    qDebug() << "Udp Server Started";

}

Dialog::~Dialog()
{
    delete ui;
}


void Dialog::createTrayIcon()
{
    // tray menu
    m_trayIconMenu = new QMenu(this);

    m_trayIconMenu->addAction(ui->actionScan);
    m_trayIconMenu->addSeparator();
    m_trayIconMenu->addAction(ui->actionQuit);
    m_trayIconMenu->addSeparator();
    m_trayIconMenu->setTitle("Scanner");
    m_trayIconMenu->setIcon( QIcon(":/Scan_icon.png") );
    m_trayIcon = new QSystemTrayIcon(this);
    m_trayIcon->setContextMenu(m_trayIconMenu);

    connect( m_trayIcon, SIGNAL( activated(QSystemTrayIcon::ActivationReason) ),
             this, SLOT( iconActivated(QSystemTrayIcon::ActivationReason) ) );

    m_trayIcon->setIcon( QIcon(":/Scan_icon.png") );
    m_trayIcon->show();
}

void Dialog::on_actionQuit_triggered()
{
    QApplication::exit(0);
}

void Dialog::iconActivated(QSystemTrayIcon::ActivationReason reason)
{
    switch (reason)
    {
        case QSystemTrayIcon::Trigger:
        case QSystemTrayIcon::DoubleClick:

            break;
        default: break;
    }
}

void Dialog::readyUdpRead()
{
    // when data comes in
    quint16 op = 0;
    QByteArray buffer;
    buffer.resize(m_socket->pendingDatagramSize());
    QHostAddress sender;
    quint16 senderPort;

    m_socket->readDatagram(buffer.data(), buffer.size(),
                         &sender, &senderPort);

    QDataStream stream( &buffer, QIODevice::ReadWrite );
    stream >> op >> dirString >> m_malwareFile;

    readDir(dirString);
    readSignature(m_malwareFile);
    ScanFiles();
}

void Dialog::udpError(QAbstractSocket::SocketError err)
{
    QString strError =
        "Error: " + (err == QAbstractSocket::HostNotFoundError ?
                     "The host was not found." :
                     err == QAbstractSocket::RemoteHostClosedError ?
                     "The remote host is closed." :
                     err == QAbstractSocket::ConnectionRefusedError ?
                     "The connection was refused." :
                     QString(m_socket->errorString())
                    );

    qDebug() << "udpError" << strError;
}

void Dialog::readDir(const QString &path)
{
    m_selectedFiles.clear();

    QDir dir(path);
    QFileInfoList files = dir.entryInfoList(QDir::Files |
                              QDir::Dirs | QDir::NoDot | QDir::NoDotDot); //Gets the file information

    foreach(const QFileInfo &fInfo, files) {
        QString const path = fInfo.absoluteFilePath();
        if(fInfo.isDir()) readDir(path);
        else {
            int static counter = 0;
            int static sizeFiles = 0;
            if(fInfo.isFile()) {
                counter += 1;
                sizeFiles += fInfo.size();
                m_selectedFiles.append(QPair<QString,int>(path, fInfo.size()));
            }
        }
    }
}

void Dialog::readSignature(const QString &path)
{
    m_signaturesMap.clear();
    m_signatures.clear();

    QFile file(path);
    if (false == file.open(QIODevice::ReadOnly)) {
       qDebug() << "File not opened!";
       return;
    }
    QTextStream in(&file);
        QString line = in.readLine();
        while (!line.isNull()) {
            QStringList strList = line.split(QRegExp("[.]"));
            QByteArray b = strList[0].toLatin1();
            QByteArray ba;
            ba.append(QByteArray::fromHex(b));
            m_signaturesMap.insert(ba, strList[1]);
            m_signatures.push_back(QPair<QByteArray*, QByteArray>(nullptr, ba));
            line = in.readLine();
        }
}

struct SignatureScan : public std::unary_function<const QPair<QByteArray*, QByteArray>&, QByteArray>
{
    QByteArray operator()(const QPair<QByteArray*, QByteArray>& info)
    {
      QByteArray res;

      if(info.first->contains(info.second))
      {
          res = info.second;
//          qDebug() << "Tread Count: " << QThread::idealThreadCount();
      }
      return res;
    }
};

void Dialog::ScanFiles()
{
    int fileCounter = 0;
    foreach(auto selectedFile, m_selectedFiles) {
        QString path = selectedFile.first;
        QFile file(path);
        if (false == file.open(QIODevice::ReadOnly)) {
           qDebug() << "File not opened!";
           return;
        }

        QByteArray ba = file.readAll();

        for (int i = 0; i < m_signatures.size(); ++i)
        {
            m_signatures[i].first = &ba;
        }

        QFuture<QByteArray> res = QtConcurrent::mapped(m_signatures,SignatureScan());
        res.waitForFinished();

        for (QFuture<QByteArray>::const_iterator i = res.begin(); i != res.end(); ++i)
        {
            if(i->size() > 0)
            {
                QString guid = m_signaturesMap[*i];
                QByteArray buffer;
                QDataStream stream( &buffer, QIODevice::ReadWrite );
                stream << qint16(1) << path << guid;
                m_socket->writeDatagram(buffer, QHostAddress::LocalHost, 3334);
            }
        }

        fileCounter++;
        QByteArray buffer;
        QDataStream stream( &buffer, QIODevice::ReadWrite );
        stream << qint16(2) << int(0) << int(m_selectedFiles.size()) << fileCounter;
        m_socket->writeDatagram(buffer, QHostAddress::LocalHost, 3334);

    }
}
