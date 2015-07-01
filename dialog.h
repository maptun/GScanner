#ifndef DIALOG_H
#define DIALOG_H

#include <QDialog>
#include <QSystemTrayIcon>
#include <QAbstractSocket>
#include <QString>
#include <QList>
#include <QMap>
#include <QPair>
#include <QVector>
#include <QByteArray>

class QUdpSocket;

namespace Ui {
class Dialog;
}

class Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit Dialog(QWidget *parent = 0);
    ~Dialog();
private slots:
    void on_actionQuit_triggered();

public slots:
    void readyUdpRead();
    void iconActivated(QSystemTrayIcon::ActivationReason reason);
    void udpError(QAbstractSocket::SocketError err);

private:

private:

    void createTrayIcon();
    void readDir(const QString &path);
    void readSignature(const QString &path);
    void ScanFiles();

    Ui::Dialog *ui;

    QSystemTrayIcon *m_trayIcon;
    QMenu *m_trayIconMenu;
    QUdpSocket *m_socket;

    QString dirString, m_malwareFile;
    QList <QPair <QString, int> > m_selectedFiles;
    QMap <QByteArray, QString> m_signaturesMap;
    QVector<QPair<QByteArray*, QByteArray> > m_signatures;

};

#endif // DIALOG_H
