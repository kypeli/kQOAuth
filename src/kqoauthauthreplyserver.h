#ifndef KQOAUTHAUTHREPLYSERVER_H
#define KQOAUTHAUTHREPLYSERVER_H

#include <QTcpServer>
#include <QMultiMap>
#include <QString>

class KQOAuthAuthReplyServer : public QTcpServer
{
    Q_OBJECT
public:
    KQOAuthAuthReplyServer(QObject *parent);
    ~KQOAuthAuthReplyServer();

signals:
    void verificationReceived(QMultiMap<QString, QString>);

private slots:
    void onIncomingConnection();
    void onBytesReady();

private:
    QMultiMap<QString, QString> parseQueryParams(QByteArray *sdata);
    QTcpSocket *s;
};

#endif // KQOAUTHAUTHREPLYSERVER_H
