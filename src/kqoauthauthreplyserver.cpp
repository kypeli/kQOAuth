#include <QTcpSocket>
#include <QStringList>
#include <QUrl>

#include "kqoauthauthreplyserver.h"


KQOAuthAuthReplyServer::KQOAuthAuthReplyServer(QObject *parent) :
    QTcpServer(parent)
{
    connect(this, SIGNAL(newConnection()),
            this, SLOT(onIncomingConnection()));
}

KQOAuthAuthReplyServer::~KQOAuthAuthReplyServer() {}

void KQOAuthAuthReplyServer::onIncomingConnection() {
    s = nextPendingConnection();
    connect(s, SIGNAL(readyRead()),
            this, SLOT(onBytesReady()));
}

void KQOAuthAuthReplyServer::onBytesReady() {
    QByteArray reply;
    QByteArray content;
    content.append("<HTML></HTML>");

    reply.append("HTTP/1.0 200 OK \r\n");
    reply.append("Content-Type: text/html; charset=\"utf-8\"\r\n");
    reply.append(QString("Content-Length: %1\r\n").arg(content.size()));
    reply.append("\r\n");
    reply.append(content);

    QByteArray data = s->readAll();

    QMultiMap<QString, QString> queryParams = parseQueryParams(&data);

    s->disconnectFromHost();
    close();

    emit verificationReceived(queryParams);
}

QMultiMap<QString, QString> KQOAuthAuthReplyServer::parseQueryParams(QByteArray *data) {
    QString splitGetLine = QString(*data).split("\r\n").first();   // Retrieve the first line with query params.
    splitGetLine.remove("GET ");                                   // Clean the line from GET
    splitGetLine.remove("HTTP/1.1");                               // From HTTP
    splitGetLine.remove("\r\n");                                   // And from rest.
    splitGetLine.prepend("http://localhost");                      // Now, make it a URL

    QUrl getTokenUrl(splitGetLine);
    QList< QPair<QString, QString> > tokens = getTokenUrl.queryItems();  // Ask QUrl to do our work.

    QMultiMap<QString, QString> queryParams;
    QPair<QString, QString> tokenPair;
    foreach(tokenPair, tokens) {
        queryParams.insert(tokenPair.first, tokenPair.second);
    }

    return queryParams;
}

