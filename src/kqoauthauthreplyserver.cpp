/**
 * KQOAuth - An OAuth authentication library for Qt.
 *
 * Author: Johan Paul (johan.paul@gmail.com)
 *         http://www.johanpaul.com
 *
 *  KQOAuth is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  KQOAuth is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with KQOAuth.  If not, see <http://www.gnu.org/licenses/>.
 */
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
    s->write(reply);

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
        queryParams.insert(tokenPair.first.trimmed(), tokenPair.second.trimmed());
    }

    return queryParams;
}

