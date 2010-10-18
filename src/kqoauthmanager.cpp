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
#include <QtCore>
#include <QNetworkReply>

#include "kqoauthrequest.h"
#include "kqoauthmanager.h"

////////////// Private implementation ////////////////

class KQOAuthManagerPrivate {
public:
    KQOAuthManagerPrivate(KQOAuthManager *parent) :
        error(KQOAuthManager::NoError) ,
        q_ptr(parent)
    {

    }

    ~KQOAuthManagerPrivate() {
    }

    KQOAuthRequest *r;
    KQOAuthManager::KQOAuthError error;
    KQOAuthManager *q_ptr;
};


/////////////// Public implementation ////////////////

KQOAuthManager::KQOAuthManager(QObject *parent) :
    QObject(parent) ,
    d_ptr(new KQOAuthManagerPrivate(this))
{
    m_networkManager = new QNetworkAccessManager;

}

KQOAuthManager::~KQOAuthManager() {
    delete d_ptr;
}

void KQOAuthManager::executeRequest(KQOAuthRequest *request) {
    Q_D(KQOAuthManager);

    d->r = request;

    if( request == 0) {
        qWarning() << "Request is NULL. Cannot proceed.";
        d->error = KQOAuthManager::RequestError;
        return;
    }

    if( !request->requestEndpoint().isValid() ) {
        qWarning() << "Request endpoint URL is not valid. Cannot proceed.";
        d->error = KQOAuthManager::RequestEndpointError;
        return;
    }

    if( !request->isValid() ) {
        qWarning() << "Request is not valid. Cannot proceed.";
        d->error = KQOAuthManager::RequestValidationError;
        return;
    }

    QNetworkRequest m_networkRequest;
    // Set the request's URL to the OAuth request's endpoint.
    m_networkRequest.setUrl( request->requestEndpoint() );

    // And now fill the request with "Authorization" header data.
    QList<QByteArray> requestHeaders = request->requestParameters();
    QByteArray authHeader;
    bool first = true;
    foreach(const QByteArray header, requestHeaders) {
        qDebug() << "Header: " << header;
        if(!first) {
            authHeader.append(", ");
        } else {
            authHeader.append("OAuth ");
            first = false;
        }

        authHeader.append(header);
    }
    m_networkRequest.setRawHeader("Authorization", authHeader);
    m_networkRequest.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");

    qDebug() << "Auth request URL and headers: " << m_networkRequest.url() << m_networkRequest.rawHeader("Authorization");

    connect(m_networkManager, SIGNAL( finished(QNetworkReply *)),
            this, SLOT( requestReplyReceived(QNetworkReply*) ));
    m_networkManager->post(m_networkRequest, "");

}


void KQOAuthManager::requestReplyReceived( QNetworkReply *reply ) {
    qDebug() << "Reply from endpoint: " << reply->readAll();
    reply->deleteLater();           // We need to clean this up, after the event processing is done.

    // TODO: Parse the reply.
    // TODO: Emit some sane return to the customer.
    emit requestReady();
}

KQOAuthManager::KQOAuthError KQOAuthManager::lastError() {
    Q_D(KQOAuthManager);

    return d->error;
}
