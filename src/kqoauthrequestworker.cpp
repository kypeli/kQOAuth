#include <QtCore>

#include "kqoauthrequest.h"
#include "kqoauthrequestworker.h"

KQOAuthRequestWorker::KQOAuthRequestWorker(KQOAuthRequest *r, QObject *parent) :
    QObject(parent) ,
    m_request( r ) ,
    m_networkManager( new QNetworkAccessManager ) ,
    m_networkRequest( new QNetworkRequest )
{
    connect(m_networkManager, SIGNAL( finished(QNetworkReply *)),
            this, SLOT( requestReplyReceived(QNetworkReply*) ));
}

KQOAuthRequestWorker::~KQOAuthRequestWorker() {
    delete m_networkManager;
    delete m_networkRequest;
}

void KQOAuthRequestWorker::createAndSendRequest() {
    if( m_request == 0) {
        qWarning() << "Request is NULL. Cannot proceed.";
        return;
    }

    if( !m_request->requestEndpoint().isValid() ) {
        qWarning() << "Request endpoint URL is not valid. Cannot proceed.";
        return;
    }

    // Set the request's URL to the OAuth request's endpoint.
    m_networkRequest->setUrl( m_request->requestEndpoint() );

    // And now fill the request with "Authorization" header data.
    QList<QByteArray> requestHeaders = m_request->requestParameters();
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
    m_networkRequest->setRawHeader("Authorization", authHeader);
    m_networkRequest->setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");

    qDebug() << "Auth request URL and headers: " << m_networkRequest->url() << m_networkRequest->rawHeader("Authorization");

    m_networkManager->post(*m_networkRequest, "");

}

void KQOAuthRequestWorker::requestReplyReceived( QNetworkReply *reply ) {
    qDebug() << "Reply from endpoint: " << reply->readAll();
    reply->deleteLater();  // We need to clean this up, after the event processing is done.

    emit requestDone(reply);
}
