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

#include "kqoauthmanager.h"

////////////// Private implementation ////////////////

class KQOAuthManagerPrivate {
public:
    KQOAuthManagerPrivate(KQOAuthManager *parent) :
        error(KQOAuthManager::NoError) ,
        opaqueRequest(new KQOAuthRequest) ,
        q_ptr(parent) ,
        isVerified(false) ,
        isAuthorized(false)
    {

    }

    ~KQOAuthManagerPrivate() {
        delete opaqueRequest;
    }

    QMultiMap<QString, QString> createRequestResponse(QNetworkReply *reply) {
        QMultiMap<QString, QString> result;
        QString replyString(reply->readAll());

        QStringList parameterPairs = replyString.split('&', QString::SkipEmptyParts);
        foreach(const QString &parameterPair, parameterPairs) {
            QStringList parameter = parameterPair.split('=');
            result.insert(parameter.value(0), parameter.value(1));
        }

        return result;
    }

    bool setSuccessfulVerified( const QMultiMap<QString, QString> request ){
        Q_UNUSED(request)
        if(currentRequestType == KQOAuthRequest::TemporaryCredentials) {

        }
        return false;
    }

    bool setSuccessfulAuthorized( const QMultiMap<QString, QString> request ){
        if(currentRequestType == KQOAuthRequest::AccessToken) {
            isAuthorized = (!QString(request.key("oauth_token")).isEmpty() && !QString(request.key("oauth_token_secret")).isEmpty());
        } else {
            return false;
        }

        if(isAuthorized) {
            requestToken = QString(request.key("oauth_token"));
            requestTokenSecret = QString(request.key("oauth_token_secret"));

        }

        return isAuthorized;
    }

    void emitTokens(const QMultiMap<QString, QString> &requestResponse) {
        Q_Q(KQOAuthManager);

        QString oauthToken = requestResponse.value("oauth_token");
        QString oauthTokenSecret = requestResponse.value("oauth_token_secret");

        if( oauthToken.isEmpty() || oauthTokenSecret.isEmpty() ) {
            error = KQOAuthManager::RequestUnauthorized;
        }

        emit q->receivedToken(oauthToken, oauthTokenSecret);
    }



    KQOAuthManager::KQOAuthError error;
    KQOAuthRequest *r;                  // This request is used to cache the user sent request.
    KQOAuthRequest *opaqueRequest;       // This request is used to creating opaque convenience requests for the user.
    KQOAuthManager * const q_ptr;

    /**
     * The items below are needed in order to store the state of the manager and
     * by that be able to do convenience operations for the user.
     */
    KQOAuthRequest::RequestType currentRequestType;

    // Variables we store here for opaque request handling.
    // NOTE: The variables are labeled the same for both access token request
    //       and protected resource access.
    QString requestToken;
    QString requestTokenSecret;

    bool isVerified;
    bool isAuthorized;

    Q_DECLARE_PUBLIC(KQOAuthManager);
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

    d->currentRequestType = request->requestType;
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

    connect(m_networkManager, SIGNAL(finished(QNetworkReply *)),
            this, SLOT(requestReplyReceived(QNetworkReply*) ));
    m_networkManager->post(m_networkRequest, request->requestBody());

}


void KQOAuthManager::requestReplyReceived( QNetworkReply *reply ) {
    Q_D(KQOAuthManager);

    QNetworkReply::NetworkError networkError = reply->error();
    switch(networkError) {
    case QNetworkReply::NoError:
        d->error = KQOAuthManager::NoError;
        break;

    case QNetworkReply::ContentAccessDenied:
        d->error = KQOAuthManager::RequestUnauthorized;
        break;

    default:
        d->error = KQOAuthManager::NetworkError;
        break;
    }

    if(d->error != KQOAuthManager::NoError) {
        return;
    }

    QMultiMap<QString, QString> requestResponse;
    requestResponse = d->createRequestResponse(reply);

    d->opaqueRequest->clearRequest();
    if( !d->isAuthorized || !d->isVerified ) {
        if( d->setSuccessfulVerified(requestResponse) ) {
        } else if( d->setSuccessfulAuthorized(requestResponse) ) {
            d->opaqueRequest->setConsumerKey(d->r->d_ptr->oauthConsumerKey);
            d->opaqueRequest->setConsumerSecretKey(d->r->d_ptr->oauthConsumerSecretKey);
            d->opaqueRequest->setToken(d->r->d_ptr->oauthToken);
            d->opaqueRequest->setSignatureMethod(KQOAuthRequest::HMAC_SHA1);
        }
    }

    emit requestReady(requestResponse);

    if( d->currentRequestType == KQOAuthRequest::TemporaryCredentials ||
        d->currentRequestType == KQOAuthRequest::AccessToken) {

        d->emitTokens(requestResponse);
    }

    reply->deleteLater();           // We need to clean this up, after the event processing is done.
}

bool KQOAuthManager::isVerified() {
    Q_D(KQOAuthManager);

    return d->isVerified;
}

bool KQOAuthManager::isAuthorized() {
    Q_D(KQOAuthManager);

    return d->isAuthorized;
}

KQOAuthManager::KQOAuthError KQOAuthManager::lastError() {
    Q_D(KQOAuthManager);

    return d->error;
}

//////////// Public convenience API /////////////

void KQOAuthManager::sendAuthorizedRequest(QUrl requestEndpoint, const KQOAuthParameters &requestParameters) {
    Q_D(KQOAuthManager);

    if( !d->isAuthorized ) {
        d->error = KQOAuthManager::RequestUnauthorized;
        return;
    }

    d->opaqueRequest->initRequest(KQOAuthRequest::AuthorizedRequest, requestEndpoint);
    d->opaqueRequest->setRequestBody(requestParameters);
    this->executeRequest(d->opaqueRequest);
}

