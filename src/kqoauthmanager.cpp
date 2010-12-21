/**
 * KQOAuth - An OAuth authentication library for Qt.
 *
 * Author: Johan Paul (johan.paul@d-pointer.com)
 *         http://www.d-pointer.com
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
#include <QDesktopServices>

#include "kqoauthmanager.h"
#include "kqoauthmanager_p.h"


////////////// Private d_ptr implementation ////////////////

KQOAuthManagerPrivate::KQOAuthManagerPrivate(KQOAuthManager *parent) :
    error(KQOAuthManager::NoError) ,
    r(0) ,
    opaqueRequest(new KQOAuthRequest) ,
    q_ptr(parent) ,
    callbackServer(new KQOAuthAuthReplyServer(parent)) ,
    isVerified(false) ,
    isAuthorized(false) ,
    autoAuth(false),
    networkManager(new QNetworkAccessManager),
    managerUserSet(false)
{

}

KQOAuthManagerPrivate::~KQOAuthManagerPrivate() {
    delete opaqueRequest;
    opaqueRequest = 0;

    if (!managerUserSet) {
        delete networkManager;
        networkManager = 0;
    }
}

QList< QPair<QString, QString> > KQOAuthManagerPrivate::createQueryParams(const KQOAuthParameters &requestParams) {
    QList<QString> requestKeys = requestParams.keys();
    QList<QString> requestValues = requestParams.values();

    QList< QPair<QString, QString> > result;
    for(int i=0; i<requestKeys.size(); i++) {
        result.append( qMakePair(requestKeys.at(i),
                                 requestValues.at(i))
                      );
    }

    return result;
}

QMultiMap<QString, QString> KQOAuthManagerPrivate::createTokensFromResponse(QByteArray reply) {
    QMultiMap<QString, QString> result;
    QString replyString(reply);

    QStringList parameterPairs = replyString.split('&', QString::SkipEmptyParts);
    foreach (const QString &parameterPair, parameterPairs) {
        QStringList parameter = parameterPair.split('=');
        result.insert(parameter.value(0), parameter.value(1));
    }

    return result;
}

bool KQOAuthManagerPrivate::setSuccessfulRequestToken(const QMultiMap<QString, QString> &request) {
    if (currentRequestType == KQOAuthRequest::TemporaryCredentials) {
        hasTemporaryToken = (!QString(request.value("oauth_token")).isEmpty() && !QString(request.value("oauth_token_secret")).isEmpty());
    } else {
        return false;
    }

    if (hasTemporaryToken) {
        requestToken = QString(request.value("oauth_token"));
        requestTokenSecret = QString(request.value("oauth_token_secret"));
    }

    return hasTemporaryToken;
}

bool KQOAuthManagerPrivate::setSuccessfulAuthorized(const QMultiMap<QString, QString> &request ) {
    if (currentRequestType == KQOAuthRequest::AccessToken) {
        isAuthorized = (!QString(request.value("oauth_token")).isEmpty() && !QString(request.value("oauth_token_secret")).isEmpty());
    } else {
        return false;
    }

    if (isAuthorized) {
        requestToken = QString(request.value("oauth_token"));
        requestTokenSecret = QString(request.value("oauth_token_secret"));
    }

    return isAuthorized;
}

void KQOAuthManagerPrivate::emitTokens(const QMultiMap<QString, QString> &requestResponse) {
    Q_Q(KQOAuthManager);

    QString oauthToken = requestResponse.value("oauth_token");
    QString oauthTokenSecret = requestResponse.value("oauth_token_secret");

    if (oauthToken.isEmpty() || oauthTokenSecret.isEmpty()) {
        error = KQOAuthManager::RequestUnauthorized;
    }

    if (currentRequestType == KQOAuthRequest::TemporaryCredentials) {
        // Signal that we are ready to use the protected resources.
        emit q->temporaryTokenReceived(oauthToken, oauthTokenSecret);
    }

    if (currentRequestType == KQOAuthRequest::AccessToken) {
        // Signal that we are ready to use the protected resources.
        emit q->accessTokenReceived(oauthToken, oauthTokenSecret);
    }

    emit q->receivedToken(oauthToken, oauthTokenSecret);
}

bool KQOAuthManagerPrivate::setupCallbackServer() {
    return callbackServer->listen();
}


/////////////// Public implementation ////////////////

KQOAuthManager::KQOAuthManager(QObject *parent) :
    QObject(parent) ,
    d_ptr(new KQOAuthManagerPrivate(this))
{    

}

KQOAuthManager::~KQOAuthManager()
{
    delete d_ptr;    
}

void KQOAuthManager::executeRequest(KQOAuthRequest *request) {
    Q_D(KQOAuthManager);

    d->r = request;

    if (request == 0) {
        qWarning() << "Request is NULL. Cannot proceed.";
        d->error = KQOAuthManager::RequestError;
        return;
    }

    if (!request->requestEndpoint().isValid()) {
        qWarning() << "Request endpoint URL is not valid. Cannot proceed.";
        d->error = KQOAuthManager::RequestEndpointError;
        return;
    }

    if (!request->isValid()) {
        qWarning() << "Request is not valid. Cannot proceed.";
        d->error = KQOAuthManager::RequestValidationError;
        return;
    }

    d->currentRequestType = request->requestType();
    QNetworkRequest networkRequest;
    // Set the request's URL to the OAuth request's endpoint.
    networkRequest.setUrl( request->requestEndpoint() );

    if (d->autoAuth && d->currentRequestType == KQOAuthRequest::TemporaryCredentials) {
        d->setupCallbackServer();

        QString serverString = "http://localhost:";
        serverString.append(QString::number(d->callbackServer->serverPort()));
        request->setCallbackUrl(QUrl(serverString));
    }

    // And now fill the request with "Authorization" header data.
    QList<QByteArray> requestHeaders = request->requestParameters();
    QByteArray authHeader;

    bool first = true;
    foreach (const QByteArray header, requestHeaders) {
        if (!first) {
            authHeader.append(", ");
        } else {
            authHeader.append("OAuth ");
            first = false;
        }

        authHeader.append(header);
    }
    networkRequest.setRawHeader("Authorization", authHeader);

    connect(d->networkManager, SIGNAL(finished(QNetworkReply *)),
            this, SLOT(onRequestReplyReceived(QNetworkReply*) ));

    if (request->httpMethod() == KQOAuthRequest::GET) {
        // Get the requested additional params as a list of pairs we can give QUrl
        QList< QPair<QString, QString> > urlParams = d->createQueryParams(request->additionalParameters());

        // Take the original URL and append the query params to it.
        QUrl urlWithParams = networkRequest.url();
        urlWithParams.setQueryItems(urlParams);
        networkRequest.setUrl(urlWithParams);

        // Submit the request including the params.
        d->networkManager->get(networkRequest);
    } else if( request->httpMethod() == KQOAuthRequest::POST) {
        networkRequest.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
        d->networkManager->post(networkRequest, request->requestBody());
    }
}


void KQOAuthManager::setHandleUserAuthorization(bool set) {
    Q_D(KQOAuthManager);

    d->autoAuth = set;
}

bool KQOAuthManager::hasTemporaryToken() {
    Q_D(KQOAuthManager);

    return d->hasTemporaryToken;
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

void KQOAuthManager::setNetworkManager(QNetworkAccessManager *manager) {
    Q_D(KQOAuthManager);

    if (manager == 0) {
        d->error = KQOAuthManager::ManagerError;
        return;
    }

    d->managerUserSet = true;
    d->networkManager = manager;
}

QNetworkAccessManager * KQOAuthManager::networkManager() const {
    Q_D(const KQOAuthManager);

    if (d->managerUserSet) {
        return d->networkManager;
    } else {
        return NULL;
    }

}


//////////// Public convenience API /////////////

void KQOAuthManager::getUserAuthorization(QUrl authorizationEndpoint) {
    Q_D(KQOAuthManager);

    if (!d->hasTemporaryToken) {
        qWarning() << "No temporary tokens retreieved. Cannot get user authorization.";
        d->error = KQOAuthManager::RequestUnauthorized;
        return;
    }

    if (!authorizationEndpoint.isValid()) {
        qWarning() << "Authorization endpoint not valid. Cannot proceed.";
        d->error = KQOAuthManager::RequestEndpointError;
        return;
    }

    d->error = KQOAuthManager::NoError;

    connect(d->callbackServer, SIGNAL(verificationReceived(QMultiMap<QString, QString>)),
            this, SLOT( onVerificationReceived(QMultiMap<QString, QString>)));

    QPair<QString, QString> tokenParam = qMakePair(QString("oauth_token"), d->requestToken);
    QList< QPair<QString, QString> > queryParams;
    queryParams.append(tokenParam);

    authorizationEndpoint.setQueryItems(queryParams);

    // Open the user's default browser to the resource authorization page provided
    // by the service.
    QDesktopServices::openUrl(authorizationEndpoint);
}

void KQOAuthManager::getUserAccessTokens(QUrl accessTokenEndpoint) {
    Q_D(KQOAuthManager);

    if (!d->isVerified) {
        qWarning() << "Not verified. Cannot get access tokens.";
        d->error = KQOAuthManager::RequestUnauthorized;
        return;
    }

    if (!accessTokenEndpoint.isValid()) {
        qWarning() << "Endpoint for access token exchange is not valid. Cannot proceed.";
        d->error = KQOAuthManager::RequestEndpointError;
        return;
    }

    d->error = KQOAuthManager::NoError;

    d->opaqueRequest->clearRequest();
    d->opaqueRequest->initRequest(KQOAuthRequest::AccessToken, accessTokenEndpoint);
    d->opaqueRequest->setToken(d->requestToken);
    d->opaqueRequest->setTokenSecret(d->requestTokenSecret);
    d->opaqueRequest->setVerifier(d->requestVerifier);
    d->opaqueRequest->setConsumerKey(d->consumerKey);
    d->opaqueRequest->setConsumerSecretKey(d->consumerKeySecret);

    executeRequest(d->opaqueRequest);
}

void KQOAuthManager::sendAuthorizedRequest(QUrl requestEndpoint, const KQOAuthParameters &requestParameters) {
    Q_D(KQOAuthManager);

    if (!d->isAuthorized) {
        qWarning() << "No access tokens retrieved. Cannot send authorized requests.";
        d->error = KQOAuthManager::RequestUnauthorized;
        return;
    }

    if (!requestEndpoint.isValid()) {
        qWarning() << "Endpoint for authorized request is not valid. Cannot proceed.";
        d->error = KQOAuthManager::RequestEndpointError;
        return;
    }

    d->error = KQOAuthManager::NoError;

    d->opaqueRequest->clearRequest();
    d->opaqueRequest->initRequest(KQOAuthRequest::AuthorizedRequest, requestEndpoint);
    d->opaqueRequest->setAdditionalParameters(requestParameters);
    d->opaqueRequest->setToken(d->requestToken);
    d->opaqueRequest->setTokenSecret(d->requestTokenSecret);
    d->opaqueRequest->setConsumerKey(d->consumerKey);
    d->opaqueRequest->setConsumerSecretKey(d->consumerKeySecret);

    executeRequest(d->opaqueRequest);
}


/////////////// Private slots //////////////////

void KQOAuthManager::onRequestReplyReceived( QNetworkReply *reply ) {
    Q_D(KQOAuthManager);

    QNetworkReply::NetworkError networkError = reply->error();
    switch (networkError) {
    case QNetworkReply::NoError:
        d->error = KQOAuthManager::NoError;
        break;

    case QNetworkReply::ContentAccessDenied:
    case QNetworkReply::AuthenticationRequiredError:
        d->error = KQOAuthManager::RequestUnauthorized;
        break;

    default:
        d->error = KQOAuthManager::NetworkError;
        break;
    }

    QByteArray networkReply = reply->readAll();

    // Just don't do anything if we didn't get anything useful.
    if(networkReply.isEmpty()) {
        reply->deleteLater();
        return;
    }
    QMultiMap<QString, QString> responseTokens;

    // We need to emit the signal even if we got an error.
    if (d->error != KQOAuthManager::NoError) {
        reply->deleteLater();
        emit requestReady(networkReply);
        d->emitTokens(responseTokens);
        return;
    }

    responseTokens = d->createTokensFromResponse(networkReply);
    d->opaqueRequest->clearRequest();
    d->opaqueRequest->setHttpMethod(KQOAuthRequest::POST);   // XXX FIXME: Convenient API does not support GET
    if (!d->isAuthorized || !d->isVerified) {
        if (d->setSuccessfulRequestToken(responseTokens)) {
            qDebug() << "Successfully got request tokens.";
            d->consumerKey = d->r->consumerKeyForManager();
            d->consumerKeySecret = d->r->consumerKeySecretForManager();
            d->opaqueRequest->setSignatureMethod(KQOAuthRequest::HMAC_SHA1);
            d->opaqueRequest->setCallbackUrl(d->r->callbackUrlForManager());

            d->emitTokens(responseTokens);

        } else if (d->setSuccessfulAuthorized(responseTokens)) {
              qDebug() << "Successfully got access tokens.";
              d->opaqueRequest->setSignatureMethod(KQOAuthRequest::HMAC_SHA1);

              d->emitTokens(responseTokens);
          } else if (d->currentRequestType == KQOAuthRequest::AuthorizedRequest) {
                emit authorizedRequestDone();
            }
    }

    emit requestReady(networkReply);

    reply->deleteLater();           // We need to clean this up, after the event processing is done.
}

void KQOAuthManager::onVerificationReceived(QMultiMap<QString, QString> response) {
    Q_D(KQOAuthManager);

    QString token = response.value("oauth_token");
    QString verifier = response.value("oauth_verifier");
    if (verifier.isEmpty()) {
        d->error = KQOAuthManager::RequestUnauthorized;
    }

    verifier = QUrl::fromPercentEncoding(verifier.toUtf8());     // We get the raw URL response here so we need to convert it back
                                                                 // to plain string so we can percent encode it again later in requests.

    if (d->error == KQOAuthManager::NoError) {
        d->requestVerifier = verifier;
        d->isVerified = true;
    }

    emit authorizationReceived(token, verifier);
}

