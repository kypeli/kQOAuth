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
#ifndef KQOAUTHMANAGER_H
#define KQOAUTHMANAGER_H

#include <QObject>
#include <QMultiMap>

#include "kqoauthrequest.h"
#include "kqoauthrequest_p.h"

class KQOAuthRequest;
class KQOAuthManagerThread;
class KQOAuthManagerPrivate;
class QNetworkReply;
class QNetworkAccessManager;
class QUrl;
class QByteArray;
class KQOAuthManager : public QObject
{
    Q_OBJECT
public:

    enum KQOAuthError {
        NoError,
        NetworkError,
        RequestEndpointError,
        RequestValidationError,
        RequestInvalid,
        RequestUnauthorized,
        RequestError
    };

    explicit KQOAuthManager(QObject *parent = 0);
    ~KQOAuthManager();

    KQOAuthError lastError();

    void executeRequest(KQOAuthRequest *request);
    void setHandleUserAuthorization(bool set);

    bool hasTemporaryToken();
    bool isVerified();
    bool isAuthorized();

    void getUserAuthorization(QUrl authorizationEndpoint);
    void getUserAccessTokens(QUrl accessTokenEndpoint);
    void sendAuthorizedRequest(QUrl requestEndpoint, const KQOAuthParameters &requestParameters);

signals:
    // This signal will be emitted after each request has got a reply.
    void requestReady(QMultiMap<QString, QString>);

    // This signal will be emited when we have an authorization token available
    // (either temporary resource tokens, or authorization tokens).
    void receivedToken(QString, QString);   // oauth_token, oauth_token_secret

    // This signal is emited when the user has authenticated the application to
    // communicate with the protected resources. Next we need to exchange the
    // temporary tokens for access tokens.
    void authorizationReceived(QString, QString); // oauth_token, oauth_verifier

    // This signal is emited when access tokens are received from the service. We are
    // ready to start communicating with the protected resources.
    void accessReceived(QString, QString);  // oauth_token, oauth_token_secret

    // This signal is emited when the authorized request is done.
    // This ends the kQOAuth interactions.
    void authorizedRequestReady();

public slots:

private slots:
    void onRequestReplyReceived( QNetworkReply *reply );
    void onVerificationReceived(QMultiMap<QString, QString> response);

private:
    KQOAuthManagerPrivate *d_ptr;
    Q_DECLARE_PRIVATE(KQOAuthManager);

    QNetworkAccessManager *m_networkManager;
};

#endif // KQOAUTHMANAGER_H
