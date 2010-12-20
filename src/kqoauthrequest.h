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
#ifndef KQOAUTHREQUEST_H
#define KQOAUTHREQUEST_H

#include <QObject>
#include <QUrl>
#include <QMultiMap>

typedef QMultiMap<QString, QString> KQOAuthParameters;

class KQOAuthRequestPrivate;
class KQOAuthRequest : public QObject
{
    Q_OBJECT
public:
    explicit KQOAuthRequest(QObject *parent = 0);
    ~KQOAuthRequest();

    enum RequestType {
        TemporaryCredentials = 0,
        AccessToken,
        AuthorizedRequest
    };

    enum RequestSignatureMethod {
        PLAINTEXT = 0,
        HMAC_SHA1,
        RSA_SHA1
    };

    enum RequestHttpMethod {
        GET = 0,
        POST
    };

    // Mandatory methods to setup a request
    void initRequest(KQOAuthRequest::RequestType type, const QUrl &requestEndpoint);
    void setConsumerKey(const QString &consumerKey);
    void setConsumerSecretKey(const QString &consumerSecretKey);

    // Mandatory methods for acquiring a request token
    void setCallbackUrl(const QUrl &callbackUrl);

    // Mandator methods for acquiring a access token
    void setTokenSecret(const QString &tokenSecret);
    void setToken(const QString &token);
    void setVerifier(const QString &verifier);


    /* Optional methods when setting up the request */
    // Request signature method to use - HMAC_SHA1 currently only supported
    void setSignatureMethod(KQOAuthRequest::RequestSignatureMethod = KQOAuthRequest::HMAC_SHA1);

    // Request's HTTP method.
    void setHttpMethod(KQOAuthRequest::RequestHttpMethod = KQOAuthRequest::POST);
    KQOAuthRequest::RequestHttpMethod httpMethod() const;

    // Additional optional parameters to the request.
    void setAdditionalParameters(const KQOAuthParameters &additionalParams);
    KQOAuthParameters additionalParameters() const;

    KQOAuthRequest::RequestType requestType() const;
    QUrl requestEndpoint() const;
    QList<QByteArray> requestParameters();
    QByteArray requestBody() const;
    bool isValid() const;

    // Clear the request so we can reuse it.
    void clearRequest();

    // Enable verbose debug output for request content.
    void setEnableDebugOutput(bool enabled);

private:    
    KQOAuthRequestPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(KQOAuthRequest);
    Q_DISABLE_COPY(KQOAuthRequest);

    // These classes are only for the internal use of KQOAuthManager so it can
    // work with the opaque request.
    QString consumerKeyForManager() const;
    QString consumerKeySecretForManager() const;
    QUrl callbackUrlForManager() const;

    friend class KQOAuthManager;
#ifdef UNIT_TEST
    friend class Ut_KQOAuth;
#endif
};

#endif // KQOAUTHREQUEST_H
