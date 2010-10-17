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
#ifndef KQOAUTHREQUEST_H
#define KQOAUTHREQUEST_H

#include <QObject>
#include <QUrl>
#include <QMultiMap>

class KQOAuthRequestPrivate;
class KQOAuthRequest : public QObject
{
    Q_OBJECT
public:
    explicit KQOAuthRequest(QObject *parent = 0);
    ~KQOAuthRequest();

    enum RequestType {
        TemporaryCredentials = 0,
        ResourceOwnerAuth,
        AccessToken
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

    typedef  QMultiMap<QString, QString> KQOAuthAdditionalParameters;

    // Mandatory methods to setup a request
    void initRequest(KQOAuthRequest::RequestType, const QUrl &requestEndpoint);
    void setConsumerKey(const QString &consumerKey);
    void setConsumerSecretKey(const QString &consumerSecretKey);

    // Mandatory methods for acquiring a request token
    void setCallbackUrl(const QUrl &callbackUrl);

    // Optional methods when setting up the request
    void setSignatureMethod(KQOAuthRequest::RequestSignatureMethod = KQOAuthRequest::HMAC_SHA1);
    void setHttpMethod(KQOAuthRequest::RequestHttpMethod = KQOAuthRequest::POST);

    // Additional optional parameters to the request.
    void setAdditionalParameters(const KQOAuthAdditionalParameters &additionalParams);

    QUrl requestEndpoint() const;
    QList<QByteArray> requestParameters();

signals:

public slots:

private:
    KQOAuthRequest::RequestType requestType;
    KQOAuthRequestPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(KQOAuthRequest);

#ifdef UNIT_TEST
    friend class Ut_KQOAuth;
#endif
};

#endif // KQOAUTHREQUEST_H
