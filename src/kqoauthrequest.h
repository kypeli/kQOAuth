#ifndef KQOAUTHREQUEST_H
#define KQOAUTHREQUEST_H

#include <QObject>
#include <QUrl>

class KQOAuthRequestPrivate;
class KQOAuthRequest : public QObject
{
    Q_OBJECT
public:
    explicit KQOAuthRequest(QObject *parent = 0);
    ~KQOAuthRequest();

    enum RequestType {
        TemporaryCredentials,
        ResourceOwnerAuth,
        AccessToken
    };

    enum RequestSignatureMethod {
        PLAINTEXT,
        HMAC_SHA1,
        RSA_SHA1
    };

    // Mandatory methods to setup a request
    void initRequest(KQOAuthRequest::RequestType, const QUrl &requestEndpoint);
    void setConsumerKey(const QString &consumerKey);
    void setConsumerSecretKey(const QString &consumerSecretKey);

    // Mandatory methods for acquiring a request token
    void setCallbackUrl(const QUrl &callbackUrl);

    // Optional methods when setting up the request
    void setSignatureMethod(KQOAuthRequest::RequestSignatureMethod = KQOAuthRequest::HMAC_SHA1);

signals:

public slots:

private:
    KQOAuthRequestPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(KQOAuthRequest);

#ifdef UNIT_TEST
    friend class Ut_KQOAuth;
#endif
};

#endif // KQOAUTHREQUEST_H
