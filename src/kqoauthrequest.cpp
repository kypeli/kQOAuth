#include <QDateTime>
#include <QCryptographicHash>
#include <QtDebug>

#include "kqoauthrequest.h"
#include "kqoauthrequest_p.h"
#include "kqoauthglobals.h"

//////////// Private d_ptr implementation /////////

KQOAuthRequestPrivate::KQOAuthRequestPrivate()
{

}

QString KQOAuthRequestPrivate::oauthTimestamp() const {
    return QString::number(QDateTime::currentDateTime().toTime_t());
}

QString KQOAuthRequestPrivate::oauthNonce() const {
    QString nonceTimestamp = oauthTimestamp_;

    if( nonceTimestamp.isEmpty()) {
        nonceTimestamp = oauthTimestamp();
    }

    return QCryptographicHash::hash(nonceTimestamp.toAscii(), QCryptographicHash::Md5).toHex();
}

QString KQOAuthRequestPrivate::oauthSignature() const {
    return "";
}


//////////// Public implementation ////////////////

KQOAuthRequest::KQOAuthRequest(QObject *parent) :
    QObject(parent),
    d_ptr(new KQOAuthRequestPrivate())
{
    Q_D(KQOAuthRequest);
    d->q_ptr = this;
}

KQOAuthRequest::~KQOAuthRequest() {
    delete d_ptr;
}

void KQOAuthRequest::initRequest(KQOAuthRequest::RequestType rtype, const QUrl &requestEndpoint) {
    // Nothing yet.
}

void KQOAuthRequest::setConsumerKey(const QString &consumerKey) {
    d_ptr->oauthConsumerKey = consumerKey;
}

void KQOAuthRequest::setConsumerSecretKey(const QString &consumerSecretKey) {
    d_ptr->oauthConsumerSecretKey = consumerSecretKey;
}

void KQOAuthRequest::setCallbackUrl(const QUrl &callbackUrl) {
    d_ptr->oauthCallbackUrl = callbackUrl;
}

void KQOAuthRequest::setSignatureMethod(KQOAuthRequest::RequestSignatureMethod requestMethod) {
    QString requestMethodString;

    switch( requestMethod ) {
    case KQOAuthRequest::PLAINTEXT:
        requestMethodString = "PLAINTEXT";
        break;
    case KQOAuthRequest::HMAC_SHA1:
        requestMethodString = "HMAC_SHA1";
        break;
    case KQOAuthRequest::RSA_SHA1:
        requestMethodString = "RSA_SHA1";
        break;
    default:
        // We should not come here
        requestMethodString = "___INVALID___";
    }

    d_ptr->oauthSignatureMethod = requestMethodString;
}
