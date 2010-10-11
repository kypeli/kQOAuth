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
#include <QByteArray>
#include <QDateTime>
#include <QCryptographicHash>
#include <QPair>
#include <QStringList>

#include <QtDebug>
#include <QtAlgorithms>

#include "kqoauthrequest.h"
#include "kqoauthrequest_p.h"
#include "kqoauthglobals.h"


//////////// Private d_ptr implementation /////////

KQOAuthRequestPrivate::KQOAuthRequestPrivate()
{

}

QByteArray KQOAuthRequestPrivate::oauthSignature()  {
    QByteArray baseString = requestBaseString();
    Q_UNUSED(baseString);

    return QByteArray();
}

bool normalizedParameterSort(const QPair<QString, QString> &left, const QPair<QString, QString> &right) {
    QString keyLeft = left.first;
    QString valueLeft = left.second;
    QString keyRight = right.first;
    QString valueRight = right.second;

    if(keyLeft == keyRight) {
        return (valueLeft < valueRight);
    } else {
        return (keyLeft < keyRight);
    }
}
QByteArray KQOAuthRequestPrivate::requestBaseString() {

    if( !this->validateRequest() ) {
        // Let's not do anything if this request is not valid.
        qWarning() << "Request is invalid.";
        return QByteArray();
    }

    prepareRequest();

    QByteArray baseString;
    // Every request has these as the commont parameters.
    baseString.append( oauthHttpMethod.toUtf8() + "&");                                                     // HTTP method
    baseString.append( QUrl::toPercentEncoding( oauthRequestEndpoint.toString(QUrl::RemoveQuery) ) + "&" ); // The path and query components

    // Sort the request parameters. These parameters have been
    // initialized earlier.
    switch ( q_ptr->requestType ) {
    case KQOAuthRequest::TemporaryCredentials:
        qSort(temporaryCredentialsParameters.begin(),
                temporaryCredentialsParameters.end(),
                normalizedParameterSort
              );
        break;
    default:
        break;
    }

    // Last append the request parameters correctly encoded.
    baseString.append( encodedParamaterList(temporaryCredentialsParameters) );

    return baseString;
}

bool KQOAuthRequestPrivate::prepareRequest() {
    switch ( q_ptr->requestType ) {
    case KQOAuthRequest::TemporaryCredentials:
        temporaryCredentialsParameters.append( qMakePair( OAUTH_KEY_CALLBACK, QString(QUrl::toPercentEncoding( oauthCallbackUrl.toString()) )));  // This is so ugly that it is almost beautiful.
        temporaryCredentialsParameters.append( qMakePair( OAUTH_KEY_SIGNATURE_METHOD, oauthSignatureMethod ));
        temporaryCredentialsParameters.append( qMakePair( OAUTH_KEY_CONSUMER_KEY, oauthConsumerKey ));
        temporaryCredentialsParameters.append( qMakePair( OAUTH_KEY_VERSION, oauthVersion ));
        temporaryCredentialsParameters.append( qMakePair( OAUTH_KEY_TIMESTAMP, this->oauthTimestamp() ));
        temporaryCredentialsParameters.append( qMakePair( OAUTH_KEY_NONCE, this->oauthNonce() ));
        break;

    case KQOAuthRequest::ResourceOwnerAuth:
        break;
    case KQOAuthRequest::AccessToken:
        break;
    default:
        break;
    }

    return true;
}

QByteArray KQOAuthRequestPrivate::encodedParamaterList(const QList< QPair<QString, QString> > &temporaryCredentialsParameters) {
    QByteArray resultList;

    bool first = true;
    QPair<QString, QString> parameter;
    foreach(parameter, temporaryCredentialsParameters) {
        if(!first) {
            resultList.append( "%26" );
        } else {
            first = false;
        }

        // Here we don't need to explicitely encode the strings to UTF-8 since
        // QUrl::toPercentEncoding() takes care of that for us.
        resultList.append( QUrl::toPercentEncoding(parameter.first)     // Parameter key
                           + "%3D"                                      // '=' encoded
                           + QUrl::toPercentEncoding(parameter.second)  // Parameter value
                          );
    }

    return resultList;
}

QString KQOAuthRequestPrivate::oauthTimestamp() const {
    // This is basically for unit tests only. In most cases we don't set the nonce beforehand.
    if( !oauthTimestamp_.isEmpty() ) {
        return oauthTimestamp_;
    }
    return QString::number(QDateTime::currentDateTime().toTime_t());
}

QString KQOAuthRequestPrivate::oauthNonce() const {
    // This is basically for unit tests only. In most cases we don't set the nonce beforehand.
    if( !oauthNonce_.isEmpty() ) {
        return oauthNonce_;
    }

    QString nonceTimestamp = oauthTimestamp_;

    if( nonceTimestamp.isEmpty()) {
        nonceTimestamp = oauthTimestamp();
    }

    return QCryptographicHash::hash(nonceTimestamp.toAscii(), QCryptographicHash::Md5).toHex();
}

bool KQOAuthRequestPrivate::validateRequest() const {
    switch ( q_ptr->requestType ) {
    case KQOAuthRequest::TemporaryCredentials:

        if( oauthRequestEndpoint.isEmpty() ||
            oauthCallbackUrl.isEmpty() ||
            oauthConsumerKey.isEmpty() ||
            oauthNonce_.isEmpty() ||
            oauthSignatureMethod.isEmpty() ||
            oauthTimestamp_.isEmpty() ||
            oauthVersion.isEmpty() )
        {
            return false;
        }
        return true;

    case KQOAuthRequest::ResourceOwnerAuth:
        return false;
    case KQOAuthRequest::AccessToken:
        return false;
    default:
        return false;
    }

    // We should not come here.
    return false;
}


//////////// Public implementation ////////////////

KQOAuthRequest::KQOAuthRequest(QObject *parent) :
    QObject(parent),
    d_ptr(new KQOAuthRequestPrivate())
{
    Q_D(KQOAuthRequest);
    d->q_ptr = this;

    // Set smart defaults.
    this->setSignatureMethod(KQOAuthRequest::HMAC_SHA1);
    this->setHttpMethod(KQOAuthRequest::POST);
    d_ptr->oauthVersion = "1.0"; // Currently supports only version 1.0
}

KQOAuthRequest::~KQOAuthRequest() {
    delete d_ptr;
}

void KQOAuthRequest::initRequest(KQOAuthRequest::RequestType rtype, const QUrl &requestEndpoint) {
    if( !requestEndpoint.isValid() ) {
        qWarning() << "Endpoint URL is not valid. Ignoring. This request might not work.";
        return;
    }

    if(rtype < 0 || rtype >= KQOAuthRequest::AccessToken) {
        qWarning() << "Invalid request type. Ignoring. This request might not work.";
    }

    requestType = rtype;
    d_ptr->oauthRequestEndpoint = requestEndpoint;
    d_ptr->oauthTimestamp_ = d_ptr->oauthTimestamp();
    d_ptr->oauthNonce_ = d_ptr->oauthNonce();
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

void KQOAuthRequest::setHttpMethod(KQOAuthRequest::RequestHttpMethod httpMethod) {
    QString requestHttpMethodString;

    switch( httpMethod ) {
    case KQOAuthRequest::GET:
        requestHttpMethodString = "GET";
        break;
    case KQOAuthRequest::POST:
        requestHttpMethodString = "POST";
    }

    d_ptr->oauthHttpMethod = requestHttpMethodString;
}
