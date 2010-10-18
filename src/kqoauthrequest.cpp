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
#include "kqoauthutils.h"
#include "kqoauthglobals.h"


//////////// Private d_ptr implementation /////////

KQOAuthRequestPrivate::KQOAuthRequestPrivate( KQOAuthRequest *parent ) :
    q_ptr(parent)
{

}

KQOAuthRequestPrivate::~KQOAuthRequestPrivate() {

}

// This method will not include the "oauth_signature" paramater, since it is calculated from these parameters.
void KQOAuthRequestPrivate::prepareRequest() {
    // If parameter list is not empty, we don't want to insert these values by
    // accident a second time. So giving up.
    if( !requestParameters.isEmpty() ) {
        return;
    }

    switch ( q_ptr->requestType ) {
    case KQOAuthRequest::TemporaryCredentials:
        requestParameters.append( qMakePair( OAUTH_KEY_CALLBACK, QString(QUrl::toPercentEncoding( oauthCallbackUrl.toString()) )));  // This is so ugly that it is almost beautiful.
        requestParameters.append( qMakePair( OAUTH_KEY_SIGNATURE_METHOD, oauthSignatureMethod ));
        requestParameters.append( qMakePair( OAUTH_KEY_CONSUMER_KEY, oauthConsumerKey ));
        requestParameters.append( qMakePair( OAUTH_KEY_VERSION, oauthVersion ));
        requestParameters.append( qMakePair( OAUTH_KEY_TIMESTAMP, this->oauthTimestamp() ));
        requestParameters.append( qMakePair( OAUTH_KEY_NONCE, this->oauthNonce() ));
        insertAdditionalParams(requestParameters);
        break;

    case KQOAuthRequest::ResourceOwnerAuth:
        break;
    case KQOAuthRequest::AccessToken:
        break;
    default:
        break;
    }
}

void KQOAuthRequestPrivate::insertAdditionalParams(QList< QPair<QString, QString> > &requestParams) {
    QList<QString> additionalKeys = this->additionalParams.keys();
    QList<QString> additionalValues = this->additionalParams.values();

    for(int i=0; i<additionalKeys.size(); i++) {
        requestParams.append( qMakePair(additionalKeys.at(i),
                                        additionalValues.at(i))
                             );
    }
}

void KQOAuthRequestPrivate::signRequest() {
    QString signature = this->oauthSignature();
    requestParameters.append( qMakePair( OAUTH_KEY_SIGNATURE, signature) );
}

QString KQOAuthRequestPrivate::oauthSignature()  {
    QByteArray baseString = this->requestBaseString();
    QString signature = KQOAuthUtils::hmac_sta1(baseString, oauthConsumerSecretKey + "&" + oauthTokenSecret);
    return QString( QUrl::toPercentEncoding( signature ) );
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
    QByteArray baseString;

    // Every request has these as the commont parameters.
    baseString.append( oauthHttpMethod.toUtf8() + "&");                                                     // HTTP method
    baseString.append( QUrl::toPercentEncoding( oauthRequestEndpoint.toString(QUrl::RemoveQuery) ) + "&" ); // The path and query components

    // Sort the request parameters. These parameters have been
    // initialized earlier.
    qSort(requestParameters.begin(),
          requestParameters.end(),
          normalizedParameterSort
          );

    // Last append the request parameters correctly encoded.
    baseString.append( encodedParamaterList(requestParameters) );

    return baseString;
}

QByteArray KQOAuthRequestPrivate::encodedParamaterList(const QList< QPair<QString, QString> > &parameters) {
    QByteArray resultList;

    bool first = true;
    QPair<QString, QString> parameter;
    foreach(parameter, parameters) {
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
    d_ptr(new KQOAuthRequestPrivate(this))
{
    Q_D(KQOAuthRequest);

    // Set smart defaults.
    this->setSignatureMethod(KQOAuthRequest::HMAC_SHA1);
    this->setHttpMethod(KQOAuthRequest::POST);
    d->oauthVersion = "1.0"; // Currently supports only version 1.0
}

KQOAuthRequest::~KQOAuthRequest() {
    delete d_ptr;
}

void KQOAuthRequest::initRequest(KQOAuthRequest::RequestType rtype, const QUrl &requestEndpoint) {
    Q_D(KQOAuthRequest);

    if( !requestEndpoint.isValid() ) {
        qWarning() << "Endpoint URL is not valid. Ignoring. This request might not work.";
        return;
    }

    if(rtype < 0 || rtype >= KQOAuthRequest::AccessToken) {
        qWarning() << "Invalid request type. Ignoring. This request might not work.";
    }

    requestType = rtype;
    d->oauthRequestEndpoint = requestEndpoint;
    d->oauthTimestamp_ = d->oauthTimestamp();
    d->oauthNonce_ = d->oauthNonce();
}

void KQOAuthRequest::setConsumerKey(const QString &consumerKey) {
    Q_D(KQOAuthRequest);
    d->oauthConsumerKey = consumerKey;
}

void KQOAuthRequest::setConsumerSecretKey(const QString &consumerSecretKey) {
    Q_D(KQOAuthRequest);
    d->oauthConsumerSecretKey = consumerSecretKey;
}

void KQOAuthRequest::setCallbackUrl(const QUrl &callbackUrl) {
    Q_D(KQOAuthRequest);
    d->oauthCallbackUrl = callbackUrl;
}

void KQOAuthRequest::setSignatureMethod(KQOAuthRequest::RequestSignatureMethod requestMethod) {
    Q_D(KQOAuthRequest);
    QString requestMethodString;

    switch( requestMethod ) {
    case KQOAuthRequest::PLAINTEXT:
        requestMethodString = "PLAINTEXT";
        break;
    case KQOAuthRequest::HMAC_SHA1:
        requestMethodString = "HMAC-SHA1";
        break;
    case KQOAuthRequest::RSA_SHA1:
        requestMethodString = "RSA-SHA1";
        break;
    default:
        // We should not come here
        qWarning() << "Invalid signature method set.";
    }

    d->oauthSignatureMethod = requestMethodString;
}

void KQOAuthRequest::setHttpMethod(KQOAuthRequest::RequestHttpMethod httpMethod) {
    Q_D(KQOAuthRequest);

    QString requestHttpMethodString;

    switch( httpMethod ) {
    case KQOAuthRequest::GET:
        requestHttpMethodString = "GET";
        break;
    case KQOAuthRequest::POST:
        requestHttpMethodString = "POST";
        break;
    default:
        qWarning() << "Invalid HTTP method set.";
    }

    d->oauthHttpMethod = requestHttpMethodString;
}

void KQOAuthRequest::setAdditionalParameters(const KQOAuthAdditionalParameters &additionalParams) {
    Q_D(KQOAuthRequest);
    d->additionalParams = additionalParams;
}

QUrl KQOAuthRequest::requestEndpoint() const {
    Q_D(const KQOAuthRequest);
    return d->oauthRequestEndpoint;
}

QList<QByteArray> KQOAuthRequest::requestParameters() {
    Q_D(KQOAuthRequest);

    QList<QByteArray> requestParamList;

    d->prepareRequest();
    if( !d->validateRequest() ) {
        qWarning() << "Request is not valid! I will still sign it, but it will probably not work.";
    }
    d->signRequest();

    QPair<QString, QString> requestParam;
    QString param;
    QString value;
    foreach(requestParam, d->requestParameters) {
        param = requestParam.first;
        value = requestParam.second;
        requestParamList.append(QString(param + "=\"" + value +"\"").toUtf8());
    }

    return requestParamList;
}
