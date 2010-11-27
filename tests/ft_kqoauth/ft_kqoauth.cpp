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
#include "ft_kqoauth.h"

// Qt includes
#include <QtDebug>
#include <QTest>
#include <QUrl>
#include <QTimer>
#include <QNetworkReply>

// Project includes
#include <QtKOAuth>

bool MyEventLoop::timeout() const
{
    return m_timeout;
}

int MyEventLoop::exec( QEventLoop::ProcessEventsFlags flags )
{
    m_timeout = false;
    return QEventLoop::exec( flags );
}

void MyEventLoop::quitWithTimeout()
{
    QEventLoop::quit();
    m_timeout = true;
}

void Ft_KQOAuth::init()
{
    manager = new KQOAuthManager(this);
    req = new KQOAuthRequest(this);

}

void Ft_KQOAuth::cleanup()
{
    delete manager;
    delete req;
}

void Ft_KQOAuth::constructor()
{
    QVERIFY( manager );
}

void Ft_KQOAuth::ft_getRequestToken_data() {
    QTest::addColumn<QUrl>("endpoint");
    QTest::addColumn<QString>("consumerKey");
    QTest::addColumn<QString>("consumerSecret");
    QTest::addColumn<QUrl>("callback");

    QTest::newRow("basicRequestToken")
            << QUrl("http://term.ie/oauth/example/request_token.php")
            << QString("key")
            << QString("secret")
            << QUrl("http://localhost:4242");

}

void Ft_KQOAuth::ft_getRequestToken() {
    QFETCH(QUrl, endpoint);
    QFETCH(QString, consumerKey);
    QFETCH(QString, consumerSecret);
    QFETCH(QUrl, callback);

    req->initRequest(KQOAuthRequest::TemporaryCredentials, endpoint);
    req->setConsumerKey(consumerKey);
    req->setConsumerSecretKey(consumerSecret);
    req->setCallbackUrl(callback);

    MyEventLoop loop;

    connect(manager, SIGNAL(requestReady(QByteArray)), &loop, SLOT(quit()));
    connect(manager, SIGNAL(requestReady(QByteArray)), this, SLOT(onRequestReady(QByteArray)));
    QTimer::singleShot( 10000, &loop, SLOT(quitWithTimeout()) );

    manager->executeRequest(req);
    loop.exec();

    if ( loop.timeout() ) {
        QWARN( "Request timeout" );
    } else {
        qDebug() << "Done!";
    }

}

void Ft_KQOAuth::onRequestReady(QByteArray response) {
    qDebug() << response;
    QCOMPARE(manager->lastError(), KQOAuthManager::NoError );
}


void Ft_KQOAuth::ft_getAccessToken_data() {
    QTest::addColumn<QUrl>("endpoint");
    QTest::addColumn<QString>("consumerKey");
    QTest::addColumn<QString>("consumerSecret");
    QTest::addColumn<QString>("tokenSecret");
    QTest::addColumn<QString>("token");
    QTest::addColumn<QString>("verifier");

    QTest::newRow("basicAccessToken")
            << QUrl("http://term.ie/oauth/example/access_token.php")
            << QString("key")
            << QString("secret")
            << QString("requestsecret")
            << QString("requestkey")
            << QString("xx");

}

void Ft_KQOAuth::ft_getAccessToken() {
    QFETCH(QUrl, endpoint);
    QFETCH(QString, consumerKey);
    QFETCH(QString, consumerSecret);
    QFETCH(QString, tokenSecret);
    QFETCH(QString, token);
    QFETCH(QString, verifier);

    req->initRequest(KQOAuthRequest::AccessToken, endpoint);
    req->setConsumerKey(consumerKey);
    req->setConsumerSecretKey(consumerSecret);
    req->setTokenSecret(tokenSecret);
    req->setToken(token);
    req->setVerifier(verifier);

    QCOMPARE(req->isValid(), true);

    MyEventLoop loop;

    connect(manager, SIGNAL(requestReady(QByteArray)), &loop, SLOT(quit()));
    connect(manager, SIGNAL(requestReady(QByteArray)), this, SLOT(onRequestReady(QByteArray)));
    QTimer::singleShot( 10000, &loop, SLOT(quitWithTimeout()) );

    manager->executeRequest(req);
    loop.exec();

    if ( loop.timeout() ) {
        QWARN( "Request timeout" );
    } else {
        qDebug() << "Done!";
    }

}

void Ft_KQOAuth::ft_AuthenticatedCall_data() {
    QTest::addColumn<QUrl>("endpoint");
    QTest::addColumn<QString>("consumerKey");
    QTest::addColumn<QString>("consumerSecret");
    QTest::addColumn<QString>("tokenSecret");
    QTest::addColumn<QString>("token");
    QTest::addColumn<QString>("data_key");
    QTest::addColumn<QString>("data");


    QTest::newRow("basicAccessToken")
            << QUrl("http://term.ie/oauth/example/echo_api.php")
            << QString("key")
            << QString("secret")
            << QString("accesssecret")
            << QString("accesskey")
            << QString("status")
            << QString("setting up my twitter");

}

void Ft_KQOAuth::ft_AuthenticatedCall() {
    QFETCH(QUrl, endpoint);
    QFETCH(QString, consumerKey);
    QFETCH(QString, consumerSecret);
    QFETCH(QString, tokenSecret);
    QFETCH(QString, token);
    QFETCH(QString, data_key);
    QFETCH(QString, data);


    req->initRequest(KQOAuthRequest::AuthorizedRequest, endpoint);
    req->setToken(token);
    req->setTokenSecret(tokenSecret);
    req->setConsumerKey(consumerKey);
    req->setConsumerSecretKey(consumerSecret);

    KQOAuthParameters params;
    params.insert(data_key, data);
    req->setAdditionalParameters(params);

    QCOMPARE(req->isValid(), true);

    MyEventLoop loop;

    connect(manager, SIGNAL(requestReady(QByteArray)), &loop, SLOT(quit()));
    connect(manager, SIGNAL(requestReady(QByteArray)), this, SLOT(onRequestReady(QByteArray)));
    QTimer::singleShot( 10000, &loop, SLOT(quitWithTimeout()) );

    manager->executeRequest(req);
    loop.exec();

    if ( loop.timeout() ) {
        QWARN( "Request timeout" );
    } else {
        qDebug() << "Done!";
    }

}

void Ft_KQOAuth::ft_AuthenticatedGetCall_data() {
    QTest::addColumn<QUrl>("endpoint");
    QTest::addColumn<QString>("consumerKey");
    QTest::addColumn<QString>("consumerSecret");
    QTest::addColumn<QString>("tokenSecret");
    QTest::addColumn<QString>("token");
    QTest::addColumn<QString>("data_key");
    QTest::addColumn<QString>("data");


    QTest::newRow("basicAccessToken")
            << QUrl("http://term.ie/oauth/example/echo_api.php")
            << QString("key")
            << QString("secret")
            << QString("accesssecret")
            << QString("accesskey")
            << QString("status")
            << QString("This is a GET call");

}

void Ft_KQOAuth::ft_AuthenticatedGetCall() {
    QFETCH(QUrl, endpoint);
    QFETCH(QString, consumerKey);
    QFETCH(QString, consumerSecret);
    QFETCH(QString, tokenSecret);
    QFETCH(QString, token);
    QFETCH(QString, data_key);
    QFETCH(QString, data);


    KQOAuthParameters params;
    params.insert(data_key, data);
    req->initRequest(KQOAuthRequest::AuthorizedRequest, endpoint);
    req->setToken(token);
    req->setTokenSecret(tokenSecret);
    req->setConsumerKey(consumerKey);
    req->setConsumerSecretKey(consumerSecret);
    req->setHttpMethod(KQOAuthRequest::GET);

    req->setAdditionalParameters(params);

    QCOMPARE(req->isValid(), true);

    MyEventLoop loop;

    connect(manager, SIGNAL(requestReady(QByteArray)), &loop, SLOT(quit()));
    connect(manager, SIGNAL(requestReady(QByteArray)), this, SLOT(onRequestReady(QByteArray)));
    QTimer::singleShot( 10000, &loop, SLOT(quitWithTimeout()) );

    manager->executeRequest(req);
    loop.exec();

    if ( loop.timeout() ) {
        QWARN( "Request timeout" );
    } else {
        qDebug() << "Done!";
    }

}


QTEST_MAIN(Ft_KQOAuth)
