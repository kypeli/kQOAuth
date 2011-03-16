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
#include "kqoauthrequest.h"
#include "kqoauthmanager.h"

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

void Ft_KQOAuth::ft_postRequestLotsOfData_data() {
    QTest::addColumn<QByteArray>("postData");

    QTest::newRow("postNormalData")
            << QByteArray("Nec quam nisl. Tempus vehicula turpis.");
    QTest::newRow("postMoreData")
            << QByteArray("Nec quam nisl. Tempus vehicula turpis. Eros neque commodo. Orci porta id. Dolor suscipit ligula adipiscing luctus mattis. Ac etiam sed rutrum pellentesque vehicula. Volutpat id posuere felis molestie ante leo aliquam lorem. Quis odio neque. Mauris in mattis massa elit eu. Lobortis ipsum a neque a vestibulum. Pulvinar maecenas integer. Eu quam pharetra bibendum donec adipiscing tempus maecenas sed. Luctus vestibulum arcu. Donec dictumst et arcu metus nullam auctor orci velit. Facilisis vestibulum perferendis etiam non sodales. Odio quisque euismod fermentum justo felis turpis netus ipsum eu sodales diam. Convallis duis molesti");
    QTest::newRow("postHugeData")
            << QByteArray("Nec quam nisl. Tempus vehicula turpis. Eros neque commodo. Orci porta id. Dolor suscipit ligula adipiscing luctus mattis. Ac etiam sed rutrum pellentesque vehicula. Volutpat id posuere felis molestie ante leo aliquam lorem. Quis odio neque. Mauris in mattis massa elit eu. Lobortis ipsum a neque a vestibulum. Pulvinar maecenas integer. Eu quam pharetra bibendum donec adipiscing tempus maecenas sed. Luctus vestibulum arcu. Donec dictumst et arcu metus nullam auctor orci velit. Facilisis vestibulum perferendis etiam non sodales. Odio quisque euismod fermentum justo felis turpis netus ipsum eu sodales diam. Convallis duis molestie. Wisi vestibulum ridiculus. Pede nonummy neque. Consectetuer non malesuada suspendisse pede tristique nec qui nascetur a mauris lacus in nullam vestibulum tincidunt ac praesent nonummy vehicula vulputate. Odio vestibulum pellentesque. Sed integer ac imperdiet nec facilisi. Lorem vitae id quis sed cursus. Dui eget ut tortor vestibulum magna in temporibus eget. Ut sollicitudin elit. Consequat id a aliquam vel id. A interdum in. Commodo sed donec. Elit amet mattis. Vestibulum magnis fermentum. Massa et donec cras odio feugiat turpis eget ac commodo dolor semper nullam nullam nunc integer nec scelerisque. Eu vestibulum aenean consectetuer tristique tempus. Mauris sed lorem enim dolor id rutrum sollicitudin ligula. Lacus eleifend imperdiet. Purus volutpat in urna nibh vel non turpis tortor." \
                          "Vestibulum turpis eget ante sit scelerisque. Nam fusce volutpat amet mollis vitae pellentesque in donec. Massa felis nec. Suspendisse proin sed turpis cum sed. Venenatis commodo ac egestas iaculis elit. Lacus mi non neque condimentum nec sodales eget tincidunt libero mi duis. Tellus lectus lorem. Justo lorem augue dui et leo molestiae et vel. Sodales nibh mauris. Rhoncus rhoncus vestibulum." \
                          "Enim lorem sit. Interdum dui nulla ante faucibus quam sunt dictum in viverra lacus metus. Tellus a at. Sodales nam suspendisse nisl a pellentesque minim montes eleifend. Pede non varius.");

}

void Ft_KQOAuth::ft_postRequestLotsOfData() {
    QFETCH(QByteArray, postData);
    sendTestPostRequest(postData);
}

void Ft_KQOAuth::sendTestPostRequest(QByteArray data) {
    req->initRequest(KQOAuthRequest::AuthorizedRequest, QUrl("http://term.ie/oauth/example/echo_api.php"));
    req->setToken("accesskey");
    req->setTokenSecret("accesssecret");
    req->setConsumerKey("key");
    req->setConsumerSecretKey("secret");
    req->setHttpMethod(KQOAuthRequest::POST);

    KQOAuthParameters params;
    params.insert("fooDataParameter", data);
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
