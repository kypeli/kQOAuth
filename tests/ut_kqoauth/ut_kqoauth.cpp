#include "ut_kqoauth.h"

// Qt includes
#include <QtDebug>
#include <QTest>
#include <QtDebug>
#include <QUrl>

// Project includes
#include <QtKOAuth>
#include <kqoauthrequest_p.h>


void Ut_KQOAuth::init()
{
    r = new KQOAuthRequest;
}

void Ut_KQOAuth::cleanup()
{
    delete r;
}

void Ut_KQOAuth::constructor()
{
    QVERIFY( r );
    QVERIFY( r->d_ptr );
}

void Ut_KQOAuth::ut_requestTemporaryTokenURL_data() {
    QTest::addColumn<QString>("consumerKey");
    QTest::addColumn<QString>("consumerSecretKey");
    QTest::addColumn<QUrl>("callbackUrl");
    QTest::addColumn<QByteArray>("signature");

    QTest::newRow("empty signature")
            << QString("key")
            << QString("secret")
            << QUrl( "http://something.empty.invalid" )
            << QByteArray();
}

void Ut_KQOAuth::ut_requestTemporaryTokenURL() {
    r->initRequest(KQOAuthRequest::TemporaryCredentials, QUrl("http://someendpoint.invalid/temporary"));

    qDebug() << r->d_ptr->oauthNonce();
}

QTEST_MAIN(Ut_KQOAuth)
