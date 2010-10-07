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
