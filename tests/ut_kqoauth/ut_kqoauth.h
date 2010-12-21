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
#ifndef UT_KQOAUTH_H
#define UT_KQOAUTH_H

#include <QObject>

class KQOAuthRequest;
class KQOAuthRequestPrivate;
class Ut_KQOAuth : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void init();
    void cleanup();
    void constructor();

    void ut_requestBaseString_data();
    void ut_requestBaseString();
    void ut_hmac_sha1_data();
    void ut_hmac_sha1();
    void ut_random_nonce();
    void ut_basestring_with_percent_encoding();
    void ut_basestring_with_percent_encoding_data();
    void ut_convert_verifier();

private:
    KQOAuthRequest *r;
    KQOAuthRequestPrivate *d_ptr;

    static const QString twitterExampleBaseString;
    static const QString googleBaseString;

};

#endif // UT_KQOAUTH_H
