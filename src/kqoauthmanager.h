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
#ifndef KQOAUTHMANAGER_H
#define KQOAUTHMANAGER_H

#include <QObject>
#include <QMultiMap>

class KQOAuthRequest;
class KQOAuthManagerThread;
class KQOAuthManagerPrivate;
class QNetworkReply;
class QNetworkAccessManager;
class QUrl;
class QByteArray;
class KQOAuthManager : public QObject
{
    Q_OBJECT
public:

    enum KQOAuthError {
        NoError,
        NetworkError,
        RequestEndpointError,
        RequestValidationError,
        RequestInvalid,
        RequestUnauthorized,
        RequestError
    };

    explicit KQOAuthManager(QObject *parent = 0);
    ~KQOAuthManager();

    KQOAuthError lastError();

    void executeRequest(KQOAuthRequest *request);

    bool isVerified();
    bool isAuthorized();

    void sendAuthorizedRequest(QUrl requestEndpoint, QMultiMap<QByteArray, QByteArray> requestParameters);

signals:
    void requestReady(QMultiMap<QString, QString>);

public slots:

private slots:
    void requestReplyReceived( QNetworkReply *reply );


private:
    KQOAuthManagerPrivate *d_ptr;
    Q_DECLARE_PRIVATE(KQOAuthManager);

    QNetworkAccessManager *m_networkManager;
};

#endif // KQOAUTHMANAGER_H
