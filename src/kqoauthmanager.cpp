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
#include <QtCore>
#include <QNetworkReply>

#include "kqoauthrequest.h"
#include "kqoauthrequestworker.h"

#include "kqoauthmanager.h"

////////////// Private implementation ////////////////

class KQOAuthManagerPrivate {
public:
    KQOAuthManagerPrivate() {

    }

    ~KQOAuthManagerPrivate() {}

    KQOAuthRequest *r;
    KQOAuthManagerThread *thread;
};


/////////////// Public implementation ////////////////

KQOAuthManager::KQOAuthManager(QObject *parent) :
    QObject(parent) ,
    d_ptr(new KQOAuthManagerPrivate)
{
}

KQOAuthManager::~KQOAuthManager() {
    Q_D(KQOAuthManager);

    delete d->r;
    delete d->thread;
}

void KQOAuthManager::executeRequest(KQOAuthRequest *request) {
    Q_D(KQOAuthManager);

    d->r = request;

    KQOAuthRequestWorker *reqWorker = new KQOAuthRequestWorker(request);
    connect(reqWorker, SIGNAL(requestDone(QNetworkReply*)),
            this, SLOT(onRequestDone(QNetworkReply *)));

    d->thread = new KQOAuthManagerThread;
    reqWorker->moveToThread(d->thread);
    reqWorker->connect( d->thread, SIGNAL(started()), SLOT(createAndSendRequest()) );

    // Start the thread!
    d->thread->start();
}

void KQOAuthManager::onRequestDone(QNetworkReply *reply) {
    qDebug() << "Got reply!" << reply;
}
