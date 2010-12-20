/**
 * TwitterCLI - This file is a part of the kQOAuth library.
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
#include <QCoreApplication>
#include <QStringList>
#include <QtDebug>

#include <QtKOAuth>

#include "twittercli.h"

TwitterCLI::TwitterCLI() {
    oauthRequest = new KQOAuthRequest;
    oauthManager = new KQOAuthManager(this);

    oauthRequest->setEnableDebugOutput(true);
}

TwitterCLI::~TwitterCLI() {
    delete oauthRequest;
    delete oauthManager;
}

void TwitterCLI::getAccess()  {
    connect(oauthManager, SIGNAL(temporaryTokenReceived(QString,QString)),
            this, SLOT(onTemporaryTokenReceived(QString, QString)));

    connect(oauthManager, SIGNAL(authorizationReceived(QString,QString)),
            this, SLOT( onAuthorizationReceived(QString, QString)));

    connect(oauthManager, SIGNAL(accessTokenReceived(QString,QString)),
            this, SLOT(onAccessTokenReceived(QString,QString)));

    connect(oauthManager, SIGNAL(requestReady(QByteArray)),
            this, SLOT(onRequestReady(QByteArray)));

    oauthRequest->initRequest(KQOAuthRequest::TemporaryCredentials, QUrl("https://api.twitter.com/oauth/request_token"));
    oauthRequest->setConsumerKey("9PqhX2sX7DlmjNJ5j2Q");
    oauthRequest->setConsumerSecretKey("1NYYhpIw1fXItywS9Bw6gGRmkRyF9zB54UXkTGcI8");

    oauthManager->setHandleUserAuthorization(true);

    oauthManager->executeRequest(oauthRequest);

}

void TwitterCLI::onTemporaryTokenReceived(QString token, QString tokenSecret)
{
    qDebug() << "Temporary token received: " << token << tokenSecret;

    QUrl userAuthURL("https://api.twitter.com/oauth/authorize");

    if( oauthManager->lastError() == KQOAuthManager::NoError) {
        qDebug() << "Asking for user's permission to access protected resources. Opening URL: " << userAuthURL;
        oauthManager->getUserAuthorization(userAuthURL);
    }

}

void TwitterCLI::onAuthorizationReceived(QString token, QString verifier) {
    qDebug() << "User authorization received: " << token << verifier;

    oauthManager->getUserAccessTokens(QUrl("https://api.twitter.com/oauth/access_token"));
    if( oauthManager->lastError() != KQOAuthManager::NoError) {
        QCoreApplication::exit();
    }
}

void TwitterCLI::onAccessTokenReceived(QString token, QString tokenSecret) {
    qDebug() << "Access token received: " << token << tokenSecret;

    oauthSettings.setValue("oauth_token", token);
    oauthSettings.setValue("oauth_token_secret", tokenSecret);

    qDebug() << "Access tokens now stored. You are ready to send Tweets from user's account!";

    QCoreApplication::exit();
}

void TwitterCLI::onAuthorizedRequestDone() {
    qDebug() << "Request sent to Twitter!";
    QCoreApplication::exit();
}

void TwitterCLI::onRequestReady(QByteArray response) {
    qDebug() << "Response from the service: " << response;
}

void TwitterCLI::sendTweet(QString tweet) {

    if( oauthSettings.value("oauth_token").toString().isEmpty() ||
        oauthSettings.value("oauth_token_secret").toString().isEmpty()) {
        qDebug() << "No access tokens. Aborting.";

        return;
    }

    oauthRequest->initRequest(KQOAuthRequest::AuthorizedRequest, QUrl("http://api.twitter.com/1/statuses/update.xml"));
    oauthRequest->setConsumerKey("9PqhX2sX7DlmjNJ5j2Q");
    oauthRequest->setConsumerSecretKey("1NYYhpIw1fXItywS9Bw6gGRmkRyF9zB54UXkTGcI8");
    oauthRequest->setToken(oauthSettings.value("oauth_token").toString());
    oauthRequest->setTokenSecret(oauthSettings.value("oauth_token_secret").toString());

    KQOAuthParameters params;
    params.insert("status", tweet);
    oauthRequest->setAdditionalParameters(params);

    oauthManager->executeRequest(oauthRequest);

    connect(oauthManager, SIGNAL(authorizedRequestDone()),
            this, SLOT(onAuthorizedRequestDone()));
}

void TwitterCLI::showHelp() {
    QTextStream qout(stdout);
    qout << "TwitterCLI, version 0.9. Author: Johan Paul <johan.paul@gmail.com>\n"
         << "\n"
         << "Usage: twittercli -[at] <tweet>\n"
         << " -a                Request for access tokens.\n"
         << " -t '<tweet>'      Send <tweet> to Twitter after retrieving access tokens\n"
         << "\n";
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName("kQOAuth");
    QCoreApplication::setApplicationName("TwitterCLI");

    QStringList args = QCoreApplication::arguments();

    TwitterCLI tAuth;
    if(args.contains("-t")) {
        if(args.last() != "-t") {
            tAuth.sendTweet(args.last());
        }
     } else if( args.contains("-a")){
        tAuth.getAccess();
    } else {
        tAuth.showHelp();
        return 0;
    }

    return app.exec();

}
