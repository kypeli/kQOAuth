#ifndef KQOAUTHREQUESTWORKER_H
#define KQOAUTHREQUESTWORKER_H

#include <QObject>
#include <QNetworkReply>
#include <QThread>

class KQOAuthManagerThread : public QThread
{
protected:
    void run() { exec(); }
};

class KQOAuthRequest;
class KQOAuthRequestWorker : public QObject
{
    Q_OBJECT
public:
    explicit KQOAuthRequestWorker(KQOAuthRequest *r, QObject *parent = 0);
    ~KQOAuthRequestWorker();

signals:
    void requestDone( QNetworkReply *reply );

public slots:
    void createAndSendRequest();

private slots:
    void requestReplyReceived( QNetworkReply *reply );

private:
    KQOAuthRequest *m_request;
    QNetworkAccessManager *m_networkManager;
    QNetworkRequest *m_networkRequest;
};

#endif // KQOAUTHREQUESTWORKER_H
