#ifndef UT_KQOAUTH_H
#define UT_KQOAUTH_H

#include <QObject>

class KQOAuthRequest;
class Ut_KQOAuth : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void init();
    void cleanup();
    void constructor();

    void ut_requestTemporaryTokenURL_data();
    void ut_requestTemporaryTokenURL();

private:
    KQOAuthRequest *r;

};

#endif // UT_KQOAUTH_H
