#ifndef RECURRINGSENDENTRY_H
#define RECURRINGSENDENTRY_H

#include <QTime>
#include <QFrame>

namespace Ui {
    class RecurringSendEntry;
}
class uint256;
class SendCoinsRecipient;
class WalletModel;
class QTime;

class RecurringSendEntry : public QFrame
{
    Q_OBJECT

public:
    explicit RecurringSendEntry(QWidget *parent = 0, QString from = "", int repeatDays = 7, unsigned long int remainingMs = 0);
    ~RecurringSendEntry();
    void addPayTo(SendCoinsRecipient recipient);
    void setModel(WalletModel *model);
    void updateRemaining();

Q_SIGNALS:
    void removeRecurringEntry(RecurringSendEntry *entry);

private Q_SLOTS:
    void updateSendTimer();
    void deleteEntry();

public:
    Ui::RecurringSendEntry *ui;
    QList<SendCoinsRecipient> recipients;
    int period;
    int minutesRemaining;
private:
    QTimer *sendTimer;
    WalletModel *model;
};

#endif // RECURRINGSENDENTRY_H
