#ifndef RECURRINGSENDPAGE_H
#define RECURRINGSENDPAGE_H

#include <QDialog>
#include "walletmodel.h"
#include "recurringsendentry.h"

namespace Ui {
    class RecurringSendPage;
}
class WalletModel;
class SendCoinsEntry;
class SendCoinsRecipient;
class OptionsModel;

class RecurringSendPage : public QDialog
{
  Q_OBJECT

public:
  explicit RecurringSendPage(QWidget *parent = 0);
  ~RecurringSendPage();

  void setOptionsModel(OptionsModel *optionsModel);
  void setModel(WalletModel *model);

public slots:
  void addRecurringEntry(QString from, int repeatDays, unsigned long remainingTime = 0);
  void addRecurringRecipient(SendCoinsRecipient recipient);
  void removeRecurringEntry(RecurringSendEntry* entry);

private:
  Ui::RecurringSendPage *ui;
  WalletModel *model;
  OptionsModel *optionsModel;
};

#endif // RECURRINGSENDPAGE_H
