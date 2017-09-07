#include "recurringsendpage.h"
#include "ui_recurringSend.h"
#include "ui_recurringEntry.h"
#include "recurringsendentry.h"
#include "bitcoingui.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include <QScrollBar>
#include <QDateTime>


RecurringSendPage::RecurringSendPage(QWidget *parent):
  QDialog(parent),
  ui(new Ui::RecurringSendPage),
  optionsModel(NULL)
{
  ui->setupUi(this);
}

RecurringSendPage::~RecurringSendPage()
{
  if(optionsModel)
  {
      QString recurringSendEntries;
      //serialize

      recurringSendEntries += QString().number(QDateTime::currentDateTime().toMSecsSinceEpoch()) + "\n"; //time recorded
      recurringSendEntries += QString().number(ui->entries->count()) + "\n"; //count of entries
      for(int i=0;i<ui->entries->count();++i)
      {
          RecurringSendEntry *entry = qobject_cast<RecurringSendEntry*>(ui->entries->itemAt(i)->widget());
          recurringSendEntries += entry->ui->payFrom->text() + "\n";  //from
          recurringSendEntries += QString().number(entry->period) + "\n"; //period
          uint64_t msRemaining = entry->minutesRemaining*60*1000;
          recurringSendEntries += QString().number(msRemaining) + "\n";//time remaining
          recurringSendEntries += QString().number(entry->recipients.size()) + "\n";//number of recipients
          for(int j=0;j<entry->recipients.size();++j)
          {
              SendCoinsRecipient recipient=entry->recipients.at(j);
              recurringSendEntries += recipient.label + "\n";
              recurringSendEntries += recipient.address + "\n";
              recurringSendEntries += QString().number(recipient.amount) + "\n";
          }
      }
      optionsModel->setRecurringSendEntries(recurringSendEntries);
  }
  delete ui;
}

void RecurringSendPage::addRecurringEntry(QString from, int repeatDays, unsigned long int remainingTime)
{
  RecurringSendEntry *entry = new RecurringSendEntry(this, from, repeatDays, remainingTime);
  entry->setModel(model);
  ui->entries->addWidget(entry);
  connect(entry, SIGNAL(removeRecurringEntry(RecurringSendEntry*)), this, SLOT(removeRecurringEntry(RecurringSendEntry*)));
}

void RecurringSendPage::addRecurringRecipient(SendCoinsRecipient recipient)
{
  int latestEntry=ui->entries->count()-1;
  RecurringSendEntry *entry = qobject_cast<RecurringSendEntry*>(ui->entries->itemAt(latestEntry)->widget());
  entry->addPayTo(recipient);
}

void RecurringSendPage::removeRecurringEntry(RecurringSendEntry* entry)
{
    delete entry;
}

void RecurringSendPage::setOptionsModel(OptionsModel *optionsModel)
{
    this->optionsModel = optionsModel;
}

void RecurringSendPage::setModel(WalletModel *model)
{
    this->model = model;
    QString recurringSendEntries = optionsModel->getRecurringSendEntries();
    //deserialize saved recurring entries
    QRegExp rx("[\n]");// match a return
    QStringList list = recurringSendEntries.split(rx, QString::SkipEmptyParts);
    if(list.count()>1)
    {
      int listIndex=0;
      qint64 timeRecorded=list.at(listIndex++).toULongLong();
      uint64_t offlineTime=QDateTime::currentDateTime().toMSecsSinceEpoch()-timeRecorded;
      int entryCount = list.at(listIndex++).toInt();

      for(int i = 0; i < entryCount; ++i)
      {
          QString from=list.at(listIndex++);
          int period = list.at(listIndex++).toInt();
          uint64_t msRemaining = list.at(listIndex++).toULong();
          if(msRemaining > offlineTime)  //ensure two minutes before send
          {
              msRemaining = msRemaining - offlineTime;
          }
          else
          {
              msRemaining = 2 * 60 * 1000;
          }

          addRecurringEntry(from,period,msRemaining);

          int recipientCount = list.at(listIndex++).toInt();
          for(int j = 0; j < recipientCount; ++j)
          {
              SendCoinsRecipient recipient;
              recipient.label=list.at(listIndex++);
              recipient.address=list.at(listIndex++);
              recipient.amount=list.at(listIndex++).toInt();
              addRecurringRecipient(recipient);
          }
      }
    }
}
