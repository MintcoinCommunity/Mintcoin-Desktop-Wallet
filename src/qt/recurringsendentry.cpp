#include "recurringsendentry.h"
#include <QApplication>
#include <QTimer>
#include "wallet/wallet.h"
#include "walletmodeltransaction.h"
#include "ui_recurringEntry.h"
#include "uint256.h"
#include "bitcoinunits.h"
#include "walletmodel.h"
#include "coincontrol.h"
#include "optionsmodel.h"

RecurringSendEntry::RecurringSendEntry(QWidget *parent, QString from, int repeatDays, unsigned long remainingMs) :
    QFrame(parent),
    ui(new Ui::RecurringSendEntry)
{
    ui->setupUi(this);

    connect(ui->deleteButton,SIGNAL(clicked()), this, SLOT(deleteEntry()));
    ui->tableWidget->setColumnCount(3);
    ui->tableWidget->setRowCount(0);
    QHeaderView *headerView = ui->tableWidget->horizontalHeader();
        #if QT_VERSION < 0x050000
    headerView->setResizeMode(QHeaderView::Stretch);
    headerView->setResizeMode(1, QHeaderView::Interactive);
    headerView->setResizeMode(2, QHeaderView::Interactive);
        #else
    headerView->setSectionResizeMode(QHeaderView::Stretch);
    headerView->setSectionResizeMode(1, QHeaderView::Interactive);
    headerView->setSectionResizeMode(2, QHeaderView::Interactive);
        #endif
    ui->tableWidget->setColumnWidth(1,320);
    ui->tableWidget->setColumnWidth(2,120);

    ui->tableWidget->setHorizontalHeaderItem(0,new QTableWidgetItem(QString("Label")));
    ui->tableWidget->setHorizontalHeaderItem(1,new QTableWidgetItem(QString("Address")));
    ui->tableWidget->setHorizontalHeaderItem(2,new QTableWidgetItem(QString("Amount")));


    //need display of amount
    ui->payFrom->setText(from);
    period = repeatDays;
    int timerRemaining;
    if(remainingMs==0) //default value
    {
        minutesRemaining = period * 24 * 60;
        timerRemaining = 60*1000; // 60 s * 1000ms
    }
    else
    {
        minutesRemaining = remainingMs / (60*1000);
        timerRemaining = remainingMs - minutesRemaining*60*1000;

    }
    if(repeatDays==1)
    {
      ui->period->setText("Send every day");
    }
    else
    {
      ui->period->setText("Send every " + QString().number(repeatDays) + " days" );
    }

    //need timer
    sendTimer = new QTimer(ui->timeRemaining);

    sendTimer->start(timerRemaining);
    connect(sendTimer, SIGNAL(timeout()), this, SLOT(updateSendTimer()));

    updateRemaining();
}

void RecurringSendEntry::updateSendTimer()
{
    minutesRemaining--;
    if(minutesRemaining <= 0)
    {
        sendTimer->setInterval(60*1000);
        minutesRemaining=period * 24 * 60; // reset for next send
        WalletModel::SendCoinsReturn sendstatus;

        WalletModelTransaction currentTransaction(recipients);
        WalletModel::SendCoinsReturn prepareStatus;

        if(model)
        {
            if(ui->payFrom->text()=="Any Address")
            {
                prepareStatus = model->prepareTransaction(currentTransaction);
            }
            else
            {
                CCoinControl coinControlByAddress;
                coinControlByAddress.setUseOnlyMinCoinAge();
                std::map<QString, std::vector<COutput> > mapCoins;
                model->listCoins(mapCoins);
                BOOST_FOREACH(PAIRTYPE(QString, std::vector<COutput>) coins, mapCoins)
                {
                    QString sWalletAddress = coins.first;
                    if(ui->payFrom->text().contains(sWalletAddress,Qt::CaseSensitive))
                    {
                        BOOST_FOREACH(const COutput& out, coins.second)
                        {
                            COutPoint outpt(out.tx->GetHash(), out.i);
                            coinControlByAddress.Select(outpt);
                        }
                    }
                }
                prepareStatus = model->prepareTransaction(currentTransaction,&coinControlByAddress);
            }
            if(prepareStatus.status == WalletModel::OK)
                model->sendCoins(currentTransaction);
        }
    }
  updateRemaining();
}

void RecurringSendEntry::updateRemaining()
{
  int days = minutesRemaining / (24 * 60);
  int hours = (minutesRemaining - days * 24 *60) / 60;
  int minutes = (minutesRemaining - days * 24 *60 - hours *60);
  QString remainingTime("");
  if(days>0) remainingTime = QString().number(days) + " days ";
  if(hours>0) remainingTime += QString().number(hours) + " hrs ";
  if(minutes>0) remainingTime += QString().number(minutes) + " min ";
  ui->timeRemaining->setText(remainingTime + "remain");
}

RecurringSendEntry::~RecurringSendEntry()
{
    delete ui;
}

void RecurringSendEntry::setModel(WalletModel *model)
{
    this->model = model;
}

void RecurringSendEntry::deleteEntry()
{
  emit removeRecurringEntry(this);
}

void RecurringSendEntry::addPayTo(SendCoinsRecipient newRecipient)
{
  int currentRow=ui->tableWidget->rowCount();
  ui->tableWidget->setRowCount(currentRow+1);
  ui->tableWidget->setItem(currentRow,0,new QTableWidgetItem(newRecipient.label));
  ui->tableWidget->setItem(currentRow,1,new QTableWidgetItem(newRecipient.address));
  //need display of amount
  int unit = model->getOptionsModel()->getDisplayUnit();
  ui->tableWidget->setItem(currentRow,2,new QTableWidgetItem(BitcoinUnits::format(unit, newRecipient.amount)));
  recipients.append(newRecipient);
}
