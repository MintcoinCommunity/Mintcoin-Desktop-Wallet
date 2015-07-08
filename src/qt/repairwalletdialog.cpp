#include "repairwalletdialog.h"
#include "ui_repairwalletdialog.h"

RepairWalletDialog::RepairWalletDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::RepairWalletDialog)
{
    ui->setupUi(this);
}

RepairWalletDialog::~RepairWalletDialog()
{
    delete ui;
}

void RepairWalletDialog::setResultLabel(QString Result)
{
    ui->resultLabel->setText(Result);
}
