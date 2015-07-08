#ifndef REPAIRWALLETDIALOG_H
#define REPAIRWALLETDIALOG_H

#include <QDialog>

namespace Ui {
class RepairWalletDialog;
}

class RepairWalletDialog : public QDialog
{
    Q_OBJECT

public:
    explicit RepairWalletDialog(QWidget *parent = 0);
    ~RepairWalletDialog();

    void setResultLabel(QString Result);

private:
    Ui::RepairWalletDialog *ui;
};

#endif // REPAIRWALLETDIALOG_H
