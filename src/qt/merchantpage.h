#ifndef MERCHANTPAGE_H
#define MERCHANTPAGE_H

#include <QDialog>
#include <QUrl>

namespace Ui {
    class MerchantPage;
}


/** Widget that shows a list of sending or receiving addresses.
  */
class MerchantPage : public QDialog
{
    Q_OBJECT

public:
    explicit MerchantPage(QWidget *parent = 0);
    ~MerchantPage();

public slots:
    void urlClicked(QUrl url);

private:
    Ui::MerchantPage *ui;

};

#endif // MERCHANTPAGE_H
