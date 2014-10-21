#ifndef MERCHANTPAGE_H
#define MERCHANTPAGE_H

#include <webviewhandler.h>
#include <QDialog>

namespace Ui {
    class MerchantPage;
}

/** Widget that shows a web view of merchants and donations
  */
class MerchantPage : public QDialog
{
    Q_OBJECT

public:
    explicit MerchantPage(QWidget *parent = 0);
    ~MerchantPage();
    void setWebView(QTextBrowser webViewIn);
    void loadPage();

private:
  Ui::MerchantPage *ui;
  WebViewHandler webViewHandler;
};

#endif // MERCHANTPAGE_H
