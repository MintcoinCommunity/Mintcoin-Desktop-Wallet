
#include "merchantpage.h"
#include "ui_merchants.h"

#include "bitcoingui.h"
#include "guiutil.h"

MerchantPage::MerchantPage( QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MerchantPage)
{
    ui->setupUi(this);
    webViewHandler.setWebView(ui->webView);
    webViewHandler.loadPage("http://mintcoin.cc/download-wallet/merchant-and-donations/");
}

MerchantPage::~MerchantPage()
{
    delete ui;
}
