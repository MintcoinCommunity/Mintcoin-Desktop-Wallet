
#include "merchantpage.h"
#include "ui_merchants.h"

#include "bitcoingui.h"
#include "guiutil.h"

MerchantPage::MerchantPage( QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MerchantPage)
{
    ui->setupUi(this); 
}

void MerchantPage::loadPage()
{
  webViewHandler.setWebView(ui->webView,"http://mintcoinofficial.com/download-wallet/merchant-and-donations/");
}

MerchantPage::~MerchantPage()
{
    delete ui;
}
