
#include "merchantpage.h"
#include "ui_merchants.h"

#include "bitcoingui.h"
#include "guiutil.h"

#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QMenu>
#include <QWebView>
#include <QDesktopServices>


MerchantPage::MerchantPage( QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MerchantPage)
{
    ui->setupUi(this);
    ui->webView->page()->setLinkDelegationPolicy( QWebPage::DelegateAllLinks );
    connect(ui->webView, SIGNAL(linkClicked (const QUrl &)), this, SLOT(urlClicked(const QUrl &)));
}

void MerchantPage::urlClicked(QUrl url)
{
  QDesktopServices::openUrl(url);
}

MerchantPage::~MerchantPage()
{
    delete ui;
}
