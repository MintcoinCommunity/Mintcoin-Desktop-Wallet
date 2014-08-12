#include "webviewhandler.h"
#include <QObject>
#include <QTextFrame>
#include <QTextBlock>


WebViewHandler::WebViewHandler()
{
}

void WebViewHandler::setWebView(QTextBrowser *webViewIn)
{
  webView=webViewIn;
}

void WebViewHandler::loadPage(QString address)
{
  url = QUrl(address);
  req.setUrl(url);
  QNetworkReply *reply = netManager.get(req);
  connect(reply, SIGNAL(finished()), this, SLOT(htmlReply()));
}

void WebViewHandler::htmlReply()
{
  QNetworkReply *reply = qobject_cast<QNetworkReply*>(sender());
  if (reply)
  {
    QVariant redirectionTarget = reply->attribute(QNetworkRequest::RedirectionTargetAttribute);
    if (!reply->error() && !redirectionTarget.isNull())
    {
      QUrl newUrl = url.resolved(redirectionTarget.toUrl());
      {
        url = newUrl;
        reply->deleteLater();
        loadPage(url.toString());
        return;
      }
    }
    else if (reply->error() == QNetworkReply::NoError)
    {
      //send the html
      QString webPage(reply->readAll());
      webView->setHtml(webPage);
      //request all the images
      QTextDocument document;
      document.setHtml(webPage);
      for(QTextFrame::iterator it = document.rootFrame()->begin(); !(it.atEnd()); ++it)
      {
        QTextBlock block = it.currentBlock();
        if (block.isValid())
        {
          QTextBlock::iterator it;
          for (it = block.begin(); !(it.atEnd()); ++it)
          {
            QTextFragment currentFragment = it.fragment();
            if (currentFragment.isValid())
            {
              if(currentFragment.charFormat().isImageFormat())
              {
               req.setUrl(QUrl(currentFragment.charFormat().toImageFormat().name().toStdString().c_str()));
               QNetworkReply *reply = netManager.get(req);
               connect(reply, SIGNAL(finished()), this, SLOT(imgReply()));
              }
            }
          }
        }
      }
    }
    reply->deleteLater();
  }
}

void WebViewHandler::imgReply()
{
   QNetworkReply *reply = qobject_cast<QNetworkReply*>(sender());
   if (reply)
   {
     if (reply->error() == QNetworkReply::NoError)
     {
         pmap.loadFromData(reply->readAll());
         QImage img(pmap.toImage());
         QUrl url = reply->url();
         webView->document()->addResource(QTextDocument::ImageResource, QUrl(url.toString().toStdString().c_str()), img);
     }
     reply->deleteLater();
   }
}
