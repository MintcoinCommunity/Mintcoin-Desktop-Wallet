#include "splashscreen.h"
#include "clientversion.h"
#include "util.h"

#include <QPainter>
#undef loop /* ugh, remove this when the #define loop is gone from util.h */
#include <QApplication>

SplashScreen::SplashScreen(const QPixmap &pixmap, Qt::WindowFlags f) :
    QSplashScreen(pixmap, f)
{
    // set reference point, paddings
    int paddingRight            = 120;
    int paddingTop              = 25;
    int line1 = 30;
    int line2 = 40;

    float fontFactor            = 1.0;
    float devicePixelRatio      = 1.0;
#if QT_VERSION > 0x050100
    devicePixelRatio = ((QGuiApplication*)QCoreApplication::instance())->devicePixelRatio();
#endif

    // define text to place
    QString titleText       = QString(QApplication::applicationName()).replace(QString("-testnet"), QString(""), Qt::CaseSensitive); // cut of testnet, place it as single object further down
    QString versionText     = QString("Version %1 ").arg(QString::fromStdString(FormatFullVersion()));
    QString copyrightText1   = QChar(0xA9)+QString(" 2009-%1 ").arg(COPYRIGHT_YEAR) + QString(tr("The Bitcoin developers"));
    QString copyrightText2   = QChar(0xA9)+QString(" 2011-%1 ").arg(COPYRIGHT_YEAR) + QString(tr("The MintCoin developers"));

    QString font            = "Arial";

    // load the bitmap for writing some text over it
    QPixmap newPixmap;
    newPixmap     = QPixmap(":/images/splash");

    QPainter pixPaint(&newPixmap);
    pixPaint.setPen(QColor(70,70,70));
    QFontMetrics fm = pixPaint.fontMetrics();

    pixPaint.setFont(QFont(font, 14*fontFactor));
    pixPaint.drawText(newPixmap.width()-paddingRight,paddingTop,versionText);

    // draw copyright stuff
    pixPaint.setFont(QFont(font, 10*fontFactor));
    int copy1width = fm.width(copyrightText1);
    pixPaint.drawText(newPixmap.width()-(copy1width*2)+(copy1width/2),newPixmap.height()-line2,copyrightText1);
    pixPaint.drawText(newPixmap.width()-(copy1width*2)+(copy1width/2)-3,newPixmap.height()-line1,copyrightText2);

    pixPaint.end();

    this->setPixmap(newPixmap);
}
