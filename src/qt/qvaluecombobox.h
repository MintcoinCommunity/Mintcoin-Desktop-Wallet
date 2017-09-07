#ifndef QVALUECOMBOBOX_H
#define QVALUECOMBOBOX_H

#include <QComboBox>
#include <QVariant>

/* QComboBox that can be used with QDataWidgetMapper to select ordinal values from a model. */
class QValueComboBox : public QComboBox
{
    Q_OBJECT

    Q_PROPERTY(QVariant value READ value WRITE setValue NOTIFY valueChanged USER true)

public:
    explicit QValueComboBox(QWidget *parent = 0);

    QVariant value() const;
    void setValue(const QVariant &value);

    /** Specify model role to use as ordinal value (defaults to Qt::UserRole) */
    void setRole(int role);

Q_SIGNALS:
    void valueChanged();

private:
    int role;

private Q_SLOTS:
    void handleSelectionChanged(int idx);
};

#endif // QVALUECOMBOBOX_H
