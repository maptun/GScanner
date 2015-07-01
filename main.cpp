#include "dialog.h"
#include <QApplication>

#define PACKAGE_NAME "Scanner"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    Dialog w;
    app.setQuitOnLastWindowClosed(false);

    //w.show();

    return app.exec();
}
