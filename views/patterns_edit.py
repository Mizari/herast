import idaapi

from PyQt5 import QtCore, QtWidgets


class PatternsManager(idaapi.PluginForm):
    def __init__(self):
        super(PatternsManager, self).__init__()
        self.parent = None


    def OnCreate(self, form):
        print('OnCreate')
        self.parent = idaapi.PluginForm.FormToPyQtWidget(form)

        # self.parent.setStyleSheet(
        #     "QPushButton {color: yellow; width: 50px; height: 20px;}"
        # )

        self.parent.resize(400, 600)
        self.parent.setWindowTitle('Patterns Manager')

        test_btn = QtWidgets.QPushButton("Huypizda")

        grid_box = QtWidgets.QGridLayout()
        grid_box.setSpacing(0)
        grid_box.addWidget(test_btn)

        self.parent.setLayout(grid_box)
    
    def OnClose(self, form):
        pass
    
    def Show(self, caption=None, options=0):
        print('Show')
    
        # options = idaapi.PluginForm.WCLS_CLOSE_LATER |\
        #         idaapi.PluginForm.WCLS_SAVE |\
        #         idaapi.PluginForm.WOPN_RESTORE

        return idaapi.PluginForm.Show(self, caption, options=options)