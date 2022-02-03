from PyQt5 import QtCore, QtWidgets

import idaapi

class CFuncGraphViewer(idaapi.GraphViewer):
	def __init__(self, title, graph=None):
		idaapi.GraphViewer.__init__(self, title)
		self.graph = graph
		self.nodes_id = {}

		# for node in self.graph.get_nodes():


	def OnRefresh(self):
		self.Clear()
		_ = self.AddNode((True, "huy", "huy", None))
		# pizda_node = self.AddNode('pizda')
		# self.AddEdge(huy_node, pizda_node)


		return True

	def OnHint(self, node_id):
		return 'huy'
	
	def OnGetText(self, node_id):
		return 'huy'
