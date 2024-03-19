import tkinter as tk
from tkinter import *
from tkinter import ttk
from PIL import ImageTk
from Controlador import Hyperalert, getHAlert, getIPListAlerts, parsertime, CreateGrafoL1, CreateGrafoL2L3, getGraph


def showIP(): #muestra la lista de ips
		
	listIPs = []
	listIPs = getIPListAlerts()
	row=0
	frTopCenterFull =  LabelFrame(scrollableFrameIP, padx = 10, pady=10)			#creo el frame
	frTopCenterFull.grid(column = 1, row = 0, rowspan=(len(listIPs)), sticky=W+E+N+S)
	for i in listIPs:
		Label(frTopCenterFull, text = i, font= ("verdana",8), justify = "left" ).grid(column=1, row=row)
		row=row+1

def showDataAlert(tabla1, query):
	count = 0

	for a in query:
		al = a['alert']
		event= al['event']
		if event["priority"] == 1:
			color="red"
		if event["priority"] == 2:
			color="orange"
		if event["priority"] == 3:
			color="yellow"
		if event["priority"] == 4:
			color="green"

		tabla1.insert("",'end',text=event["priority"], values = (al["_id"], event["classification"], event["event-id"], event["event-second"], event["event-microsecond"]),tags= color)
		tabla1.tag_configure("red", background="#FF0000")
		tabla1.tag_configure("orange", background="#FFC100")
		tabla1.tag_configure("yellow", background="#FFFF1B")
		tabla1.tag_configure("green", background="#ACFF1B")
		count=count+1
	return count


def getHyperA():

	hyperA = getHAlert()
	row=0
	row1=0

	for doc in hyperA:
		alertas= doc["alerts"]
		nAlerts= int(doc["nAlerts"])
		
		#********************************************************************
		#                		 top right full frame
		#********************************************************************
		frTopRightFull =  LabelFrame(scrollableFrame,text= ("HyperAlert ID:",doc["_id"]), font= ("verdana",8, "bold"), padx = 10, pady=10)			#creo el frame
		frTopRightFull.grid(column = 2, row = row, rowspan=(nAlerts),columnspan=7, sticky=W+E+N+S)
			#********************************************************************
			#                		 top right left frame: Information
			#********************************************************************
		frTopRightLeft =  LabelFrame(frTopRightFull,text= ("Information"), font= ("verdana",8, "bold"), padx = 5, pady=5)							#creo el frame
		frTopRightLeft.grid(column = 2, row = row, rowspan=(nAlerts), columnspan=2,sticky=W+E+N+S)

		tk.Label(frTopRightLeft, text = "Flow ID",  anchor="w" ,font= ("verdana",8, "bold"), justify = "left" ).grid(column=2, row=row, sticky=W+E)
		tk.Label(frTopRightLeft, text = doc["flow"] , anchor="w" ,font= ("verdana",8)).grid(column=3, row=row,sticky=W+E)
		row=row+1
		
		tk.Label(frTopRightLeft, text = "Protocol", anchor="w" ,font= ("verdana",8, "bold")).grid(column=2, row=row, sticky=W+E)
		tk.Label(frTopRightLeft, text = doc["classificationProt"], anchor="w", font= ("verdana",8)).grid(column=3, row=row,sticky=W+E)
		row=row+1

		tupla = doc["tupla"]
		
		tk.Label(frTopRightLeft, text = "Source IP" , anchor="w" ,font= ("verdana",8, "bold")).grid(column=2, row=row, sticky=W+E)
		tk.Label(frTopRightLeft, text = tupla["srcIP"] ,  anchor="w" ,font= ("verdana",8)).grid(column=3, row=row,sticky=W+E)
		row=row+1
		
		tk.Label(frTopRightLeft, text = "Source Port", anchor="w" , font= ("verdana",8, "bold")  ).grid(column=2, row=row, sticky=W+E)
		tk.Label(frTopRightLeft, text = tupla["srcPort"] , anchor="w" , font= ("verdana",8) ).grid(column=3, row=row,sticky=W+E)
		row=row+1
		
		tk.Label(frTopRightLeft, text = "Dest IP", anchor="w" , font= ("verdana",8, "bold") ).grid(column=2, row=row, sticky=W+E)
		tk.Label(frTopRightLeft, text = tupla["destIP"] ,  anchor="w" ,font= ("verdana",8) ).grid(column=3, row=row,sticky=W+E)
		row=row+1

		tk.Label(frTopRightLeft, text= "Dest Port",  anchor="w" ,font= ("verdana",8, "bold") ).grid(column=2, row=row, sticky=W+E)
		tk.Label(frTopRightLeft, text= tupla["destPort"] ,  anchor="w" ,font= ("verdana",8) ).grid(column=3, row=row,sticky=W+E)
		
			#********************************************************************
			#                		 top right right frame: Alerts
			#********************************************************************
		frTopRightRight = LabelFrame(frTopRightFull,text= ("Alerts List"), font= ("verdana",8, "bold"), padx = 5, pady=5)
		frTopRightRight.grid(column=4, row=row1, columnspan=5, rowspan=(nAlerts))

		tabla1 = ttk.Treeview(frTopRightRight, columns= ("#1","#2","#3","#4","#5"), selectmode = "browse")
		tabla1.grid(column=4, row = row1, rowspan= 6, columnspan = 5, sticky=W+E+N+S)

		scrollYTable = ttk.Scrollbar(frTopRightRight, orient="vertical",command = tabla1.yview)
		scrollYTable.grid(column=9, row = row1, rowspan=6, sticky=W+E+N+S)
		tabla1.configure(yscrollcommand = scrollYTable.set)

		tabla1.heading("#0", text= "priority")
		tabla1.heading("#1", text= "id")
		tabla1.heading("#2", text= "classification")
		tabla1.heading("#3", text= "event-id")
		tabla1.heading("#4", text= "event-second")
		tabla1.heading("#5", text= "event-microsecond")

		row1 = row1+showDataAlert(tabla1, alertas)+1
		row = row1


def updateTableGraph():
	nodes = getGraph()

	tabla2 = ttk.Treeview(frBottomLeft, columns= ("#1","#2","#3","#4"), selectmode = "browse")
	tabla2.grid(column=0, row = 0,columnspan=9, rowspan = 10,sticky=W+E+N+S)

	scrollYTable2 = ttk.Scrollbar(frBottomLeft, orient="vertical",command = tabla2.yview)
	scrollYTable2.grid(column=9, row = 0, rowspan=10, sticky=W+E+N+S)
	tabla2.configure(yscrollcommand = scrollYTable2.set)

	tabla2.heading("#0", text= "Src IP")
	tabla2.heading("#1", text= "Dst IP")
	tabla2.heading("#2", text= "Class. Prot")
	tabla2.heading("#3", text= "Criticality")
	tabla2.heading("#4", text= "Num HyperAlerts")

	for doc in nodes:
		info = doc["_id"]
		
		if info["Criticity"] == 1:
			color="red"
		if info["Criticity"] == 2:
			color="orange"
		if info["Criticity"] == 3:
			color="yellow"
		if info["Criticity"] == 4:
			color="green"


		tabla2.insert("",'end',text=info["srcIP"], values = (info["dstIP"], info["ClassProt"], info["Criticity"], info["NumHAs"]),tags= color)
		tabla2.tag_configure("red", background="#FF0000")
		tabla2.tag_configure("orange", background="#FFC100")
		tabla2.tag_configure("yellow", background="#FFFF1B")
		tabla2.tag_configure("green", background="#ACFF1B")

def getWGrafoL1():

	ip = ipGraphL1.get()

	graf = CreateGrafoL1(ip)				#funcion que crea la imagen del grafo
	graf.render('GraphL1.png', view=True)

	return graf 

def getWGrafoL2():
	ip1 = ipGraphL1.get()
	graf = CreateGrafoL1(ip1)
	
	ip = ipGraphL2.get()

	graf=CreateGrafoL2L3(ip,graf)
	graf.render('GraphL2.png', view=True)



#*********************************************
#                  MAIN PROGRAM
#*********************************************

if __name__ == '__main__':	
	Hyperalert()

	window = Tk()

	window.title("Phases of a Cyber-Attack tool")
	window.geometry("1024x768")
	window.attributes("-fullscreen", False)

	#********************************************************************
	#             crear el lienzo y ponen el wallpaper
	#********************************************************************
	container= Frame(window, width= 1024, height =700)#768)
	## Buttons FONDO
	background = Canvas(container, width= 1024, height =700, bg= "#6600cc")
	background.grid(row=0, column=0, columnspan=10, sticky=N+S+W+E)
	image= ImageTk.PhotoImage(file = "./images/wallpaper.png")
	background.create_image(0,0, image = image, anchor= NW)
	
	#********************************************************************
	#                 		top left frame
	#********************************************************************
	frTopLeft = Frame(container, width= 50, height =213, padx =5, pady=5)
	frTopLeft.grid(column=0, row=0, rowspan=15, sticky=N+W) 				#distancia a los bordes de la window

	#********************************************************************
	#                		 top center frame
	#********************************************************************

	frTopCenter =  LabelFrame(container,text= "IPs List", width= 120, height =213,padx = 5, pady=5)
	backgroundC = Canvas(frTopCenter, width=120 , height =213, bg= "#6600cc")
	
	scrollbarIP = ttk.Scrollbar(frTopCenter, orient="vertical",command = backgroundC.yview)
	scrollableFrameIP= ttk.Frame(backgroundC)

	scrollableFrameIP.bind(
		"<Configure>",
		lambda e: backgroundC.configure(
			scrollregion = backgroundC.bbox("all")
			)
		)

	backgroundC.create_window((0,0), window=scrollableFrameIP, anchor="nw")

	backgroundC.configure(yscrollcommand=scrollbarIP.set)

	frTopCenter.grid(row=0, column=1, rowspan=6, sticky=N+W)
	scrollbarIP.grid(row = 0, column=1, rowspan=6, sticky=E+N+S)
	backgroundC.grid(row=0, column=1, rowspan=6, sticky=N+S+W+E)
	
	
	#********************************************************************
	#                		 top right frame
	#********************************************************************
	frTopRight =  LabelFrame(container,text= "Hyper Alerts List", padx = 5, pady=5, width= 600, height=200)
	frTopRight.grid(column=2, row=0, rowspan=6,columnspan=8, sticky=N+W+E)

	## HYPERALERT FONDO
	backgroundR = Canvas(frTopRight, width= 600, height =200, bg= "#6600cc")
	backgroundR.grid(row=0, column=2, columnspan=8,rowspan=6, sticky=N+S+W+E)

	scrollbarTRVFrame=Scrollbar(frTopRight, orient=VERTICAL, command=backgroundR.yview)						 #scroll vertical
	scrollbarTRHFrame=Scrollbar(frTopRight, orient=HORIZONTAL, command=backgroundR.xview)					 #scroll Horizontal
	scrollableFrame= Frame(backgroundR)
	scrollableFrame.bind(
		"<Configure>",
		lambda e: backgroundR.configure(
			scrollregion = backgroundR.bbox("all")
			)
		)
	backgroundR.create_window((0,0), window=scrollableFrame, anchor="nw")
	backgroundR.configure(yscrollcommand=scrollbarTRVFrame.set, xscrollcommand=scrollbarTRHFrame.set)
	scrollbarTRVFrame.grid(row=0, column=10, rowspan=6, sticky=N+S+W+E)
	scrollbarTRHFrame.grid(row=6, column=0, columnspan=10, sticky=W+E)

	#********************************************************************
	#                		 bottom left frame                    		
	#********************************************************************
	## GRAPH FONDO

	frBottomLeft =  LabelFrame(container,text= "Graph Information", width= 1000, height=200)
	
	backgroundBL = Canvas(frBottomLeft, width=1000 , height =200, bg= "#6600cc")

	frBottomLeft.grid(row= 0 , column= 0,  rowspan= 10, columnspan = 9, sticky=S+E+W)
	backgroundBL.grid(row= 0, column= 0,  rowspan= 10, columnspan = 9, sticky=S+E+W)


	#********************************************************************
	#                 top left frame: buttons
	#********************************************************************
	ipListButton = Button(frTopLeft, text="Show IPs" ,padx = 16, pady= 2, command= showIP,  bg= "#e699ff",fg= "#000000")
	ipListButton.grid(row=0, column = 0, sticky=W+E)

	hyperaButton = Button(frTopLeft, text="Show HyperAlert", padx = 16, pady= 2, command= getHyperA, bg= "#e699ff", fg= "#000000")
	hyperaButton.grid(row=1, column = 0, sticky=W+E)


	ipL1Label = tk.Label(frTopLeft, text= "Insert IP L1",  anchor="w" ,font= ("verdana",8, "bold") )
	ipL1Label.grid(row=2, column=0,  sticky=W+E)

	ipGraphL1 = tk.Entry(frTopLeft)
	ipGraphL1.grid(row=3, column = 0, sticky=W+E)

	graphL1Button = tk.Button(frTopLeft, text="Interaction Graph L1", padx = 16, pady= 2, command=getWGrafoL1,bg= "#e699ff",  fg= "#000000")
	graphL1Button.grid(row=4, column = 0, sticky=W+E)

	ipL2Label = tk.Label(frTopLeft, text= "Insert IP L2",  anchor="w" ,font= ("verdana",8, "bold") )
	ipL2Label.grid(row=5, column=0, sticky=W+E)

	ipGraphL2 = tk.Entry(frTopLeft)
	ipGraphL2.grid(row=6, column = 0, sticky=W+E)

	graphL2Button = Button(frTopLeft, text="Interaction Graph L2", padx = 16, pady= 2, command=getWGrafoL2, bg= "#e699ff",fg= "#000000")
	graphL2Button.grid(row=7, column = 0, sticky=W+E)

	graphINFOButton = Button(frTopLeft, text="Graph Info", padx = 16, pady= 2, command= updateTableGraph, bg= "#e699ff",fg= "#000000")
	graphINFOButton.grid(row=8, column = 0, sticky=W+E)

	closeApp=  Button(frTopLeft, text="Close App", padx = 16, pady= 2, command= window.destroy, bg= "#ff8080", fg= "#000000")
	closeApp.grid(row=9, column = 0, sticky=W+E)


	container.grid(row=0, column=0, columnspan=10,rowspan=2000, sticky=N+S+W+E)

	window.mainloop()
		
