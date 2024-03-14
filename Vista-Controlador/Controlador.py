from pymongo import * 																													# mongo library
from pymongo import MongoClient, errors
import json 																																		# import the built-in JSON library
import sys 																																			# get arg
import shutil 																																	# copy and move files
import time
from bson.son import SON																												#mongo map reduce
import pprint 																																	# to print json format like pretty() in mongo
import calendar																																	# to get datetime now
import bisect																											              # to order list with bisection algorithm
from iso8601 import parse_date																									# to parse isotime to unixtime
#import networkx as nx  #to create the graph
#import matplotlib.pyplot as plt #to draw the graph
from graphviz import Digraph
timeChange = True #para la defensa cambiar a false antes de meter los datos en la bd

#********************************************************
#   it make the conection to mongodb into a collection
#********************************************************
def conectToDB(db, colection):

	conexion = MongoClient('localhost', 27017) 																		#the connection is local 
	db = conexion[db] 																														#the name of the db
	coleccion = db[colection]																											#the name of the collection where is the register of file 
	return coleccion																															# from snort insert in mongo and where is reading the file

def conectToDBNodes():
	conexion = conectToDB("tranalyzer","nodes")
	return conexion
	
def conectToDBHypera():
	conexion = conectToDB("tranalyzer","HiperAlert")
	return conexion
	
def conectToDBAlerts():
	conexion = conectToDB("tranalyzer","alertas")
	return conexion	

def conectToDBFlow():
	conexion = conectToDB("tranalyzer","flow")
	return conexion	

def conectToDBTime():
	conexion = conectToDB("tranalyzer","timeAnalized")
	return conexion	

def conectToDBGraph():
	conexion = conectToDB("tranalyzer","Graph")
	return conexion	

#**********************************************************************************
#  search ip in list return the position of the ip in the list or -1 if  not exist.
#**********************************************************************************
def binarySearch(listIP, ip):
	low = 0
	high = len(listIP)-1
	mid = 0
	
	while low <= high:
		mid = (high + low)
		if listIP[mid] < ip:
			low = mid + 1
		elif listIP[mid] > ip:
			high = mid - 1
		else:
			return mid
			
	return -1


#***********************************************************
#  search in alerts return list of IPs.
#***********************************************************
def getIPListAlerts():
	listIP = []
	alerts= conectToDBAlerts()
	ip = {}
	ipsSrcSearch = [{"$unwind":"$event.source-ip"},{"$group":{"_id":{"srcIP":"$event.source-ip"}, "count":{"$sum":1}}}]
	ipsDstSearch = [{"$unwind":"$event.destination-ip"},{"$group":{"_id":{"dstIP":"$event.destination-ip"}, "count":{"$sum":1}}}]
	
	ipsrc = alerts.aggregate(ipsSrcSearch)
	ipdst = alerts.aggregate(ipsDstSearch)
	
	for i in ipsrc:
		ip = i["_id"]
		search = binarySearch(listIP, ip["srcIP"])
		if search == -1:
			listIP.append(str(ip["srcIP"]))
			listIP.sort() 

	for i in ipdst:
		ip = i["_id"]
		search = binarySearch(list(listIP), ip["dstIP"])
		if search == -1:
			listIP.append(str(ip["dstIP"]))
			listIP.sort() 

	return listIP                                                      # "srcIP":192.168.1.1


#***********************************************************
#  get the last event time processed
#***********************************************************	
def GetlastTimeAnalized():
	time = 0
	exist = 0
	colTime = conectToDBTime()
	listCollection = []
	listCollection = getAllCollections("tranalyzer")
	lasTime=[]
	
	for col in listCollection: 																										#iterate over the list of collection names
		if(str(col) == 'timeAnalized'):
			exist = 1 																																#timeAnalized exist get lastTimeAnalized
			lasTime = colTime.find()
			for t in lasTime:
				time = t["lastTimeAnalized"]
	if(exist == 0):																																#timeAnalized doesn't exist, create collection and lastTimeAnalized=0																						
		myJson= {"lastTimeAnalized": 0}
		colTime.insert_one(myJson).inserted_id 																			#Insert new time in mongo and create collection
	return time
#***********************************************************
#  update into lastTimeAnalized the last event time analized
#***********************************************************	
def UpdateLTAnalized(sg):
	conexion = conectToDBTime()
	time = GetlastTimeAnalized()
	lasTime = conexion.find()
	
	for t in lasTime:
		time = t["lastTimeAnalized"]
		idtime = t['_id']
		
	query = {"_id":idtime}
	updates = {"$set": {"lastTimeAnalized": sg}}
	
	conexion.update_one(query, updates) 																					#update mongo
	

	
#****************************************************************************
#  it returns all the collections from a db that you pass like a parameter. 
#****************************************************************************	
def getAllCollections(sDB):
	domain = 'localhost:'
	port = 27017
																																								# use a try-except indentation to catch MongoClient() errors
	try: 																																					# try to instantiate a client instance
		  client = MongoClient(
		      host = [ str(domain) + str(port) ],
		      serverSelectionTimeoutMS = 3000 																			# 3 second timeout
		  )
	except errors.ServerSelectionTimeoutError as err:
		  																																					# set the client instance to 'None' if exception
		  client = None
		  																																					# catch pymongo.errors.ServerSelectionTimeoutError
		  print ("pymongo ERROR:", err)

	if client != None:
		database_names = client.list_database_names() 															# the list_database_names() method returns a list of strings
		
		for db in enumerate(database_names): 																				# iterate over the list of db
			if (str(db[1]) == sDB):
				collection_names = client[db[1]].list_collection_names() 								#  list_collection_names() return collection names
		return collection_names 																										#the list of collections from tranalyzer db
	else:
		print ("The domain and port parameters passed to client's host is invalid")
 

	 
#*************************************
#      isoToUnix parser
#*************************************
def isoToUnixtime(time):

	parser= parse_date(str(time))	
	tupla = parser.timetuple()
	seconds = calendar.timegm(tupla) 
	
	return seconds
	
#*******************************************************************
#  update all isotime to unix time. it replace the fields timeFirst,
#  timeLast, duration, tcpBtm in flow collection
#*******************************************************************

def parsertime():
	global timeChange
	print(timeChange)
	if timeChange == False:
		flow = conectToDBFlow()
		fl = flow.find()
		for f in fl:
			timeFirst = isoToUnixtime(f['timeFirst'])
			timeLast = isoToUnixtime(f['timeLast'])
			duration = isoToUnixtime(f['duration'])
			tcpBtm = isoToUnixtime(f['tcpBtm'])
			query = {"_id":f['_id']}
			updates = {"$set":{"timeFirst":timeFirst, "timeLast":timeLast, "duration":duration, "tcpBtm":tcpBtm}}
			flow.update_one(query, updates)
		timeChange = True
	else:
		timeChange = True


#*******************************************************
#   it make a list of the time in seconds for alerts
#*******************************************************
def getListOfSecondsA():
	alerts = conectToDBAlerts()
	eventos = []
	seconds = []
	
	alertasS = [{"$unwind":"$event.event-second"},{"$group":{"_id":{"event-second":"$event.event-second",  "srcIP":"$event.source-ip", "destIP":"$event.destination-ip", "srcPort":"$event.sport-itype", "destPort":"$event.dport-icode"}, "count":{"$sum":1}}}, {"$sort":SON([("event.event-second",-1)])}]
	agrupEvent = alerts.aggregate(alertasS) 
	
	for i in agrupEvent: 
		seconds.append(i['_id'])
		#pprint.pprint(i['_id'])

		
	return seconds
#end getListOfSecondsA

#***********************************************************************************
#  it make a list of the {init, end} time in seconds for flows
#***********************************************************************************
def getListOfSecondsF():
	flows = conectToDBFlow()
	flowTime = []
	seconds =[]
	 
	flowSec= [{"$unwind":"$timeFirst"},{"$group":{"_id":{"secondsInit":"$timeFirst", "secondsFin":"$timeLast","srcIP":"$srcIP", "srcPort": "$srcPort",  "dstIP": "$dstIP", "dstPort":"$dstPort", "_id":"$_id","nDPIclass" :"$nDPIclass"}, "count":{"$sum":1}}}, {"$sort":SON([("timeFirst",-1)])}]
		
		
	agrupflowtime = flows.aggregate(flowSec)

	for i in agrupflowtime: 
		seconds.append(i['_id'])
		#pprint.pprint(seconds)
		
	return seconds
#end getListOfSecondsF

#***********************************************************************************
#  it make a list of data if seconds >= "sg" for flows or alerts
#  list flow structure: {"secondsInit":"$timeFirst", "secondsFin":"$timeLast","srcIP":"$srcIP", "srcPort": "$srcPort",  "dstIP": "$dstIP", "dstPort":"$dstPort", "_id":"$_id","nDPIclass" :"$nDPIclass"}
#  list alert structure: {"seconds":"$event.event-second", "srcIP":"$event.source-ip", "destIP":"$event.destination-ip", "srcPort":"$event.sport-itype", "destPort":"$event.dport-icode", "_id":"$_id", "Classification":"$event.classification"}
#  sg= seconds to compare, 
#  lista= list of alerts or flows,
#  fOa= "f" if is flow list "a" if is alert list
#***********************************************************************************
def getListGEOfSeconds(sg,lista, fOa):  

	newList = []

	if fOa == "f": #flow
		for n in lista:
			if n['secondsInit'] >= sg:
				newList.append(n)

			
	if fOa == "a": #alert
		for z in lista:
			if z['seconds'] >= sg:
				newList.append(z)
	
	return newList

#end getListGEOfSeconds

#***********************************************************************************
#  it make a list of data if seconds <= "sg" for flows or alerts
#  list flow structure: {"secondsInit":"$timeFirst", "secondsFin":"$timeLast","srcIP":"$srcIP", "srcPort": "$srcPort",  "dstIP": "$dstIP", "dstPort":"$dstPort", "_id":"$_id","nDPIclass" :"$nDPIclass"}
#  list alert structure: {"seconds":"$event.event-second", "srcIP":"$event.source-ip", "destIP":"$event.destination-ip", "srcPort":"$event.sport-itype", "destPort":"$event.dport-icode", "_id":"$_id", "Classification":"$event.classification"}
#  sg= seconds to compare, 
#  lista= list of alerts or flows,
#  fOa= "f" if is flow list "a" if is alert list
#***********************************************************************************
def getListLTEOfSeconds(sg, lista, fOa):

	newList = []

	if fOa == "f": #flow
		for n in lista:
			if n['secondsInit'] <= sg:
				newList.append(n)

			
	if fOa == "a": #alert
		for z in lista:
			if z['seconds'] <= sg:
				newList.append(z)
				
	return newList

#end getListLTEOfSeconds



#***********************************************************************************
#  it return True if num sgInit >= num <= sgFin
#***********************************************************************************
def isBetween(sgInit, sgFin, num):
	new = False
	if num >= sgInit:
		if num <= sgFin:
			new = True
					
	return new
#end isBetween


#def menu():

#	selectMenu = int(input())
	
	#************************************************************
	#TO CREATE HIPERALERT WE NEED ALERTS, CLASSIFICATIONS AND FLOW
	#
	#'''agrupar por:
	#	 ip origen, 
	#	 ip destino, 
	#	 puerto orig, 
	#	 puerto dest, 
	#	 lista [ ids]
	#'''
	#	
	#	idf = q['_id']
	#	tin = q['timeFirst']
	#	tfin = q['timeLast']
	#	ipSrc = q['srcIP'] 
	#	pSrc = q['srcPort'] 
	#	ipDes = q['dstIP'] 
	#	pDes = q['dstPort'] 
	#**************************************************************
#**************************************************************************************
#   get all hyperalerts
#**************************************************************************************
def getHAlert():
	#parsertime()
	#Hyperalert()
	hyperA = conectToDBHypera()
	allHyperA = hyperA.find()

	return allHyperA
	
#**************************************************************************************
#   get Graph nodes, edges and info
#**************************************************************************************
def getGraph():

	graph = conectToDBGraph()
	GraphInfo = graph.find()

	return GraphInfo
#**************************************************************************************
#   method valuate criticality of alerts p1, p2 and p3
#**************************************************************************************	
def getCriticidadHA(aP1,aP2, aP3): #alta, medio, baja, muy baja.
	
	if aP1 >= 1:
		criticidad = 1
	elif aP2 >= 1: 
		criticidad = 2
	elif aP3 >= 1:
		criticidad = 3
	else:
		criticidad = 4


	return criticidad

#**************************************************************************************
#   method to calulate criticality of a hyperAlert
#**************************************************************************************
def calculateCriticality(allPriorities):
	countP1 = 0
	countP2 = 0
	countP3 = 0

	for a in allPriorities:
		if a ==1:
			countP1 = countP1+1
		if a ==2:
			countP2 = countP2+1
		if a ==3:
			countP3 = countP3+1	

	criticality=getCriticidadHA(countP1,countP2, countP3)

	return criticality

#**************************************************************************************
#   group by alerts and flow with equal (srcIP, srcPort, dstIp, dstPort)
#**************************************************************************************

def Hyperalert():
	flowid = None 
	prot = "Unknown"
	alerts = conectToDBAlerts()
	flow = conectToDBFlow()	
	hiperA = conectToDBHypera()																#hiperAlert collection in mongodb 
	hiperA.drop()																																	#delete all hiperAlerts
	tupla = []
	count =[]
	idAlertas = []
	allPriorities = []

	#find the same ip and aggregate:
	pipeline = [{"$unwind":"$event.source-ip"},{"$group":{"_id":{"srcIP":"$event.source-ip", "destIP":"$event.destination-ip", "srcPort":"$event.sport-itype", "destPort":"$event.dport-icode"}, "count":{"$sum":1}}}, {"$sort":SON([("count",-1),("_id",-1)])}]
	agrupIP = alerts.aggregate(pipeline) 

	for a in agrupIP:
		tupla= a["_id"]
		count= a["count"]
		destIP = str(tupla['destIP']) #get the field destIP from agrupIP
		srcIP = str(tupla['srcIP']) 
		srcPort = int(tupla['srcPort'])
		destPort = int(tupla['destPort'])
		#find in agrupIP the same tuplas to add in a list of events and the packet-id (is the same id than event.event-id)
		findal = alerts.find({"event.source-ip":srcIP, "event.destination-ip":destIP,  "event.sport-itype":srcPort, "event.dport-icode":destPort},{"_id":1,"event.event-id":1, "event.classification" :1, "event.priority":1, "event.event-second":1, "event.event-microsecond":1}) #alerts	

		for b in findal:
			event = b["event"]
			cadena = {"alert":{"_id":b["_id"],"event":event}}
			priority = event["priority"]
			idAlertas.append(cadena)
			allPriorities.append(priority)
			#pprint.pprint(b)
		#--------------------------------------#

		findfl = flow.find({"srcIP": srcIP, "srcPort": srcPort,  "dstIP": destIP, "dstPort":destPort},{"_id":1,"nDPIclass" :1}) #flow

		for c in findfl:
			flowid = c["_id"]
			prot = c["nDPIclass"]
			
			#pprint.pprint(c["_id"])
			#pprint.pprint(c["nDPIclass"])
		level = calculateCriticality(allPriorities)

		#insert into hiperalertas tupla, count, b["_id"], flows and the protocol type
		myJson= {"tupla": a["_id"],
				"nAlerts": a["count"],
				"alerts": idAlertas,
				"flow" : flowid,
				"classificationProt":prot,
				"criticality": level}
		allPriorities = []
		#pprint.pprint(myJson)
		idAlertas = []																				
		hiperA.insert_one(myJson).inserted_id																					#Insert new file in mongo
	
	#h = hiperA.find()
	#print("\n")
	#for n in h:
	#	pprint.pprint(n)
	#	print("\n----------------------------------------------\n")
		
	####prueba de filtro id.alert.event.event....
	#h = hiperA.find({"idAlertas.alerta.event.event-id": 9})
	#for n in h:
	#	pprint.pprint(n)
	#hiperA.drop()	
#end groupby1()

#**************************************************************************************
#   group by alerts in each flow
#		alertas dentro de flujos event.event-second >= flow "timeFirst" <=	"timeLast"
#**************************************************************************************

def groupby2():
	
	hiperA = conectToDBHypera()																#hiperAlert collection in mongodb
	hiperA.drop()
	al = conectToDBAlerts()
	hiperA.drop()
	timeAlerts = []
	timeFlow = []
	dataAlerts = []
	alerts = []
	
	timeAlerts = getListOfSecondsA() #obtengo las alertas ordenadas por seconds
	timeFlow = getListOfSecondsF()	#obtengo init y fin de flujos con tupla
											
	
	for f in timeFlow: #recorro los flujos
		for a in timeAlerts: #recorro el json
			#pprint.pprint(a)
			if isBetween(f['secondsInit'], f['secondsFin'], a['event-second']): 				#alert in a flow
				if "srcIP" in f:
					if (str(f['srcIP']) == str(a['srcIP'])):
						if (str(f['srcPort']) == str(a['srcPort'])):
							if (str(f['dstIP']) == str(a['destIP'])):
								if (str(f['dstPort']) == str(a['destPort'])): 
									destIP = a["destIP"]
									eventsecond = a["event-second"]
									srcIP = a["srcIP"]
									srcPort = a["srcPort"]
									destPort = a["destPort"]
									
									dataAlerts = al.find({"event.destination-ip":destIP, "event.event-second":eventsecond,"event.source-ip":srcIP,"event.sport-itype":srcPort, "event.dport-icode":destPort},{"_id":1,"event.event-id":1, "event.classification" :1, "event.priority":1, "event.event-second":1, "event.event-microsecond":1, "event.destination-ip":1, "event.event-second":1,"event.source-ip":1,"event.sport-itype":1, "event.dport-icode":1})	#buso el resto de datos de esas alertas
									for da in dataAlerts:
										event = da["event"]
										classification = event["classification"]
										ide = da["_id"]
										eventid = event["event-id"]
										priority = event["priority"]
										second = event["event-second"]
										microsecond = event["event-microsecond"]
										aJson={"alert":{"_id":ide, "event":{"classification": classification,"event-id":eventid,"event-microsecond":microsecond,"event-second":second, "priority":priority}}}
										alerts.append(aJson) #las guardo en json
									#print(alerts[0])
		if len(alerts) > 0:
			#alertJson = {"alert": {"_id":alerts["_id"], "event":{"Classification" : alerts["Classification"], "event-id" : alerts["event-id"], "event-microsecond" : alerts["event-microsecond"], "event-second" : alerts["event-second"], "priority" : alerts["priority"]}}}
			myJson = {"flow": f["_id"], "classificationProt":f["nDPIclass"],"tupla":{"srcIP":f['srcIP'],"srcPort": f['srcPort'],"destIP":f['dstIP'],"destPort":f['dstPort'] }, "alerts": alerts}
			hiperA.insert_one(myJson).inserted_id
			alerts = []
	
	#h = hiperA.find()
	#print("\n")
	#for z in h:
	#	pprint.pprint(z)
	#	print("\n----------------------------------------------\n")

#end groupby2()
	
#***************************************
# group like1 and 2 + a period of time
#***************************************

def groupby3():
	
	print("\nInsert the number of seconds\n")
	period = int(input())
	while (period < 0):
		print("\nYou might insert a number of seconds bigger than 0\n")
		period = int(input())
	
	alerts = conectToDBAlerts()
	flow = conectToDBFlow()	
	hiperA = conectToDBHypera()																#hiperAlert collection in mongodb 
	lastSecondProcesed = conectToDBHypera()
	tupla = []
	count =[]
	idAlertas = []
	pipeline = []
	lastTime = GetlastTimeAnalized()
	
	#ordenar alertas por tiempo
	
	if (lastTime==0): #si el lastime es 0 coger el tiempo mas antiguo lastTime=tiempo mas antiguo
	#find the same ip and aggregate:
		hola=1
	else: #find alerts evet.event-second > lastTime  y < flowfin y flow que flow init >lastTime
		hola=0
		
		
		
		
		pipeline = [{"$unwind":"$event.source-ip"},{"$group":{"_id":{"srcIP":"$event.source-ip", "destIP":"$event.destination-ip", "srcPort":"$event.sport-itype", "destPort":"$event.dport-icode"}, "count":{"$sum":1}}}, {"$sort":SON([("_id",-1)])}]
		agrupIP = alerts.aggregate(pipeline)
		for a in agrupIP:
			tupla = a["_id"]
			count = a["count"]
			destIP = str(tupla['destIP']) #get the field destIP from agrupIP
			srcIP = str(tupla['srcIP']) 
			srcPort = int(tupla['srcPort'])
			destPort = int(tupla['destPort'])
			#find in agrupIP the same tuplas to add in a list of events and the packet-id (is the same id than event.event-id)
			findal = alerts.find({"event.source-ip":srcIP, "event.destination-ip":destIP,  "event.sport-itype":srcPort, "event.dport-icode":destPort},{"_id":1,"event.event-id":1, "event.classification" :1, "event.event-second":1}) #alerts	
			for fa in findal:
				if (cuenta == 0):
					start = int(fa["event.event-second"])
					end = start + period
					cuenta = cuenta + 1
				
		#		"event.event-second" :{'$gte':start, '$lte': end}
		#crear una variable con todos los json que event.event-second > lastTime+6period, period es la ventana de tiempo para agrupar
		#de esa variable agrupar por groupby1
	
	
	#pipeline = [{"$unwind":"$event.source-ip"},{"$group":{"_id":{"srcIP":"$event.source-ip", "destIP":"$event.destination-ip", "srcPort":"$event.sport-itype", "destPort":"$event.dport-icode"}, "count":{"$sum":1}}}, {"$sort":SON([("event.event-second" : -1)])}]
	#agrupIP = alerts.aggregate(pipeline)
	#for a in agrupIP:
	#	tupla = a["_id"]
	#	count = a["count"]
	#	destIP = str(tupla['destIP']) #get the field destIP from agrupIP
	#	srcIP = str(tupla['srcIP']) 
	#	srcPort = int(tupla['srcPort'])
	#	destPort = int(tupla['destPort'])
	#	#find in agrupIP the same tuplas to add in a list of events and the packet-id (is the same id than event.event-id)
	#	findal = alerts.find({"event.source-ip":srcIP, "event.destination-ip":destIP,  "event.sport-itype":srcPort, "event.dport-icode":destPort},{"_id":1,"event.event-id":1, "event.classification" :1, "event.event-second":1}) #alerts	
	#	cuenta = 0
	#	for fa in findal:
	#		if (cuenta == 0):
	#			start = int(fa["event.event-second"])
	#			end = start + period
	#			cuenta = cuenta + 1
			
	#		"event.event-second" :{'$gte':start, '$lte': end}


#*********************************************************		
#
# Agrupa alertas y flujos comunes ipO ipD pO pD segun el tiempo que se le pasa por parametro en sg	
#busco alertas ordenadas por event.second de menos a mas,  .sort([(campo1, pymongo.ASCENDING o 1),(campo2, pymongo.DESCENDING o -1)])
#agrupo alertas entre event.second de la primera y timesg, agrupo por ips, añado los flujos
#*********************************************************

#def groupby3(timeSg):
#	alerts = conectToDBAlerts()
#	pipeline = [{"$unwind":"$event.source-ip"},{"$group":{"_id":{"srcIP":"$event.source-ip", "destIP":"$event.destination-ip", "srcPort":"$event.sport-itype", "destPort":"$event.dport-icode"}, "count":{"$sum":1}}}, {"$sort":SON([("count",-1),("_id",-1)])}]
#	agrupIP = alerts.aggregate(pipeline) 
	
#selecciona una alerta, agrupa ipO ipD pO pD y tiempo >= "event-second" : 1492358992

#agrupa los flujos "timeFirst" >= "event-second",
# y "timeLast" <= : "event-second" + timeSg,
	




#end groupby3()


#***************************************************
#   Search ip in hiperAlert
#***************************************************

def SearchIpInHyperAlert(ip,where): #where puede ser src o dst
	result = []

	hiperA = conectToDBHypera()																#hiperAlert collection in mongodb
	
	where = where.lower()
	
	if where == "src":
		result = hiperA.find({"tupla.srcIP":ip})
		
	if where == "dst":
		result = hiperA.find({"tupla.destIP":ip})

	#for a in result:
	#	pprint.pprint(a)
	#	print("----------------")
	
	return result

#***************************************************
#   Search port in hiperAlert
#***************************************************

def groupby6():
	result = []
	port = ""
	wrong1 = True
	query= "h"
	hiperA = conectToDBHypera()															#hiperAlert collection in mongodb

	while (isinstance(port, int) == False):
		print("which port do you want to look for?")
		port = int(input("write the number of port e.g. 445\n"))
			
	while wrong1:
		print("source Port or destination Port?")
		query = str(input("type: src or dst"))
		query = query.lower()
		if query =="src":
			wrong1 = False
		if query == "dst":
			wrong1 = False

	if query == "src":
		#result = hiperA.find({"_id.srcPort":port})
		result = hiperA.find({"tupla.srcPort":port})
	
	if query == "dst":
		#result = hiperA.find({"_id.dstPort":port})
		result = hiperA.find({"tupla.srcPort":port})
	
	resultcount= result.count()
	#print("\n\nThere are ", resultcount,"result in BD\n")
	
	#for r in result:
	#	print("\n----------------------------------------\n")
	#	pprint.pprint (r)
#end groupby6()

#***************************************************
#  Search ip and port in hiperAlert"
#***************************************************

def groupby7():
	result = []
	wrong = True
	queryip = "h"
	queryp = "h"
	port = ""
	hiperA = conectToDBHypera()																#hiperAlert collection in mongodb
	
	print("which Ip do you want to look for?")
	ip = str(input("type sth like: 192.168.198.203\n"))
	
	
	while wrong:
		print("source IP or destination IP?")
		queryip = str(input("type: src or dst\n"))
		queryip = queryip.lower()
		if queryip =="src":
			wrong = False
		if queryip == "dst":
			wrong = False
	
	while (isinstance(port, int) == False):
		print("which port do you want to look for?")
		port = int(input("write the number of port e.g. 445\n"))
	
	wrong = True
	while wrong:
		print("source Port or destination Port?")
		queryp = str(input("type: src or dst\n"))
		queryp = queryp.lower()
		if queryp =="src":
			wrong = False
		if queryp == "dst":
			wrong = False

	if queryip == "src":
		if queryp == "src":
			result = hiperA.find({"_id.srcPort":port, "_id.srcIP":ip})
		if queryp == "dst":
			result = hiperA.find({"_id.dstPort":port, "_id.srcIP":ip})

	if queryip == "dst":
		if queryp == "src":
			result = hiperA.find({"_id.srcPort":port, "_id.dstIP":ip})
		if queryp == "dst":
			result = hiperA.find({"_id.dstPort":port, "_id.dstIP":ip})

	resultcount= result.count()
	print("\n\nThere are ", resultcount,"result in BD\n")
	
	#for r in result:
	#	print("\n----------------------------------------\n")
	#	pprint.pprint (r)
#end groupby7()

#***************************************************
#   Search classification protocol in hiperAlert"
#***************************************************

def groupby8():
	nDPIclass
#end groupby8()

#***************************************************
#   if you select an wrong option in menu	
#***************************************************
def default():
	print("Wrong option")

#***************************************************
#   exit the program	
#***************************************************

def exitp():
	return 0





#********************************************************
#    add yours functions to do queryes to mongo here....
#********************************************************	
#
#def myfunction(): 
#	......

def diccionario():
	#menu mapping
	dict = {
		0 : exitp,
		1 : groupby1,
		2 : groupby2,
		3 : groupby3,
		4 : groupby4,
		5 : groupby5,
		6 : groupby6,
		7 : groupby7,
		8 : groupby8,
		#add yours queryes to mongo here....
		999 : default
	}
	event = dict.get(selectMenu, default)()

	return event

#*********************************************
#  Method to select the color of the edge
#*********************************************
def getColorCrit(crit):

	color = "#ffffff"
	
	if crit == 1:
		color = "#FF0000" #rojo
	if crit == 2:
		color = "#FFA600" #naranja
	if crit == 3:
		color = "#F0FF00" #amarillo
	if crit == 4:
		color = "#00FF00" #verde

	return color

#*********************************************
#  Method to select the width of the edge
#*********************************************
def getWidthEdge(numveces):

	if int(numveces) == 1:
		penwidth = 1
	if int(numveces) == 2:
		penwidth = 2
	if int(numveces) == 3:
		penwidth = 3
	if int(numveces) >= 4:
		penwidth = 5

	return penwidth


#*********************************************
#  Method to create one node in a graph
#  return the new graph
#*********************************************
def createNode(node, graf):
	grafo = graf
	grafo.node(node,node, shape="egg")

	return grafo

#*********************************************
#  Method to add nodes and edges in a graph
#*********************************************
def addNodes(parent, listNodesCrit, grafo): 
	graf = grafo
	numCom = 0
	
	for n in listNodesCrit:
		#print (n)

		crit = listNodesCrit[n][0]
		numCom = listNodesCrit[n][1]                           ###############################REVISAR!!!!!!!!
		prot= listNodesCrit[n][2]
		c = getColorCrit(int(crit))
		w = getWidthEdge(numCom) 
		#criticality = "Criticity: "+str(crit) + " NumHAs: "+ str(numCom) + str(prot)
		criticality = prot
		graf = createNode(n, grafo)
		graf.edge(parent, n, label = criticality, color = c)#, arrowhead='vee', weight = w) ##only for html
	#print ("///////////////")
	return graf

#****************************************************
# Method to insert in a colecction Graph, graph info
#****************************************************
def InsertNodesDB(parent, listNodesCrit, grafo):
	dbcol = conectToDB("tranalyzer","Graph")

	graf = grafo
	numCom = 0
	
	for n in listNodesCrit:
		crit = listNodesCrit[n][0]
		numCom = listNodesCrit[n][1]                           
		prot= listNodesCrit[n][2]
		c = getColorCrit(int(crit))
		nodesAndEdges ={ "_id":{"srcIP": parent, "dstIP": n, "Criticity": crit, "NumHAs":numCom, "ClassProt":prot}}
		dbcol.replace_one(nodesAndEdges, nodesAndEdges, upsert=True)


#******************************************************
#  Method to get all the comunication with one ip
#  return list[(ip, criticality)]
#******************************************************
def getComunication(ip, where): #where puede ser src o dst
	nodes = []
	where = where.lower()
	hiperA = SearchIpInHyperAlert(ip,where)
	lista = []
	for a in hiperA:
		tupla=a["tupla"]
		if where == "src":
			grafo = (tupla["destIP"], a["criticality"], a["classificationProt"])
		if where == "dst":
			grafo = (tupla["srcIP"], a["criticality"], a["classificationProt"])
		nodes.append(grafo)

	return nodes

#********************************************************
#   It search ips wich ip parent comunicate, then return 
#   dic {ip:[ max criticality, number of comunications, protocol]}
#********************************************************
def getNodesSonsAndFeatures(ip):
	nodes={}
	
	nodesEdges = getComunication(ip, "src")
	for i in nodesEdges:
		nodes[i[0]] =[5,0, i[2]]
	for i in nodesEdges:
		if i[1] < nodes[i[0]][0]:
			nodes[i[0]][0] = i[1]
		nodes[i[0]][1] += 1
	#pprint.pprint(nodes)
	return nodes

#****************************************************************
# Method to create Graph Level 1
#****************************************************************
def CreateGrafoL1(ip):
	grafo = Digraph(comment ='GraphL1', format = 'png')
	nodes = getNodesSonsAndFeatures(ip)
	grafo = createNode(ip, grafo) ##creo el primer nodo
	grafo = addNodes(ip, nodes, grafo) ## añade todos los nodos al grafo con sus características correspondientes
	InsertNodesDB(ip, nodes, grafo)
	#print(grafo.source)
	#grafo.render('GraphL1.png', view=True)
	return grafo

#****************************************************************
# Method to create Graph Level 2
#****************************************************************
def CreateGrafoL2L3(son, grafo):
	nodes = getNodesSonsAndFeatures(son)
	grafo = addNodes(son, nodes, grafo)
	InsertNodesDB(son, nodes, grafo)
	#print(grafo.source)
	#grafo.render('GraphL2.png', view=True)
	return grafo
	

#*********************************************
#                  MAIN PROGRAM
#*********************************************

#if __name__ == '__main__':

	#Hyperalert()
	#graf = CreateGrafoL1("192.168.1.102")
	#graf = CreateGrafoL1("10.6.12.203")

	#graf = CreateGrafoL2L3("10.6.12.157",graf)
	

	#parsertime()
	#  Hyperalert()
	#def CreateGraphL1():
	#grafo = Digraph(comment ='GraphL1', format = 'png')
	#nodes = getNodesSonsAndFeatures("10.128.0.243")
	#grafo = createNode("10.128.0.243", grafo) ##creo el primer nodo
	#grafo = addNodes("10.128.0.243", nodes, grafo) ## añade todos los nodos al grafo con sus características correspondientes
	#print(grafo.source)
	#grafo.render('Graph L1.png', view=True)
	#grafo.view()
	#####end CreateGraphL1()



	#new= nx.Graph()
	#grafo = Digraph(comment ='GraphL1', format = 'png')
	#grafo = createGraph(nodesEdges)

	#nodesEdges = getNodesAndEdges("192.168.198.204", "src")

	#new= nx.Graph()
	#grafo = Digraph(comment ='GraphL1', format = 'png')
	#grafo = addNode(nodesEdges, grafo)

	#print(grafo.source)
	#grafo.render('Graph L1.gv.pdf', view=True)
	#grafo.view()

#
#		event = None
#lastTimeAnalized(3)
#print(GetlastTimeAnalized())
#UpdateLTAnalized(10)

#while(event == None):
#	print("\n************************************************************")
#	print("**                    Correlator                          **")
#	print("************************************************************\n")
#	print("This program  correlates flow, alerts and events to facilitate\nthe CSO's task of evaluating possible cyber attack")
#	print("\n")
#	print("Select the number of one method of correlation:\n")
#	print("1 Group by Source IP, Source Port, Destination IP, Destination \n  Port and flow clasification.\n")
#	print("2 Group by alerts and events in each flow\n") 
#	print("3 Group by 1 but in a period of time (in seconds)\n") 
#	print("4 Group by\n") 
#	print("5 Search ip in hiperAlert\n")
#	print("6 Search port in hiperAlert\n")
#	print("7 Search ip and port in hiperAlert\n")
#	print("8 Search classification protocol in hiperAlert\n")
#	#add yours queryes to mongo here....
#	print("0 exit program\n")
#	event = menu()

