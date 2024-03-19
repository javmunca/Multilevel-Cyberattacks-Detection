# -*- coding: utf-8 -*-
#########################################################
# 														#
# Programa que:											#
# 														#
# - Lee del directorio de SNORT los logs creados		#
#   convertidos a ficheros json	(de forma continua)		#
#		directorio de logs: /home/tfg/Escritorio/json/	#
#		directorio final: /home/tfg/Escritorio/prueba/	#
# - Inserta los json en la bd MongoDB					#
# 														#
#	TFG "Deteccion de las fases de un ciberataque"		#
#	autora: Elvira Castillo 							#
# https://github.com/layoel/ModeladoFasesCiberAtaques  	#
#	contacto twitter: @layoel							#
#														#
#								licencia CC-BY-SA		#
#								Granada marzo2020		#
#########################################################

#doc watchdog:  https://pythonhosted.org/watchdog/
#programa que comprueba los cambios en el directorio de snort 
#y ejecuta el script para leer un nuevo fichero creado

# How to use: python script-3.py /home/tfg/Escritorio/json/

from pymongo import *                                       #libreria mongo
import json 											    #import the built-in JSON library
import sys 													#para acceder a los argumentos
import time
import datetime 											#para obtener fecha y hora actuales
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler

#--------------------------------METHODS---------------------------------------#

#query is the sentence were will update the last byte read
#conexion is the colection to update
#byte is the las byte read
def updateDBByteRead(query,conexion, byte):
	myNewJson =  { "$set": {"lastByteRead": byte} }
	conexion.update_one(query, myNewJson) 					#update mongo


#query is the sentence were will update the time to init update 
#conexion is the colection to update
def updateDBDateTimeInit(query,conexion):
	init = updateDateTime() 
	myNewJson =  { "$set": {"updateInit": init} }
	conexion.update_one(query, myNewJson) 					#update mongo


##query is the sentence were will update the time to end update
#conexion is the colection to update
def updateDBDateTimeEnd(query,conexion):
	end = updateDateTime() 
	myNewJson =  { "$set": {"updateEnd": end} }
	conexion.update_one(query, myNewJson) 					#update mongo


#it return an array with two fields: one with the date and other with the time
def updateDateTime():
	now = str(datetime.datetime.now()) 									#current date time
	actual = datetime.datetime.strptime(now, "%Y-%m-%d %H:%M:%S.%f")
	
	date1 = [] 															#year month day
	date1.append(actual.year)
	date1.append(actual.month)
	date1.append(actual.day)
	time1 = [] 															#hour minutes seconds
	time1.append(actual.hour)
	time1.append(actual.minute)
	time1.append(actual.microsecond)

	diaYhora = []
	diaYhora.append(date1)
	diaYhora.append(time1)
	return diaYhora


#it make the conection to mongodb
def conectToDB(colection):
	conexion = MongoClient('localhost', 27017) 		#the connection is local 
	db = conexion['tranalyzer'] 					#the name of the db
	coleccion = db[colection]						#the name of the collection where is the register of file 
	return coleccion								#from snort insert in mongo and where is reading the file 

																				 
# @breaf: when a file is created new in a directory																															
# this method insert in mongo a json with the next
# Structure of the colection LogsSnort in mongo																	 
# @param: event new file in a directory
def on_created(event):
	path = event.src_path
	cadena = "Se ha CREADO un archivo "+ path 
	print(cadena)

	init = updateDateTime()
	end = init

	myJson= {"fileName": path,
				"lastByteRead": 0,
				"updateInit": init,
				"updateEnd" : end}
																					
	col= 'LogsSnort'											#col collection in mongodb 
	coLogs = conectToDB(col)																																							

	coLogs.insert_one(myJson).inserted_id 						#Insert new file in mongo	
	with open(path, 'r') as f:
		cole= 'alertas'											#col collection in mongodb 
		alertas = conectToDB(cole)
		fileSize = len(f.read())
		f.seek(0)
		lastByteRead = f.tell()									#save the number of last byte read
		consulta= {"fileName": path}
		mydoc = coLogs.find(consulta)
		while fileSize >lastByteRead :
			content = f.readline() 								#read one line
			readJson = json.loads(content) 						#convert to json dictionary
			alertas.insert_one(readJson).inserted_id 			#Insert new file in mongo	
			lastByteRead = f.tell()								#save the number of last byte read
			print(lastByteRead)
			updateDBByteRead(consulta,coLogs, lastByteRead)
			updateDBDateTimeEnd(consulta,coLogs)



# @breaf: when a file is update it make a query to get the	
def on_modified(event):
	path = event.src_path
	# para probar: path = "/home/tfg/Escritorio/json/a.json"

	#FIND A PATH IN COLLECTION
	consulta= {"fileName": path}
	col= 'LogsSnort'								#col collection in mongodb 
	coLogs = conectToDB(col)		
	mydoc = coLogs.find_one(consulta)

	byte = mydoc['lastByteRead'] 					#get from db the last byte read
	print(byte)

	updateDBDateTimeInit(consulta,coLogs) 			#update time in db to modify the file

	#####comienzo la modificacion del archivo y las inserciones en la bd#########
	with open(path, 'r') as f:
		cole= 'alertas'											#cole collection in mongodb
		alertas = conectToDB(cole)
		fileSize = len(f.read())
		f.seek(byte) 											#seek at last byte read	
		lastByteRead = f.tell()									#save the number of last byte read
		consulta= {"fileName": path}
		mydoc = coLogs.find(consulta)
		while fileSize >lastByteRead :
			content = f.readline() 								#read one line
			readJson = json.loads(content) 						#convert to json dictionary
			alertas.insert_one(readJson).inserted_id 			#Insert new file in mongo	
			lastByteRead = f.tell()								#save the number of last byte read
			print(lastByteRead)
			updateDBByteRead(consulta,coLogs, lastByteRead)
			updateDBDateTimeEnd(consulta,coLogs)



#---------------------------PROGRAMA PRINCIPAL-----------------#
if __name__ == '__main__':
	if len(sys.argv) == 2:
		#creo el controlador de eventos
		patterns = "*.json" # archivos que queremos manejar (json para insertar en bd y log snort para convertir a json)
		ignore_patterns = ""
		ignore_directories = True
		case_sensitive = True
		manejador = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)
		
		#se invocan estas funciones cuando se genera el evento correspondiente
		manejador.on_created = on_created
		manejador.on_modified = on_modified

		#creamos el observador
		path = sys.argv[1]
		recursivo = True
		monitor = Observer()
		monitor.schedule(manejador, path, recursive=recursivo)

		#iniciamos el monitoreo
		monitor.start()
		try:
			while True:
				time.sleep(1)
		except KeyboardInterrupt:
			monitor.stop()
			monitor.join()
	else:
		print ("Use: [insertJson.py] [path logs snort]")


	#Structure of the colection LogsSnort on mongo:
	#
	#	{	"_id" : ObjectId('.......'),
	#		"fileName": "path/file.json", 	
	#		"lastByteRead" : "field update last byte read", 
	#		"updateInit" : "field update last update started",
	#		"updateEnd" : "field update last update finished"
	#	}

	#Structure of the colection alertas on mongo:
	#
	# {"_id" : ObjectId('.......'),
	#  "type": "event", 
  #  "event": {
  #						"impact": 0, 
  #						"generator-id": 129, 
  #						"protocol": 6, 
  #						"dport-icode": 1632, 
  #						"signature-revision": 2, 
  #						"classification-id": 3, 
  #						"signature-id": 12, 
  #						"sensor-id": 0, 
  #						"impact-flag": 0, 
  #						"sport-itype": 102, 
  #						"priority": 2, 
  #						"event-second": 1246619960, 
  #						"pad2": null, 
  #						"destination-ip": "192.168.178.32", 
  #						"event-id": 1, 
  #						"mpls-label": null, 
  #						"vlan-id": null, 
  #						"source-ip": "192.168.178.230", 
  #						"event-microsecond": 753493, 
  #						"blocked": 0}
  # }
  # {	_id : ObjectId('.......'),
	# "type": "packet", 
  # "packet": {
  #						"packet-second": 1408529136, 
  #						"linktype": 1, 
  #						"sensor-id": 0, 
  #						"packet-microsecond": 979838, 
  #						"event-second": 1408529136, 
  #						"length": 111, 
  #						"data": "......paquete....", 
  #						"event-id": 13}
  # }
