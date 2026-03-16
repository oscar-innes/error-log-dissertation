# -*- coding: utf-8 -*-
#type: ignore
import jarray
from java.io import File, FileOutputStream
import subprocess
from javax.xml.parsers import DocumentBuilderFactory
from org.w3c.dom import Node
import json
from java.lang import ProcessBuilder
import inspect
import os
from java.util import ArrayList
import csv
from java.lang import ProcessBuilder
import io
from java.io import File
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.autopsy.coreutils import Logger


from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter, IngestModule, DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleReferenceCounter
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModule, DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter, IngestMessage, IngestServices
from org.sleuthkit.datamodel import SleuthkitCase, AbstractFile

from org.sleuthkit.autopsy.ingest import IngestModule, IngestServices, ModuleDataEvent
from org.sleuthkit.datamodel import BlackboardArtifact, BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.datamodel import BlackboardAttribute

from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule import Case

# For accessing the SleuthKit Case and content
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import FileManager

from xml.etree import ElementTree as ET
from org.sleuthkit.autopsy.coreutils import Logger
from java.util.logging import Level
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.autopsy.ingest import IngestServices, IngestMessage
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.coreutils import Logger


class ErrorFactory(IngestModuleFactoryAdapter):
    moduleName = "Error log analyser"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Reads, collects and analyses error logs"

    def getModuleVersionNumber(self):
        return "BETA"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return Error_log_collection()
    

class Error_log_collection(DataSourceIngestModule):
    moduleName = ErrorFactory.moduleName
    _logger = Logger.getLogger(ErrorFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], str(msg))

    def __init__(self):
        self.context = None

    def startUp(self, context):
        self.context = context
        self.log(Level.INFO, "Error log module starting...")



    def process(self, dataSource, progressBar):
        self.log(Level.INFO, "Starting datasource processing")
        progressBar.switchToIndeterminate()

        if PlatformUtil.isWindowsOS():
            progressBar.switchToDeterminate(4)
            files = []
            fileobserver = Case.getCurrentCase().getServices().getFileManager()
            files = fileobserver.findFiles(dataSource, "%.evtx")
            board = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
            try:
                evtx_detail = board.getOrAddArtifactType(
                "DETAIL_EVTX_ERRORS", 
                "Error Log analyser"
                )
           
                try: attr_time_type = board.getOrAddAttributeType(
                    "ERROR_TIME",
                    BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                    "Event Time"
                )
                except Exception as e: self.log(Level.SEVERE, "ERROR_TIME attribute failure: " + str(e))
                try: atr_compname = board.getOrAddAttributeType("ERROR_PC", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Computer Name")
                except Exception as e: self.log(Level.SEVERE, "Could not find computer name! " + str(e))
                try: atr_username = board.getOrAddAttributeType("ERROR_USER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Username")
                except Exception as e: self.log(Level.SEVERE, "Could not find user who executed activity! " + str(e))
                try: atr_sid = board.getOrAddAttributeType("ERROR_SID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Security Identifier")
                except Exception as e: self.log(Level.SEVERE, "Could not find user SID! " + str(e))
                try: atr_ename = board.getOrAddAttributeType("ERROR_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "EventName")
                except Exception as e: self.log(Level.SEVERE, "Could not find any EventName with associated event! " + str(e))
                try: atr_channel = board.getOrAddAttributeType("ERROR_EVENT_CHANNEL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Channel")
                except Exception as e: self.log(Level.SEVERE, "Could not find error log file this log was extracted from! " + str(e))
                try: atr_indication = board.getOrAddAttributeType("ERROR_ANALYSIS_OUTCOME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Analysis")
                except Exception as e: self.log(Level.SEVERE, "Did not find analysis built in! " + str(e))
                try: atr_ttp = board.getOrAddAttributeType("ERROR_TTP", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "TTP")
                except Exception as e: self.log(Level.SEVERE, "Did not find TTP built in! " + str(e))
                try: atr_provider = board.getOrAddAttributeType("ERROR_PROVIDER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Provider")
                except Exception as e: self.log(Level.SEVERE, "Did not find provider value! " + str(e))
                try: atr_pid = board.getOrAddAttributeType("ERROR_PROCESS_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Linked Process ID")
                except Exception as e: self.log(Level.SEVERE, "Could not find proc ID with associated event! " + str(e))
                try: atr_id = board.getOrAddAttributeType("ERROR_WIN_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Windows Event ID")
                except Exception as e: self.log(Level.SEVERE, "Could not find event ID with associated event! " + str(e))
                try: atr_source = board.getOrAddAttributeType("ERROR_CAUSE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Source")
                except Exception as e: self.log(Level.SEVERE, "Could not find event source with associated event! " + str(e))
                try: atr_domain = board.getOrAddAttributeType("ERROR_DOMAIN", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Domain Name")
                except Exception as e: self.log(Level.SEVERE, "Could not find domain name with associated event! " + str(e))
                try: atr_errortext = board.getOrAddAttributeType("ERROR_ITEMS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Additional error text")
                except Exception as e: self.log(Level.SEVERE, "Could not find any EventData with associated event! " + str(e))
            except Exception as e:
                self.log(Level.SEVERE, "Error creating artifact types! " + str(e))
                self.log(Level.SEVERE, "Could not create artifact type")  
            IngestServices.getInstance().postMessage(IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Error_log_collection", "New artifact created wowza" ))
            progressBar.switchToDeterminate(4)
            progressBar.progress(1)
            fileset = []
            fileobserver = Case.getCurrentCase().getServices().getFileManager()
            fileset = fileobserver.findFiles(dataSource, "%.evtx")
            self.log(Level.INFO, "found Event Log log files")
            temp_csv = Case.getCurrentCase().getTempDirectory()
            temp_work = os.path.join(temp_csv, "FullErrorLogs")
            try: os.makedirs(temp_work)
            except: self.log(Level.INFO, "Event Log temporary directory exists already on this case" + temp_work)
            for f in fileset:
                if not os.path.exists(temp_work):
                    self.log(Level.SEVERE, "EVTX extraction failed: " + temp_work)
                    raise
                if self.context.isJobCancelled(): return IngestModule.ProcessResult.OK
                outer = os.path.join(temp_work, f.getName())
                ContentUtils.writeToFile(f, File(outer))
            exe_path = os.path.join(os.path.dirname(__file__), "Conversion.exe")
            exit_code = subprocess.call([exe_path, "-f", str(temp_work), "-o", str(temp_work)])
            progressBar.progress(2)
            for item in os.listdir(temp_work):
                if item.endswith(".csv"):
                    self.log(Level.INFO, "found a csv!")
                    file_path = os.path.join(temp_work, item)
                    artifacts = ArrayList()
                    artcount = 0
                    for row in csv.DictReader(open(str(file_path))):
                        self.log(Level.INFO, str(file_path))
                        self.log(Level.INFO, row)
                        event_id = row["EventID"]
                        channel = row["Channel"]
                        computer = row["Computer"]
                        name = row["Provider_EventSourceName"]
                        provider = row["Provider_Name"]
                        domain = row["SubjectDomainName"]
                        user = row["SubjectUserName"]
                        time = row["TimeCreated_SystemTime"]
                        pid = row["ProcessID"]
                        sid = row["UserID"]
                        source = str(file_path)
                        eventhorizon = row["EventData"]
                        errortext = ""
                        ttp = ""
                        self.log(Level.INFO, row)
                        #analysis would kind of start here (maybe call a seperate python file)? -- analysing patterns needs to be figured out (because we have no logic for that yet) but for now we just want to output all the logs -- and any quick wins we know to be malicious.
                        # We would only want to post errors that we find as interesting (and useful in cases but for now we post all just to show it working)

                        if provider == "Microsoft-Windows-CodeIntegrity/Operational" and event_id == "3001":
                            errortext = "Unsigned driver was blocked from loading/wasattempted to be loaded"
                            ttp = "T1068  - Exploitation for Privilege Escalation (malicious driver)"

                        if provider == "Microsoft-Windows-Windows Defender" and event_id == "5001":
                            errortext = "Windows Defender Antivirus Service stopped unexpectedly"
                            ttp = "T1489 - Service Stop"

                        if provider == "Microsoft-Windows-Windows Defender" and event_id == "5010":
                            errortext = "Windows Defender scanning has been disabled"
                            ttp = "T1562.001 - Impair Defenses: Disable or Modify Tools"

                        newfact = dataSource.newArtifact(evtx_detail.getTypeID())
                        newfact.addAttributes([
                                (BlackboardAttribute(attr_time_type, Error_log_collection.moduleName, str(time))), 
                                (BlackboardAttribute(atr_channel, Error_log_collection.moduleName, str(channel))),
                                (BlackboardAttribute(atr_provider, Error_log_collection.moduleName, str(provider))), 
                                (BlackboardAttribute(atr_id, Error_log_collection.moduleName, str(event_id))), 
                                (BlackboardAttribute(atr_username, Error_log_collection.moduleName, str(user))), 
                                (BlackboardAttribute(atr_domain, Error_log_collection.moduleName, str(domain))), 
                                (BlackboardAttribute(atr_pid, Error_log_collection.moduleName, str(pid))), 
                                (BlackboardAttribute(atr_ename, Error_log_collection.moduleName, str(name)) ), 
                                (BlackboardAttribute(atr_errortext, Error_log_collection.moduleName, str(eventhorizon))), 
                                (BlackboardAttribute(atr_source, Error_log_collection.moduleName, str(source))), 
                                (BlackboardAttribute(atr_compname, Error_log_collection.moduleName, str(computer))), 
                                (BlackboardAttribute(atr_sid, Error_log_collection.moduleName, str(sid))), 
                                (BlackboardAttribute(atr_indication, Error_log_collection.moduleName, str(errortext))),
                                (BlackboardAttribute(atr_ttp, Error_log_collection.moduleName, str(ttp)))
                                ])
                            
                        self.log(Level.INFO, "newfact did coagulate")
                        artifacts.add(newfact)
                        
                        try: board.postArtifact(newfact, Error_log_collection.moduleName)
                        except Blackboard.BlackboardException as e:  self.log(Level.SEVERE, "Error in posting artifact "+ newfact.getDisplayName())   
                        progressBar.progress(3)  
                    artifacts.clear()           
                else:
                    self.log(Level.INFO, "badfinding, not a csv file")
                    continue
        else:
           self.log(Level.WARNING, "Case is NOT windows logs")
        progressBar.progress(4)
        IngestServices.getInstance().postMessage(IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Error_log_collection", "Error logs collected successfully" ))
                    
                   

                
          
               





    

