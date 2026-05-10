# -*- coding: utf-8 -*-
#type:ignore
import jarray
import re
from java.io import File, FileOutputStream
import subprocess
from javax.xml.parsers import DocumentBuilderFactory
from org.w3c.dom import Node
import json
import re
from java.lang import ProcessBuilder
import inspect
import os
from java.util import ArrayList
from java.text import SimpleDateFormat
from java.util import Date
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import Score

import csv
from java.lang import ProcessBuilder
import io
from java.io import File
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.datamodel import BlackboardAttribute  # lot of autopsy imports
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
from java.text import SimpleDateFormat
from java.util import Date
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
import os
import json
from datetime import datetime, timedelta

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
from collections import defaultdict


def clean_float(val):
    try:
        if isinstance(val, str) and val.startswith('0x'):  # some log values are in hex, we convert them to decimal for easier analysis and comparison in rules.
            return float(int(val, 16))
        return float(val)
    except (ValueError, TypeError):
        return 0.0 

Operations = {
    "eq":       lambda a, b: str(a).lower() == str(b).lower(),
    "contains": lambda a, b: str(b).lower() in str(a).lower(),
    "endswith": lambda a, b: str(a).lower().endswith(str(b).lower()),
    "regex":    lambda a, b: bool(re.search(b, str(a), re.I)),
    "in":       lambda found, count: str(found) in [str(x) for x in count],
    "not_in":       lambda found, count: str(found) not in [str(x) for x in count],
    "contains_any": lambda a, b: any(str(x).lower() in str(a).lower() for x in b),  # Operations for JSON rules
}

def get_unix_time(timing):
    try:
        timing = timing.strip().strip("'\"")
        if '+' in timing:
            timing = timing[:timing.index('+')]  #Processing and sorting timestamps for logs, quick way that I did this
        if timing.endswith('Z'):
            timing = timing[:-1]
        
        timing = timing.strip()
        
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):  #Remove some noensense from Windows timestamps.
            try:
                dated = datetime.strptime(timing, fmt)
                return (dated - datetime(1970, 1, 1)).total_seconds()
            except ValueError:
                continue
        raise ValueError("No format matched")
    except (ValueError, TypeError) as e:
        print("get_unix_time failed: " + str(e) + " input: " + repr(timing))
        return 0.0
    
def load_json_rules(module_dir):
    rules_list = []
    rule_set = os.path.join(module_dir, "rules")
    
    if not os.path.exists(rule_set):
        os.makedirs(rule_set)
        return rules_list

    for filename in os.listdir(rule_set):
        if filename.endswith(".json"):
            file_full_path = os.path.join(rule_set, filename)
            try:
                with open(file_full_path, 'r') as f:
                    rule_data = json.load(f)
                    if isinstance(rule_data, list):
                        rules_list.extend(rule_data)
                    else:
                        rules_list.append(rule_data)
            except Exception as e:
                print("Error loading rule {}: {}".format(filename, str(e)))
                
    return rules_list


def clean_str(val):
    if val is None:
        return ""
    if isinstance(val, unicode): # in Python 2, strings read from files may be unicode, so we decode them to UTF-8 for consistency. In Python 3, all strings are unicode by default, so we can skip decoding.
        u = val
    else:
        u = val.decode("utf-8", errors="replace")
    cleaned = re.sub(u'[\u200e\u200f\u200b\u202a-\u202e\ufeff]', u'', u)
    return cleaned.strip()


def evaluate_condition(block, row):
    if "logic" in block:
        logic_type = block.get("logic", "AND").upper()
        detections = block.get("detection", [])
        results = [evaluate_condition(value, row) for value in detections]  #check condition of each rule against an operation to decide to do with key-value JSON pair.
        if logic_type == "OR":
            return any(results)
        else:
            return all(results) 
    field = block.get("field")
    if not field:
        return False 
        
    actual = row.get(field, "")
    op = block.get("op")
    value = block.get("value")
    
    handler = Operations.get(op)
    if handler:
        try:
            return handler(actual, value)
        except Exception:
            return False
            
    return False

class ErrorFactory(IngestModuleFactoryAdapter):  #building outline of a module autopsy
    moduleName = "Autopsy EVTX analyser"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Reads, collects and analyses logs"

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
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], str(msg))  #logging setup

    def __init__(self):
        self.context = None

    def startUp(self, context):
        self.context = context
        self.log(Level.INFO, "Log analysis module starting...")


    def process(self, dataSource, progressBar):
        self.log(Level.INFO, "Starting datasource processing")
        progressBar.switchToIndeterminate()

        if PlatformUtil.isWindowsOS():  #Is the case Windows logs? If not, skip the module.
            progressBar.switchToDeterminate(4)
            files = []
            fileobserver = Case.getCurrentCase().getServices().getFileManager()
            files = fileobserver.findFiles(dataSource, "%.evtx") #find all evtx across disk image, even in non standard directories for them
            board = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
            try:
                evtx_detail = board.getOrAddArtifactType(
                "DETAIL_EVTX_ERRORS", 
                "Log analyser"
                )
           
                try: attr_time_type = board.getOrAddAttributeType(
                    "ERROR_TIME",
                    BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                    "Event Time"
                )
                except Exception as e: self.log(Level.SEVERE, "ERROR_TIME attribute failure: " + str(e))
                try: atr_indication = board.getOrAddAttributeType("ERROR_ANALYSIS_OUTCOME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Analysis")
                except Exception as e: self.log(Level.SEVERE, "Did not find analysis built in! " + str(e))
                try: atr_ttp = board.getOrAddAttributeType("ERROR_TTP", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "TTP")
                except Exception as e: self.log(Level.SEVERE, "Did not find TTP built in! " + str(e))
                try: atr_ttp = board.getOrAddAttributeType("ERROR_SEVERITY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Severity")
                except Exception as e: self.log(Level.SEVERE, "Did not find TTP built in! " + str(e))
                
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
            temp_csv = Case.getCurrentCase().getTempDirectory()  #Get the temp directory of the case -> this is where stuff will be sent to for analysis
            temp_work = os.path.join(temp_csv, "FullErrorLogs")
            try: os.makedirs(temp_work)
            except: self.log(Level.INFO, "Event Log temporary directory exists already on this case" + temp_work)
            for f in fileset:
                if not os.path.exists(temp_work):
                    self.log(Level.SEVERE, "EVTX extraction failed: " + temp_work)
                    raise
                if self.context.isJobCancelled(): return IngestModule.ProcessResult.OK
                outer = os.path.join(temp_work, f.getName())  # write event log content to CSVs in temp dir
                ContentUtils.writeToFile(f, File(outer))
            exe_path = os.path.join(os.path.dirname(__file__), "Conversion.exe") #workaround .exe
            subprocess.call([exe_path, "-f", str(temp_work), "-o", str(temp_work)])  # have to call a subprocess, evtx parsing requires python 3.0+ and autopsy's Jython is 2.7, so I made a separate script to do the conversion and call it from here, this is where the conversion.py file comes into play, it takes the evtx files, converts them to csv and adds some extra parsing and data extraction for the rules engine to use.
            progressBar.progress(2)
            module_dir = os.path.dirname(os.path.abspath(__file__))
            self.log(Level.INFO, "Loading JSON rules...")
            my_rules = load_json_rules(module_dir)
            self.log(Level.INFO, "Loaded {} rules.".format(len(my_rules)))  #now we have csvs load the rules
            for item in os.listdir(temp_work):
                if not item.endswith(".csv"): # we dont want to deal with original log files again.
                    self.log(Level.INFO, "skipping non-key log file: " + item)
                    continue
                if item.endswith(".csv"):
                    self.log(Level.INFO, "found a csv!")
                    file_path = os.path.join(temp_work, item)
                    all_rows = list(csv.DictReader(open(str(file_path))))
                    all_rows.sort(key=lambda x: get_unix_time(x.get("TimeCreated_SystemTime", "0")))  #Sort by timestamp, this is needed to ensure temporal event tracking works.
                    temporal_matches = defaultdict(list)
                    Sequential = {}  
                    for row in all_rows:
                        row_time = get_unix_time(row.get("TimeCreated_SystemTime", ""))  
                        for rule in my_rules:
                            ruler = rule.get('rule_title', 'Unknown Rule') # for every rule does this log line meet it?
                            if evaluate_condition(rule, row):  #What do we look for and how?
                                window_secs = rule.get('window_seconds')
                                required_count = rule.get('threshold')
                                sequence = rule.get('steps')
                                severity = rule.get('severity')
                                if window_secs and required_count and not sequence:
          
                                    temporal_matches[ruler].append(float(row_time))    # If the rule has a temporal component, we add the timestamp to a list of matches for that rule. We then check if the number of matches within the specified window meets the threshold for creating an artifact. 
                                    #This allows us to identify patterns of events that occur within a certain time frame, which can be indicative of specific TTPs or attack behaviors.
                                    self.log(Level.INFO, "appending: " + str(row_time) + " type: " + str(type(row_time)))

                                    temporal_matches[ruler].sort()
                                    temporal_matches[ruler] = [
                                        t for t in temporal_matches[ruler]  #Remove old timestamps outside the window, this allows us to track events that happen within a certain time of each other, even if they don't all happen at once.
                                        if (t - temporal_matches[ruler][0]) <= window_secs
                                    ]
                                    
                                       
                                    if len(temporal_matches[ruler]) >= required_count:
                                        newfact2 = dataSource.newArtifact(evtx_detail.getTypeID())
                                        self.log(Level.INFO, "cluster before convert: " + str(temporal_matches[ruler]))
                                        count = len(temporal_matches[ruler])
                                        epoch = datetime(1970, 1, 1)  # time in python is weird had to make this move a bit.
                                        first = (epoch + timedelta(seconds=temporal_matches[ruler][0])).strftime("%Y-%m-%d %H:%M:%S")
                                        last = (epoch + timedelta(seconds=temporal_matches[ruler][-1])).strftime("%Y-%m-%d %H:%M:%S")
                                        time_summary = "\n[!] TEMPORAL THRESHOLD MET\nTotal Occurrences: {}\nWindow: {}s\nFirst Seen: {}\nLast Seen: {}".format(
                                            count, window_secs, first, last
                                        )
                                        # if we've got a hit, post it.
                                        newfact2.addAttribute(BlackboardAttribute(atr_ttp, Error_log_collection.moduleName, str(ruler)))
                                        newfact2.addAttribute(BlackboardAttribute(atr_indication, Error_log_collection.moduleName, rule.get('description', "") + time_summary))
            
            
                                        for col_name, col_val in row.items():
                                            if col_val:
                                                if isinstance(col_val, unicode):
                                                    col_val = col_val.encode('utf-8', 'replace')
                                                clean_name = str(col_name).replace(" ", "_").replace(".", "_")
                                                attr_type = board.getOrAddAttributeType(clean_name, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, str(col_name))
                                                newfact2.addAttribute(BlackboardAttribute(attr_type, Error_log_collection.moduleName, str(col_val)))
            
                                            if severity == "critical" or severity == "high":
                                                important = BlackboardAttribute(
                                                    BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT.getTypeID(),
                                                    Error_log_collection.moduleName,
                                                    "SEVERITY: " + severity.upper()  # severity rating.
                                                )
                                                newfact2.addAttribute(important)
                                            board.postArtifact(newfact2, Error_log_collection.moduleName)
                                            last_time = temporal_matches[ruler][-1]
                                            temporal_matches[ruler] = [last_time]
                                        else:
                                            continue
                                elif sequence and window_secs and required_count: # if the rule has a sequence component, we track the progress of that sequence in a dictionary. Each step of the sequence is checked against the current log entry, and if it matches, we record the time and details of that step. We then check if the required steps of the sequence have been completed within the specified time window, and if so, we create an artifact with the details of the matched sequence. This allows us to identify complex patterns of events that occur in a specific order within a certain time frame, which can be indicative of multi-stage attack behaviors or TTPs.
                                    self.log(Level.INFO, "This rule is being checked correctly")
                                    if ruler not in Sequential:
                                        Sequential[ruler] = {}
                                    for step in sequence:
                                        step_num = step['step']
                                        step_results = []
                                        for c in step['detection']:
                                            actual = row.get(c['field'], "")
                                            handler = Operations.get(c['op'])  # use operation to determine hits across the different sequence steps
                                            if handler:
                                                step_results.append(handler(actual, c['value']))
                                        if step_results and all(step_results):
                                            Sequential[ruler][step_num] = {
                                                'time': float(row_time),  # calculate what row was hit when.
                                                'row': dict(row)
                                            }
                                            self.log(Level.INFO, "Sequence checker hits break instruction.")
                                            break
                                            
                                    if 1 in Sequential[ruler]:
                                        anchor_time = Sequential[ruler][1]['time']
                                        Sequential[ruler] = {
                                            k: v for k, v in Sequential[ruler].items()
                                            if (v['time'] - anchor_time) <= window_secs
                                        }
                                        self.log(Level.INFO, "This rule is being checked correvtly but part 2")
                                        required = set(s['step'] for s in sequence)
                                        found = set(Sequential[ruler].keys())
                                        if required.issubset(found):
                                            newfact3 = dataSource.newArtifact(evtx_detail.getTypeID())  # make a new artifact object to publish
                                            epoch = datetime(1970, 1, 1)
                                            entries = sorted(Sequential[ruler].items())

                                            for step_num, entry in entries:
                                                step_label = next(
                                                    (s.get('label', 'step_{}'.format(s['step']))
                                                    for s in sequence if s['step'] == step_num),
                                                    'step_{}'.format(step_num)
                                                )
                                                chain_note = "\n[!] TTP SEQUENCE MATCH — Step {}: {}\nPart of chain for: {}".format(
                                                    step_num, step_label, ruler
                                                )

                                   
                                                newfact3.addAttribute(BlackboardAttribute(
                                                    atr_ttp, Error_log_collection.moduleName, str(ruler)
                                                ))
                                                newfact3.addAttribute(BlackboardAttribute(
                                                    atr_indication, Error_log_collection.moduleName,  # add to the blackboard attributes for the artifact, including the rule description and details of the sequence match.
                                                    rule.get('description', '') + chain_note
                                                ))
                                                for col_name, col_val in entry['row'].items():
                                                    if col_val:
                                                        if isinstance(col_val, unicode):
                                                            col_val = col_val.encode('utf-8', 'replace')
                                                        clean_name = str(col_name).replace(" ", "_").replace(".", "_")
                                                        attr_type = board.getOrAddAttributeType(
                                                            clean_name,
                                                            BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                            str(col_name)
                                                        )

                                                    newfact3.addAttribute(BlackboardAttribute(
                                                        attr_type, Error_log_collection.moduleName, str(col_val)
                                                    ))
                                                if severity == "critical" or severity == "high":
                                                    important = BlackboardAttribute(
                                                        BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT.getTypeID(),
                                                        Error_log_collection.moduleName,
                                                        "SEVERITY: " + severity.upper()
                                                        )
                                                    newfact3.addAttribute(important)
                                                board.postArtifact(newfact3, Error_log_collection.moduleName)
                                                Sequential[ruler] = {}  
                                else: # if a standard standalone matching rule, we just create an artifact for that single log entry with the details of the match and the rule.
                                    newfact2 = dataSource.newArtifact(evtx_detail.getTypeID())
                                    newfact2.addAttribute(BlackboardAttribute(atr_ttp, Error_log_collection.moduleName, rule.get('rule_title', "")))
                                    newfact2.addAttribute(BlackboardAttribute(atr_indication, Error_log_collection.moduleName, rule.get('description', "")))  # what rule was hit and what was context - important for triage and understanding the finding.
                                    for col_name, col_val in row.items():
                                        if col_val:
                                            if isinstance(col_val, unicode):
                                                col_val = col_val.encode('utf-8', 'replace')
                                            clean_name = str(col_name).replace(" ", "_").replace(".", "_")
                                            attr_type = board.getOrAddAttributeType(clean_name, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, str(col_name))
                                            newfact2.addAttribute(BlackboardAttribute(attr_type, Error_log_collection.moduleName, str(col_val)))
                                    if severity == "critical" or severity == "high":
                                        important = BlackboardAttribute(
                                            BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT.getTypeID(),
                                            Error_log_collection.moduleName,
                                            "SEVERITY: " + severity.upper()
                                        )
                                        newfact2.addAttribute(important)
                                    board.postArtifact(newfact2, Error_log_collection.moduleName)

                else:
                    self.log(Level.INFO, "badfinding, not a csv file")
                    continue
            temporal_windows = []
            progressBar.progress(4) # progressbar tracks progress of the modules works for user experience.
            IngestServices.getInstance().postMessage(IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Error_log_collection", "Error logs collected successfully" ))
        else:
           self.log(Level.WARNING, "Case is NOT windows logs")
        
                    
                   

                
          
               





    

