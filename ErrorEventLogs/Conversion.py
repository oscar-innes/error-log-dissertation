#!python2
from logging import root
from pathlib import Path
import string
import os
from Evtx.Evtx import Evtx
import argparse
from numpy import record
import pandas as pd
import json
from pandasql import sqldf
from bs4 import BeautifulSoup
import csv
import xml.etree.ElementTree as ET

def find_text(text, *tags, nested=None):
    finder = text
    for tag in tags:
        if finder is None:
            return ""
        finder = finder.find(lambda t: t.name.endswith(tag))
    
    if finder is None:
        return ""
    
    return finder.get(nested, "") if nested else finder.get_text(strip=True)

if __name__ == "__main__":
    setup_msg = "Error Event Log Extraction and Analysis Tool"
    args = argparse.ArgumentParser(description=setup_msg, formatter_class=argparse.RawTextHelpFormatter)
    args.add_argument('-f', '--file', type=str, required=True, help="Evtx Folder")
    args.add_argument('-o', '--output', type=str, required=True, help="temp storage")
    args = args.parse_args()
    eventlog_space = args.file
    rows = []
    for path, subdirs, files in os.walk(eventlog_space):
        for file in files:
            if not file.endswith('.evtx'):
                continue
            pathing = os.path.join(path, file)
            log = os.path.splitext(file)[0]
            csv_path = os.path.join(
                args.output     ,
                os.path.splitext(file)[0] + ".csv")
            fields = [
            "EventID", "Channel", "Computer", "EventName", "Provider_Name", "SubjectDomainName", "Execution_ThreadID", "Provider_EventSourceName",
            "SubjectUserName", "TimeCreated_SystemTime", "ProcessID", "UserID", "EventData", "Security_UserID", "Keywords", "EventRecordID"]  
            with Evtx(pathing) as logset:  
                for log_record in logset.records():
                        try:
                            xml = log_record.xml()
                        except UnicodeDecodeError:
                            # skip corrupt record -- maybe in future we do stuff to handle corruption?
                            continue
                        soup = BeautifulSoup(xml, "xml")
                        provide = find_text(soup, "System", "Provider", nested="Name")
                        level = find_text(soup, "System", "Level")
                        if level and level == "2" or provide.lower() == "Windows Error Reporting".lower():
                            rowdata = {
                                "EventID": find_text(soup, "System", "EventID"),
                                "Computer": find_text(soup, "System", "Computer"),
                                "Channel": find_text(soup, "System", "Channel"),
                                "ProcessID": find_text(soup, "System", "Execution", nested="ProcessID"),
                                "Provider_Name": find_text(soup, "System", "Provider", nested="Name"),
                                "SubjectDomainName": find_text(soup, "System", "Security", nested="SubjectDomainName"),
                                "SubjectUserName": find_text(soup, "System", "Security", nested="SubjectUserName"),
                                "TimeCreated_SystemTime": find_text(soup, "System", "TimeCreated", nested="SystemTime"),
                                "UserID": find_text(soup, "System", "Security",  nested="UserID"),
                                "Security_UserID": find_text(soup, "System", "Execution", nested="UserID"),
                                "Keywords": find_text(soup, "System", "Keywords"),
                                "EventRecordID": find_text(soup, "System", "EventRecordID"),
                                "Execution_ThreadID": find_text(soup, "System", "Execution", nested="ThreadID"),
                                "Provider_EventSourceName": find_text(soup, "System", "Provider", nested="Name"),
                                "EventName": find_text(soup, "System", "EventName") or find_text(soup, "System", "AppName")
                            }
                            eventdata = soup.find(lambda t: t.name.endswith("EventData"))
                            if eventdata:
                                event_data = {}
                                for data in eventdata.find_all(lambda t: t.name.endswith("Data")):
                                    name = data.get("Name")
                                    value = data.get_text(strip=True)
                                    event_data[name] = value
                                rowdata["EventData"] = json.dumps(event_data)
                            else:
                                rowdata["EventData"] = ""
                            rows.append(rowdata)
                        else:
                            continue
            with open(Path(csv_path), "w", newline="", encoding="utf-8") as csv1:
                writer = csv.DictWriter(csv1, fieldnames=fields)
                writer.writeheader() 
                for row in rows:
                    writer.writerow(row)
            rows.clear()                               

                        

                    


