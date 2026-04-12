#!python2
import datetime
from logging import root
from pathlib import Path
import string
import os
import struct
import sys
from Evtx.Evtx import Evtx
from Evtx.BinaryParser import OverrunBufferException
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
            lognme = os.path.splitext(file)[0]
            pathing = os.path.join(path, file)
            log = os.path.splitext(file)[0]
            csv_path = os.path.join(
                args.output     ,
                os.path.splitext(file)[0] + ".csv")
            with Evtx(pathing) as logset:  
                for log_record in logset.records():
                        try:
                            xml = log_record.xml()
                        except (struct.error, KeyError, UnicodeDecodeError, OverrunBufferException, Exception) as e:
                            continue
                        soup = BeautifulSoup(xml, "xml")
                        rowdata = {
                                "EventID": find_text(soup, "System", "EventID"),
                                "Computer": find_text(soup, "System", "Computer"),
                                "Provider": find_text(soup, "System", "Provider", nested="Name"),
                                "Level": find_text(soup, "System", "Level"),
                                "Channel": find_text(soup, "System", "Channel"),
                                "ProcessID": find_text(soup, "System", "Execution", nested="ProcessID"),
                                "Provider_Name": find_text(soup, "System", "Provider", nested="Name"),
                                "SubjectDomainName": find_text(soup, "System", "Security", nested="SubjectDomainName"),
                                "SubjectUserName": find_text(soup, "System", "Security", nested="SubjectUserName"),
                                "TimeCreated_SystemTime": find_text(soup, "System", "TimeCreated", nested="SystemTime"),
                                "UserID": find_text(soup, "System", "Security",  nested="UserID"),
                                "Security_UserID": find_text(soup, "System", "Execution", nested="UserID"),
                                "Keywords": find_text(soup, "System", "Keywords"),
                                "Opcode": find_text(soup, "System", "Opcode"),
                                "EventRecordID": find_text(soup, "System", "EventRecordID"),
                                "Execution_ThreadID": find_text(soup, "System", "Execution", nested="ThreadID"),
                                "EventName": find_text(soup, "System", "EventName") or find_text(soup, "System", "AppName")
                        }
                        event_data_tag = soup.find("EventData")
                        if event_data_tag:
                            for data_tag in event_data_tag.find_all("Data"):
                                name = data_tag.get("Name")
                                if name:
                                    rowdata["ED_" + name] = data_tag.get_text(strip=True)
                                else:
                                    existing = [k for k in rowdata if k.startswith("ED_Unnamed")]
                                    rowdata["ED_Unnamed_{}".format(len(existing))] = data_tag.get_text(strip=True)
                        user_data_tag = soup.find("UserData")
                        if user_data_tag:
                            for child in user_data_tag.find_all(True): 
                                if child.get_text(strip=True) and not child.find(True):  
                                    rowdata["UD_" + child.name] = child.get_text(strip=True)
                        eventdata = soup.find(lambda t: t.name.endswith("EventData"))
                        rows.append(rowdata)

            all_keys = []
            seen = set()
            for row in rows:
                for k in row.keys():
                    if k not in seen:
                        all_keys.append(k)
                        seen.add(k)
            with open(Path(csv_path), "w", newline="", encoding="utf-8") as csv1:
                writer = csv.DictWriter(csv1, fieldnames=all_keys, extrasaction="ignore")
                writer.writeheader() 
                for row in rows:
                    writer.writerow(row)
            rows.clear()                               
