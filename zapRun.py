import os

os.system("python ZAP_automation/zapInstallation.py --zap i")
os.system("python ZAP_automation/ZAP_manual.py")
os.system("python ZAP_autonation/ZAP_ActiveScan.py")
os.system("python ZAP_autonation/generateReports.py")
os.system("python ZAP_automation/zapInstallation.py --zap r")