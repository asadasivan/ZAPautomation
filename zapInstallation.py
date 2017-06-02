#!/usr/bin/python
import os
import sys
import argparse


'''
Install zap
'''
class zapInstallation:

	def __init__(self, directory="/home/arun/", zapVersion="2.6.0"):
		self.directory = directory
		self.zapVersion = zapVersion

	def zapInstall(self):
		os.system("wget - https://github.com/zaproxy/zaproxy/releases/download/%s/ZAP_%s_Linux.tar.gz"%(self.zapVersion, self.zapVersion))
		os.system("tar zxf ZAP_%s_Linux.tar.gz -C %s"%(self.zapVersion, self.directory))
		os.system("ln -s %sZAP_%s %szap"%(self.directory, self.zapVersion, self.directory))

	def removeZap(self):
		os.system("rm -rf %sZAP_%s"%(self.directory,self.zapVersion))
		os.system("rm -rf %szap"%self.directory)
		os.system("rm -rf ZAP_%s_Linux.tar.gz"%self.zapVersion)
		os.system("rm -rf .ZAP")
	
	



if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='install or remove zap')
	parser.add_argument('--zap', type=str, default="n",
	                   help='install zap')
	args = parser.parse_args()

	zap_installation = zapInstallation()

	if args.zap == "i":
		zap_installation.zapInstall()
	elif args.zap == "r":
		zap_installation.removeZap()
	else:
		print "please enter an option --zap i for install or --zap r for remove"
