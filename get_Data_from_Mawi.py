# -*- coding: utf-8 -*-
"""
Created on Tue Apr  9 10:01:23 2019

@author: Davide
"""

# =============================================================================
#                   DOWNLOADING .pcapFile from MAWI Lab
# =============================================================================

## Writing a script able to download from the Mawi dataset the tracks relative to our analysis

## This is the link: http://mawi.wide.ad.jp/mawi/samplepoint-F/2019/

## We will focus our attention oh the dataset about samplepoint-F during 2019

## Libraries
import sys
from subprocess import call

#This library is used to copy the file
from shutil import copy

#On the command line we can specify the precise date for which we download data
print ("You are working with this script:  ", sys.argv[0])

#First example of Downloading, here we decide to work during the period of March 
#and the last 
#thursday of February and April
#date = ["0228", "0307", "0314", "0328", "0404"]

#New date related to the period during 1 week of March used for the Thesis
#date = ["0308", "0309", "0310", "0311", "0312", "0313", "0314"]

#New date related to the period during 1 week of Mondays 
#date = ["0321", "0328", "0404", "0411", "0418"]

#New date related to the period during another month: April 
date = ["0521", "0528"]

# The first command download the pcap file zipped and the second is used to unzip it

#call(['wget', '-c', 'http://mawi.nezu.wide.ad.jp/mawi/samplepoint-F/2019/201903211400.pcap.gz'])
#call(['gunzip', 'http://mawi.nezu.wide.ad.jp/mawi/samplepoint-F/2019/201903211400.pcap.gz'])

link = ["http://mawi.nezu.wide.ad.jp/mawi/samplepoint-F/2019/2019" + elem + "1400.pcap.gz" for elem in date] 

number_link = int(sys.argv[1])

file = link[number_link]

print("I'm working on:  " + file)
print()
call(['wget', '-c', file])

print("I have finished the Download for: " + file)
print()
unzip_file = file.split("/")[-1]

print("I'm opening on:  " + unzip_file)
print()
call(['gunzip', unzip_file])

print("I have opened  :  " + unzip_file)

print()
print("I have downloaded all !!!!")
cp_file = unzip_file[:-3]

print()
print("Now we copy the file into the directory of data")
copy(cp_file, "./data2019")

print()
print(" Finish !!! ")