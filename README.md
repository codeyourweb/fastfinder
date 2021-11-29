[![Project Status](https://img.shields.io/badge/status-BETA-yellow?style=flat-square)]()
# _FastFinder_ - Incident Response - Fast suspicious file finder

## What is this project designed for?
_FastFinder_ is a lightweight tool made for threat hunting, live forensics and triage on Windows Platform. It is 
focused on enpoint enumeration and suspicious file finding based on various criterias:
* file path / name;
* simple string content match
* complex content condition(s) based on YARA

### Installation 
Compiled release of this software are available. If you want to compile 
from sources, it could be a little bit tricky cause it's stronly depends of 
_go-yara_ and CGO compilation. Anyway, you'll find a detailed documentation [here](README.windows-compilation.md)

### Usage 
```
fastfinder [-h|--help] -c|--string "<value>"

Arguments:

  -h  --help    Print help information
  -c  --configuration  fastfind configuration file
``` 

Depending on where you are looking for files, _FastFinder_ could be used with admin OR simple user rights. 

### Scan and export file match according to your needs
a configuration file example is available [here](configuration.yaml.example) in this repository
``` 
input:
    path: [] # match file path AND / OR file name based on simple string ('?' and '*' wildcards are available for simple string) OR regular expression (regex have to be enclosed by "/<regex>/")
    content:
        grep: [] # match literal string value inside file contente
        yara: [] # use yara rule and specify rules path(s) for more complex pattern search (wildcards / regex / conditions) 
options:
    findInHardDrives: true	# enumerate hard drive content
    findInRemovableDrives: true # enumerate removable drive content 
    findInNetworkDrives: true # enumerate network drive content
output:
    base64Files: true # base64 matched content before copy
    filesCopyPath: '' # empty value will copy matched files in the fastfinder.exe folder
``` 

## About this project and future versions
I initially created this project to automate the creation of fastfind on a wide computer network. 
It fulfills the needs I have today, nevertheless if you have complementary ideas, do not hesitate 
to ask for, I will see to implement them if they can be useful for everyone.
On the other hand, pull request will be studied carefully.
