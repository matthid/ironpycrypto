"""Recursively delete all .pyc and .pyo files staring at current directory""" 
import os 
import sys 
 
doit = True
 
def main():
    topdir = os.getcwd()
    cleandir(topdir) 
 
def cleandir(dir): 
    os.path.walk(dir, walker, None) 
 
def walker(dummy, top, names): 
    global doit
    for name in names:
        if name[-4:] in ('.pyc', '.pyo'): 
            path = os.path.join(top, name) 
            print 'cleaning ', path 
            if doit: 
                os.unlink(path) 
 
if __name__ == '__main__': 
    main() 