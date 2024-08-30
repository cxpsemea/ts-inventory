
import os
import csv
from datetime import datetime
from config import config
from cxloghandler import cxlogger
from baserunner import baserunner
from sastcache import sastcachetype


# CSV output files
OUT_REPOSITORIES        = 'sast_repositories.csv'

# CSV file headers
CSV_REPOSITORIES        = ['ID', 'NAME', 'DUPLICATED', 'CREATED', 'TEAM-ID', 'TEAM-NAME', 'REPOSITORY-TYPE', 'REPOSITORY-NAME', 'REPOSITORY-BRANCH', 'INFO']


class sastrepositories(baserunner) :

    def __init__(self):
        # Well known file for csv containing queries
        self.__reposhandler = None
        self.__reposwriter = None
        super().__init__


    def __init__(self, config: config, conn = None, caches = None, verbose = None, csvseparator = None) :
        # Well known file for csv containing queries
        self.__reposhandler = None
        self.__reposwriter = None
        super().__init__(config, conn, caches, verbose, csvseparator)    


    def preparedatafiles(self) :
        try :
            filename = self.datapath() + os.sep + OUT_REPOSITORIES
            if os.path.exists(filename) :
                os.remove(filename)
            self.__reposhandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__reposwriter = csv.writer(self.__reposhandler, delimiter = self.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__reposwriter.writerow(CSV_REPOSITORIES)
            return True
        except Exception as e:
            cxlogger.verbose( 'Unable to create output files with "' + str(e) + '"', True, False, True, e )    
            self.closedatafiles()
            return False


    def closedatafiles(self) :
        if (self.__reposhandler):
            self.__reposhandler.close()
            
            
    def extract_project_repositories(self) :
        cachedata = self.cacheoneof( [sastcachetype.projectsfull, sastcachetype.projectssimple, sastcachetype.projectstiny ] )
        errorcount = 0
        projcount = 0
        inventory_name = 'project repositories'
        dtini = datetime.now()
        cxlogger.verbose( '  - Processing ' + inventory_name )
        
        try :
            for item in cachedata :
                projcount += 1
                if (projcount % 100) == 0 :
                    cxlogger.verbose('  - Processed ' + inventory_name + ' (' + str(projcount) + ')', False )    
                    
                # Resolve duplicates project name
                pduplicated = None
                if next( filter( lambda el: el['id'] != item['id'] and el['name'].upper() == item['name'].upper(), cachedata), None ) :
                    pduplicated = True
                    
                reponame    = None
                repobranch  = None
                repoinfo    = None                  
                    
                # Resolve repository information
                auxdata = self.conn.sast.get( '/cxrestapi/projects/' + str(item['id']) )
                repotype = auxdata['sourceSettingsLink']['type']
                
                # Pre-scan action
                if repotype == 'custom' :
                    repodata    = self.conn.sast.get('/cxrestapi' + auxdata['sourceSettingsLink']['uri'])
                    reponame    = repodata['pullingCommandId']
                    repoinfo    = 'Pre-scan action'
                # Shared folder
                elif repotype == 'shared' :
                    repodata    = self.conn.sast.get('/cxrestapi' + auxdata['sourceSettingsLink']['uri'])
                    if len(repodata['paths']) > 0 :
                        reponame    = repodata['paths'][0]
                    repoinfo    = 'Shared folder'
                elif repotype != 'local' :
                    repodata = self.conn.sast.get('/cxrestapi' + auxdata['sourceSettingsLink']['uri'])
                    if 'uri' in repodata :
                        reponame = repodata['uri']['absoluteUrl']
                        repoinfo = 'Port: ' + str(repodata['uri']['port'])
                    elif 'url' in repodata :
                        reponame    = repodata['url']    
                    if 'branch' in repodata :
                        repobranch  = str(repodata['branch']).replace('/refs/heads/', '')
                    
                self.__reposwriter.writerow( [
                    item['id'], 
                    item['name'], 
                    pduplicated,
                    item['createdDate'],
                    item['teamId'],
                    item['teamFullName'],
                    repotype,
                    reponame,
                    repobranch,
                    repoinfo
                ] )

            # Close
            cxlogger.verbose('  - Processed ' + inventory_name + ' (' + str(len(cachedata)) + ') ' + self.duration(dtini, True), False )
        except Exception as e:
            errorcount += 1
            cxlogger.verbose( '  - Processing ' + inventory_name + ' failed with "' + str(e) + '"', True, False, True, e )
        return errorcount        
            
            
    def execute(self) :
        errorcount = 0
        dtini = datetime.now()
        # Prepare the data files
        if not self.preparedatafiles() :
            exit(1)
        try :
            cxlogger.verbose( '============================================================' )
            cxlogger.verbose( 'Extracting repositories from SAST' )            
            cxlogger.verbose( 'Extraction started: ' + datetime.now().strftime('%d-%m-%Y %H:%M:%S') )
            cxlogger.verbose( '------------------------------------------------------------' )
            cxlogger.verbose( 'Processing sast project repositories')    
            # Project repositories
            errorcount += self.extract_project_repositories() if errorcount == 0 else 0
            # Done
            cxlogger.verbose( 'Sast project repositories processed' )
        finally :
            dtend = datetime.now()
            cxlogger.verbose( '------------------------------------------------------------' )
            cxlogger.verbose( 'Extraction ended: ' + dtend.strftime('%d-%m-%Y %H:%M:%S') )
            cxlogger.verbose( 'Total duration: ' + self.duration(dtini, False) )
            if errorcount > 0 :
                cxlogger.verbose( str(errorcount) + ' errors were found.' )    
            self.closedatafiles()
            