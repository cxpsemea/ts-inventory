import csv
import json
import os
from http import HTTPStatus
from shared.package.clients.cxhttpclient import HTTPForbiddenException
from shared.package.clients.cxhttpclient import HTTPTimeout
from shared.package.clients.cxhttpclient import HTTPUnauthorizedException
from shared.package.common import cxutils
from shared.package.common.cxcaches import CxCaches
from shared.package.common.cxconfig import cxconfig
from shared.package.common.cxcsv import CxCsv
from shared.package.common.cxdatetime import CxDatetime
from shared.package.common.cxglobfilters import GlobFilters
from shared.package.common.cxlogging import DEBUG
from shared.package.common.cxlogging import cxlogger
from shared.package.common.cxparamfilters import CxParamFilters
from shared.package.cxsast.cxsasthttpclient import CxSastHttpClient
from shared.package.cxsast.cxsastsoapclient import CxSastSoapClient
from shared.package.cxsast.presets.sastdefaultpresets import sastdefaultpresets
from shared.package.cxsast.querycategories.sastdefaultcategories import sastdefaultcategories


# BOUNDARIES
SAST_MIN_VERSION: float = 9.7
MAX_LOC_VAL: int = 9500000
MAX_LOC_TXT: str = '9.5M'

# CONTENT SPLITTERS
SPLITTER: str = '|'
NOTESSPLITTER: str = ' | '

# STATUSES
SOK: int = 0
SWARNING: int = 1
SDANGER: int = 2
SFAILED: int = 3
STATUS: list[str] = ['OK', 'WARNING', 'DANGER', 'FAILED']

# PRESET TYPES AND PRESET QUERY STATUSES
PTYPE_OOB: str = 'Checkmarx'
PTYPE_CUSTOM: str = 'Customized'
QOK: int = 0
QADDED: int = 1
QMISSING: int = 2
QSTATUS: list[str] = ['MATCH', 'QUERY-ADDED', 'QUERY-REMOVED']
QSEVERITY: list[str] = ['Info', 'Low', 'Medium', 'High', 'Critical']

# HTTP RELATED EXCEPTIONS
SFORBIDDEN: str = 'Insufficient permissions to get this data'
SEXCEPTION: str = 'Failed to get this data'

# CACHE NAMES FOR DATA
CACHE_CONFIG: str = 'CACHE-CONFIG'
CACHE_TEAMS: str = 'CACHE-TEAMS'
CACHE_QUERIES: str = 'CACHE-QUERIES'
CACHE_PRESETS: str = 'CACHE-PRESETS'

# CACHE NAMES INTERNAL
CACHE_AC_PROVIDERS: str = 'CACHE-AC-PROVIDERS'
CACHE_AC_USERS: str = 'CACHE-AC-USERS'
CACHE_AC_TEAMS: str = 'CACHE-AC-TEAMS'
CACHE_ALL_QUERIES: str = 'CACHE-ALL-QUERIES'
CACHE_PROJ_NAMES: str = 'CACHE-PROJ-NAMES'
CACHE_PROJ_DUPLICATED: str = 'CACHE-PROJ-DUPLICATED'
CACHE_SCAN_ORIGINS: str = 'CACHE-SCAN-ORIGINS'
CACHE_COUNTERS: str = 'CACHE-COUNTERS'


# CONFIGURATION OUTPUT OBJECT TYPES
OBJ_SAST_INSTANCE: str = 'SAST-INSTANCE'
OBJ_ADD_ONS: str = 'ADD-ON-COMPONENTS'
OBJ_ENGINE_CONFIG: str = 'ENGINE-CONFIG'
OBJ_ENGINE_SERVER: str = 'ENGINE-SERVER'
OBJ_CUSTOM_FIELDS: str = 'CUSTOM-FIELD'
OBJ_SMTP_SETTINGS: str = 'SMTP-SETTINGS'
OBJ_ISSUE_TRACKER: str = 'ISSUE-TRACKER'
OBJ_SCAN_ACTIONS: str = 'SCAN-ACTIONS'
OBJ_PRE_SCAN_ACTION: str = 'PRE-SCAN-ACTION'
OBJ_POST_SCAN_ACTION: str = 'POST-SCAN-ACTION'
OBJ_RESULT_STATES: str = 'RESULT-STATE'
# ACCESS-CONTROL OUTPUT OBJECT TYPES
OBJ_AC_USERS: str = 'AC-USERS'
OBJ_AC_USERS_APP: str = 'AC-USERS-APPLICATION'
OBJ_AC_USERS_SAML: str = 'AC-USERS-SAML'
OBJ_AC_USERS_LDAP: str = 'AC-USERS-LDAP'
OBJ_AC_USERS_DOMAIN: str = 'AC-USERS-DOMAIN'
OBJ_AC_USERS_EMAILS: str = 'AC-USERS-EMAIL-DOMAINS'
OBJ_AC_TEAMS: str = 'AC-TEAMS'
OBJ_AC_ROLES: str = 'AC-ROLES'
OBJ_AC_SAML: str = 'AC-SAML-SETTINGS'
OBJ_AC_LDAP: str = 'AC-LDAP-SETTINGS'
OBJ_AC_DOMAIN: str = 'AC-DOMAIN-SETTINGS'
# PRESETS, QUERIES, CATEGORIES
OBJ_QUERIES: str = 'QUERIES'
OBJ_QUERIES_CORP: str = 'CUSTOM-QUERIES-CORP'
OBJ_QUERIES_TEAM: str = 'CUSTOM-QUERIES-TEAM'
OBJ_QUERIES_PROJ: str = 'CUSTOM-QUERIES-PROJ'
OBJ_PRESETS: str = 'PRESETS'
OBJ_QUERY_CATEGORIES: str = 'CUSTOM-QUERY-CATEGORIES'
OBJ_PROJECTS: str = 'PROJECTS'
# OTHER
OBJ_SCAN_ORIGINS: str = 'SCAN-ORIGINS'
OBJ_CONSTRAINTS: str = 'CONSTRAINTS'


# INVENTORY CSV OUTPUT FILES
OUT_SUMMARY: str = 'sast_inventorysummary.csv'
OUT_CONFIG: str = 'sast_inventoryconfigurations.csv'
OUT_ACUSERS: str = 'sast_inventoryusers.csv'
OUT_ACTEAMS: str = 'sast_inventoryteams.csv'
OUT_ACROLES: str = 'sast_inventoryroles.csv'
OUT_QUERIES: str = 'sast_inventoryqueries.csv'
OUT_PRESETS: str = 'sast_inventorypresets.csv'
OUT_PRESETQUERIES: str = 'sast_inventorypresetqueries.csv'
OUT_CATEGORIES: str = 'sast_inventorycustomcategories.csv'
OUT_PROJECTS: str = 'sast_inventoryprojects.csv'


# CSV FILES HEADERS
CSV_SUMMARY: list[str] = ['STATUS', 'OBJ-TYPE', 'OBJ-COUNT', 'NOTES']
CSV_CONFIG: list[str] = ['STATUS', 'OBJ-TYPE', 'OBJ-ID', 'OBJ-NAME', 'OBJ-REF', 'PROJ-USING', 'NOTES']
CSV_ACUSERS: list[str] = ['STATUS', 'PROVIDER-TYPE', 'ID', 'NAME', 'EMAIL', 'FIRST-NAME', 'LAST-NAME', 'NOTES']
CSV_ACTEAMS: list[str] = ['STATUS', 'TEAM-ID', 'TEAM-NAME', 'PROJ-USING', 'QUERY-USING', 'NOTES']
CSV_ACROLES: list[str] = ['STATUS', 'ROLE-ID', 'ROLE-NAME', 'NOTES']
CSV_QUERIES: list[str] = ['STATUS', 'QUERY-ID', 'QUERY-PACKAGE-TYPE', 'QUERY-LANGUAGE', 'QUERY-NAME', 'QUERY-GROUP', 'QUERY-SEVERITY',
                          'REF-ID', 'REF-NAME', 'PROJ-USING', 'NOTES']
CSV_PRESETS: list[str] = ['STATUS', 'PRESET-ID', 'PRESET-NAME', 'PRESET-TYPE', 'CUSTOMIZED', 'PROJ-USING', 'NOTES']
CSV_PRESETQUERIES: list[str] = ['STATUS', 'PRESET-ID', 'PRESET-NAME', 'PRESET-TYPE', 'QUERY-STATUS',
                                'QUERY-ID', 'QUERY-NAME', 'QUERY-LANGUAGE', 'QUERY-GROUP', 'QUERY-PACKAGE-TYPE']
CSV_CATGEGORIES: list[str] = ['STATUS', 'CATEGORY-ID', 'CATEGORY-NAME', 'NOTES']
CSV_PROJECTS: list[str] = ['STATUS', 'ID', 'NAME', 'DUPLICATED', 'ISPUBLIC', 'CREATED', 'TOTAL-SCANS',
                           'TEAM-ID', 'TEAM-NAME', 'PRESET', 'ENGINE-CONFIG',
                           'CUSTOM-FIELDS', 'ISSUE-TRACKER', 'SCHEDULED-SCANS',
                           'EXCLUSIONS-FILES', 'EXCLUSIONS-FOLDERS', 'EXCLUSIONS-GLOB',
                           'EMAIL-NOTIFICATIONS', 'PRE-SCAN-ACTION', 'POST-SCAN-ACTION', 'SHARED-FOLDER',
                           'CUSTOM-CORP-QUERIES', 'CUSTOM-TEAM-QUERIES', 'CUSTOM-PROJ-QUERIES',
                           'REPOSITORY-TYPE', 'REPOSITORY-URL', 'REPOSITORY-BRANCH',
                           'PLUGIN', 'ORIGIN',
                           'LAST-SCAN-ID', 'LAST-SCAN-DATE', 'LAST-SCAN-FULL',
                           'LOC', 'LANGUAGES',
                           'TOTAL-RESULTS', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO',
                           'TRIAGES', 'CUSTOM-STATES', 'NOTES']


class CxSastInventory(object) :

    def __init__(self ) :
        self.__cxsast: CxSastHttpClient = None
        self.__cxsoap: CxSastSoapClient = None
        self.__cxcsv: CxCsv = CxCsv()
        self.__cxcaches: CxCaches = CxCaches()
        self.__datapath: str = None
        # Global execution options
        self.__noiam: bool = cxconfig.getvalue( "options.no-iam" )
        self.__noiam = self.__noiam and isinstance(self.__noiam, bool)
        self.__usersfull: bool = cxconfig.getvalue( "options.detailed-users" )
        self.__usersfull = self.__usersfull and isinstance(self.__usersfull, bool)
        self.__noscandata: bool = cxconfig.getvalue( "options.no-scans" )
        self.__noscandata = self.__noscandata and isinstance(self.__noscandata, bool)
        self.__notriages: bool = cxconfig.getvalue( "options.no-triages" )
        self.__notriages = self.__notriages and isinstance(self.__notriages, bool)
        self.__projectfilter: any = cxconfig.getvalue( "options.projects-filter" )
        self.__includerepos: bool = cxconfig.getvalue( "options.include-repos" )
        self.__includerepos = self.__includerepos and isinstance(self.__includerepos, bool)
        # Control variable for starting cunston state id
        self.__customstateid: int = 0
        # Well known file for csv containing summary
        self.__sumryhandler = None
        self.__sumrywriter = None
        # Well known file for csv containing system configurations
        self.__confhandler = None
        self.__confwriter = None
        # Well known file for csv containing access-control users
        self.__usershandler = None
        self.__userswriter = None
        # Well known file for csv containing access-control teams
        self.__teamshandler = None
        self.__teamswriter = None
        # Well known file for csv containing access-control roles
        self.__roleshandler = None
        self.__roleswriter = None
        # Well known file for csv containing custom queries
        self.__queryhandler = None
        self.__querywriter = None
        # Well known file for csv containing presets
        self.__psetshandler = None
        self.__psetswriter = None
        # Well known file for csv containing preset queries
        self.__psetqhandler = None
        self.__psetqwriter = None
        # Well known file for csv containing custom categories
        self.__categshandler = None
        self.__categswriter = None
        # Well known file for csv containing projects
        self.__projshandler = None
        self.__projswriter = None


    @property
    def cxsast(self) -> CxSastHttpClient :
        return self.__cxsast


    @property
    def cxsoap(self) -> CxSastSoapClient :
        return self.__cxsoap


    @property
    def cxcsv(self) -> CxCsv :
        return self.__cxcsv


    @property
    def cxcaches(self) -> CxCaches :
        return self.__cxcaches


    def __dateparse(self, datetimestr: str) -> str :
        if not datetimestr :
            return datetimestr
        xdatestr: str = datetimestr.replace( 'T', ' ' )
        xdatestr = xdatestr.replace( 'Z', '' )
        xdotpos: int = xdatestr.find('.')
        if xdotpos > 0 :
            xdatestr = xdatestr[: xdotpos ]
        return xdatestr


    def __preparedatafiles(self) :
        # location path
        try :
            self.__closedatafiles()
            self.__datapath = cxutils.application_path()
            if not self.__datapath :
                self.__datapath = 'data'
            else :
                self.__datapath = self.__datapath + os.sep + 'data'
            os.makedirs(self.__datapath, exist_ok = True)
            cxlogger.debug( 'Output files location set to "' + self.__datapath + '"' )
            # Well known file for csv containing summary
            filename = self.__datapath + os.sep + OUT_SUMMARY
            if os.path.exists(filename) :
                os.remove(filename)
            # Well known file for csv containing system configurations
            filename = self.__datapath + os.sep + OUT_CONFIG
            if os.path.exists(filename) :
                os.remove(filename)
            # Well known file for csv containing access-control users
            filename = self.__datapath + os.sep + OUT_ACUSERS
            if os.path.exists(filename) :
                os.remove(filename)
            # Well known file for csv containing access-control teams
            filename = self.__datapath + os.sep + OUT_ACTEAMS
            if os.path.exists(filename) :
                os.remove(filename)
            # Well known file for csv containing access-control roles
            filename = self.__datapath + os.sep + OUT_ACROLES
            if os.path.exists(filename) :
                os.remove(filename)
            # Well known file for csv containing queries
            filename = self.__datapath + os.sep + OUT_QUERIES
            if os.path.exists(filename) :
                os.remove(filename)
            # Well known file for csv containing presets
            filename = self.__datapath + os.sep + OUT_PRESETS
            if os.path.exists(filename) :
                os.remove(filename)
            # Well known file for csv containing preset queries
            filename = self.__datapath + os.sep + OUT_PRESETQUERIES
            if os.path.exists(filename) :
                os.remove(filename)
            # Well known file for csv containing custom categories
            filename = self.__datapath + os.sep + OUT_CATEGORIES
            if os.path.exists(filename) :
                os.remove(filename)
            # Well known file for csv containing projects
            filename = self.__datapath + os.sep + OUT_PROJECTS
            if os.path.exists(filename) :
                os.remove(filename)
            # Done
            cxlogger.debug( 'Output files reset' )
            return True
        except Exception as e:
            cxlogger.exception(e)
            return False


    def __closedatafiles(self) :
        if (self.__sumryhandler):
            self.__sumryhandler.close()
        if (self.__confhandler):
            self.__confhandler.close()
        if (self.__usershandler):
            self.__usershandler.close()
        if (self.__teamshandler):
            self.__teamshandler.close()
        if (self.__roleshandler):
            self.__roleshandler.close()
        if (self.__queryhandler):
            self.__queryhandler.close()
        if (self.__psetshandler):
            self.__psetshandler.close()
        if (self.__psetqhandler):
            self.__psetqhandler.close()
        if (self.__categshandler):
            self.__categshandler.close()
        if (self.__projshandler):
            self.__projshandler.close()
        self.__sumryhandler = None
        self.__confhandler = None
        self.__usershandler = None
        self.__teamshandler = None
        self.__roleshandler = None
        self.__queryhandler = None
        self.__psetshandler = None
        self.__psetqhandler = None
        self.__categshandler = None
        self.__projshandler = None


    def __internal_write_summary( self, data: list ) :
        # Check output file is ready
        if not self.__sumryhandler :
            filename = self.__datapath + os.sep + OUT_SUMMARY
            self.__sumryhandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__sumrywriter = csv.writer(self.__sumryhandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__internal_write_summary(CSV_SUMMARY)
        # Write it
        self.__sumrywriter.writerow( data )


    def __internal_write_config( self, data: list, cacheit: bool = True ) :
        # Check output file is ready
        if not self.__confhandler :
            filename = self.__datapath + os.sep + OUT_CONFIG
            self.__confhandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__confwriter = csv.writer(self.__confhandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__confwriter.writerow(CSV_CONFIG)
        # Write it
        self.__confwriter.writerow( data )
        # Cache it
        if cacheit :
            xpos: int = 0
            xval: any = None
            xdict: dict = {}
            for xkey in CSV_CONFIG :
                xval = data[xpos]
                xdict[xkey] = xval
                xpos += 1
            xcache: list[dict] = self.cxcaches.cache(CACHE_CONFIG)
            if not xcache :
                xcache = []
                xcache.append(xdict)
                self.cxcaches.putcache(CACHE_CONFIG, xcache)
            else :
                xcache.append(xdict)


    def __internal_write_user( self, data: list ) :
        # Check output file is ready
        if not self.__usershandler :
            filename = self.__datapath + os.sep + OUT_ACUSERS
            self.__usershandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__userswriter = csv.writer(self.__usershandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__userswriter.writerow(CSV_ACUSERS)
        # Write it
        self.__userswriter.writerow( data )


    def __internal_write_team( self, data: list, cacheit: bool = True ) :
        # Check output file is ready
        if not self.__teamshandler :
            filename = self.__datapath + os.sep + OUT_ACTEAMS
            self.__teamshandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__teamswriter = csv.writer(self.__teamshandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__teamswriter.writerow(CSV_ACTEAMS)
        # Write it
        self.__teamswriter.writerow( data )
        # Cache it
        if cacheit :
            xpos: int = 0
            xval: any = None
            xdict: dict = {}
            for xkey in CSV_ACTEAMS :
                xval = data[xpos]
                xdict[xkey] = xval
                xpos += 1
            xcache: list[dict] = self.cxcaches.cache(CACHE_TEAMS)
            if not xcache :
                xcache = []
                xcache.append(xdict)
                self.cxcaches.putcache(CACHE_TEAMS, xcache)
            else :
                xcache.append(xdict)


    def __internal_write_role( self, data: list ) :
        # Check output file is ready
        if not self.__roleshandler :
            filename = self.__datapath + os.sep + OUT_ACROLES
            self.__roleshandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__roleswriter = csv.writer(self.__roleshandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__roleswriter.writerow(CSV_ACROLES)
        # Write it
        self.__roleswriter.writerow( data )


    def __internal_write_query( self, data: list, cacheit: bool = True ) :
        # Check output file is ready
        if not self.__queryhandler :
            filename = self.__datapath + os.sep + OUT_QUERIES
            self.__queryhandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__querywriter = csv.writer(self.__queryhandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__querywriter.writerow(CSV_QUERIES)
        # Write it
        self.__querywriter.writerow( data )
        # Cache it
        if cacheit :
            xpos: int = 0
            xval: any = None
            xdict: dict = {}
            for xkey in CSV_QUERIES :
                xval = data[xpos]
                xdict[xkey] = xval
                xpos += 1
            xcache: list[dict] = self.cxcaches.cache(CACHE_QUERIES)
            if not xcache :
                xcache = []
                xcache.append(xdict)
                self.cxcaches.putcache(CACHE_QUERIES, xcache)
            else :
                xcache.append(xdict)


    def __internal_write_preset( self, data: list, cacheit: bool = True ) :
        # Check output file is ready
        if not self.__psetshandler :
            filename = self.__datapath + os.sep + OUT_PRESETS
            self.__psetshandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__psetswriter = csv.writer(self.__psetshandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__psetswriter.writerow(CSV_PRESETS)
        # Write it
        self.__psetswriter.writerow( data )
        # Cache it
        if cacheit :
            xpos: int = 0
            xval: any = None
            xdict: dict = {}
            for xkey in CSV_PRESETS :
                xval = data[xpos]
                xdict[xkey] = xval
                xpos += 1
            xcache: list[dict] = self.cxcaches.cache(CACHE_PRESETS)
            if not xcache :
                xcache = []
                xcache.append(xdict)
                self.cxcaches.putcache(CACHE_PRESETS, xcache)
            else :
                xcache.append(xdict)


    def __internal_write_preset_query( self, data: list ) :
        # Check output file is ready
        if not self.__psetqhandler :
            filename = self.__datapath + os.sep + OUT_PRESETQUERIES
            self.__psetqhandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__psetqwriter = csv.writer(self.__psetqhandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__psetqwriter.writerow(CSV_PRESETQUERIES)
        # Write it
        self.__psetqwriter.writerow( data )


    def __internal_write_custom_category( self, data: list ) :
        # Check output file is ready
        if not self.__categshandler :
            filename = self.__datapath + os.sep + OUT_CATEGORIES
            self.__categshandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__categswriter = csv.writer(self.__categshandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__categswriter.writerow(CSV_CATGEGORIES)
        # Write it
        self.__categswriter.writerow( data )


    def __internal_get_identity_providertype_ids(self, providertype: str) -> int :
        xproviders: list = self.cxcaches.cache(CACHE_AC_PROVIDERS)
        if not xproviders :
            try :
                xproviders = self.cxsast.get('/cxrestapi/auth/authenticationproviders')
                self.cxcaches.putcache(CACHE_AC_PROVIDERS, xproviders)
            except Exception :
                xproviders = []
                pass
            self.cxcaches.putcache(CACHE_AC_PROVIDERS, xproviders)
        xproviderids: list[int] = []
        if xproviders :
            xproviderslist = list( filter( lambda el: el['providerType'] == providertype, xproviders) )
            for xprovider in xproviderslist :
                xproviderids.append(xprovider['id'])
        return xproviderids


    def __internal_get_identity_provider_id(self, providername: str, providertype: str) -> int :
        xproviders: list = self.cxcaches.cache(CACHE_AC_PROVIDERS)
        if not xproviders :
            try :
                xproviders = self.cxsast.get('/cxrestapi/auth/authenticationproviders')
                self.cxcaches.putcache(CACHE_AC_PROVIDERS, xproviders)
            except Exception :
                xproviders = []
                pass
            self.cxcaches.putcache(CACHE_AC_PROVIDERS, xproviders)
        xproviderid: int = 0
        if xproviders :
            xprovider = next( filter( lambda el: el['name'] == providername and el['providerType'] == providertype, xproviders), None )
            if xprovider :
                xproviderid = xprovider['id']
        return xproviderid


    def __internal_get_identity_provider_name(self, providerid: int) -> str :
        xproviders: list = self.cxcaches.cache(CACHE_AC_PROVIDERS)
        if not xproviders :
            try :
                xproviders = self.cxsast.get('/cxrestapi/auth/authenticationproviders')
                self.cxcaches.putcache(CACHE_AC_PROVIDERS, xproviders)
            except Exception :
                xproviders = []
                pass
            self.cxcaches.putcache(CACHE_AC_PROVIDERS, xproviders)
        xprovider: dict = None
        xprovidername: str = None
        if xproviders :
            xprovider = next( filter( lambda el: el['id'] == providerid, xproviders), None )
        if xprovider :
            xprovidername = xprovider.get('name')
        if not xprovidername :
            xprovidername = None
        return xprovidername


    def __internal_get_all_active_users(self, ignoreerrors: bool = False) -> list[dict] :
        xallusers: list = self.cxcaches.cache(CACHE_AC_USERS)
        if not xallusers :
            xallusers = []
            try :
                xusers: list = self.cxsast.get('/cxrestapi/auth/users')
                # filter only active
                xallusers = list( filter( lambda el: el['active'], xusers) )
            except Exception as e:
                if ignoreerrors :
                    pass
                else :
                    raise e
            self.cxcaches.putcache( cachename = CACHE_AC_USERS, cachedata = xallusers )
        return xallusers


    def __internal_get_all_teams(self, ignoreerrors: bool = False) -> list[dict] :
        xallteams: list = self.cxcaches.cache(CACHE_AC_TEAMS)
        if not xallteams :
            xallteams = []
            try :
                xallteams = self.cxsast.get('/cxrestapi/auth/teams')
            except Exception as e:
                if ignoreerrors :
                    pass
                else :
                    raise e
            self.cxcaches.putcache( cachename = CACHE_AC_TEAMS, cachedata = xallteams )
        return xallteams


    def __internal_get_all_queries(self, ignoreerrors: bool = False) -> list[dict] :
        xallqueries = self.cxcaches.cache(CACHE_ALL_QUERIES)
        if not xallqueries :
            xallqueries = []
            try :
                xallqueries = self.cxsoap.getqueries(flatten = True, onlycustom = False)
            except Exception as e :
                if ignoreerrors :
                    pass
                else :
                    raise e
            self.cxcaches.putcache( cachename = CACHE_ALL_QUERIES, cachedata = xallqueries )
        return xallqueries


    def __internal_get_custom_queries(self, querytype: str) -> list[dict] :
        xallqueries = self.__internal_get_all_queries(ignoreerrors = True)
        xallteams: list = None
        if querytype == 'Team' :
            xallteams = self.__internal_get_all_teams(ignoreerrors = True)
        xqueries: list[dict] = []
        for query in xallqueries :
            ptype = query.get("PackageType")
            if (ptype == querytype) :
                qitem = query
                # Resolve the query team path
                qitem["OwningTeamName"] = None
                if qitem["OwningTeam"] and xallteams and len(xallteams) > 0 :
                    team = next(filter( lambda el: el['id'] == qitem['OwningTeam'], xallteams), None)
                    if team :
                        qitem['OwningTeamName'] = team['fullName']
                xqueries.append(qitem)
        return xqueries


    def __inventory_sastinstance(self) :
        errorcount: int = 0
        inventory_name: str = 'sast instance'
        xobject: str = OBJ_SAST_INSTANCE
        xstatus: int = SOK
        xinfo: str = None
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            sastversion: float = None
            sastname = self.cxsast.host + ' - version ' + self.cxsast.versionstr()
            sastverz = self.cxsast.version()
            if sastverz :
                sastversion = float(sastverz['major'] + '.' + sastverz['minor'])
            # Is version below 9.6
            if sastversion and sastversion < SAST_MIN_VERSION :
                xstatus = SWARNING
                xinfo = 'version is below ' + str(SAST_MIN_VERSION)
            # Register to inventory
            self.__internal_write_config( [STATUS[xstatus], xobject, None, sastname, None, None, xinfo ] )
            # Register to summary
            if xinfo :
                xinfo = sastname + ', ' + xinfo
            else :
                xinfo = sastname
            self.__internal_write_summary( [STATUS[xstatus], xobject, 1, xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (1) - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_addoncomponents(self) :
        errorcount = 0
        inventory_name = 'add-on components'
        xobject: str = OBJ_ADD_ONS
        xauxdata: list = None
        xstatus: int = SWARNING
        xinfo: str = None
        xstarted = CxDatetime.now()
        xcounter: int = 0
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            xsettings = self.cxsast.get('/cxrestapi/configurationsextended/systemsettings')
            # ARM M&O / REMEDIATION INTELIGENCE / POLICY MANAGER
            xarmurl: str = None
            xauxdata = list( filter( lambda el: el['key'] == 'CxARMURL', xsettings ) )
            if xauxdata and len(xauxdata) > 0:
                xarmurl = xauxdata[0]['value']
                if xarmurl :
                    # Register to inventory
                    xname = 'Policy Manager'
                    xinfo = 'Extra add-on detected'
                    self.__internal_write_config( [STATUS[xstatus], xobject, None, xname, None, None, xinfo ], False )
                    xcounter += 1

            # Try get role permissions (ignore failures)
            xpermissions: list = None
            try :
                xpermissions = self.cxsast.get( '/cxrestapi/auth/permissions' )
            except Exception :
                xpermissions = []
                pass
            if len(xpermissions) > 0 :
                # Have reporting service
                xperm = next( filter( lambda el: el["category"] == "Reports" and el["name"] in ["generate-project-report", "generate-executive-report"], xpermissions ), None )
                if xperm :
                    # Register to inventory
                    xname = 'Reporting Service'
                    xinfo = 'Extra add-on detected'
                    self.__internal_write_config( [STATUS[xstatus], xobject, None, xname, None, None, xinfo ], False )
                    xcounter += 1

            # Register to summary
            if xcounter > 0 :
                xinfo = 'Extra add-ons detected'
            else :
                xstatus = SOK
                xinfo = 'No Extra add-ons detected'
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcounter) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_engineconfigs(self) :
        errorcount = 0
        inventory_name = 'engine configurations'
        xobject: str = OBJ_ENGINE_CONFIG
        xstatus: int = SOK
        xinfo: str = None
        xiscustom: bool = False
        xcustomcount: int = 0
        xiscustomref: str = None
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            xconfigs = self.cxsast.get('/cxrestapi/sast/engineconfigurations')
            # Register to inventory
            for config in xconfigs :
                xiscustom = config['name'] not in ['Default Configuration', 'Japanese (Shift-JIS)', 'Korean', 'Multi-language Scan', 'Improved Scan Flow', 'Fast Scan', 'Fast Scan With File Exclusions']
                config['IsCustom'] = xiscustom
                if xiscustom :
                    xiscustomref = 'Customized'
                    xstatus = SWARNING
                    xinfo = 'customized engine configuration'
                    xcustomcount += 1
                else :
                    xstatus = SOK
                    xinfo = None
                self.__internal_write_config( [STATUS[xstatus], xobject, config['id'], config['name'], xiscustomref, None, xinfo ] )
            # Register to summary
            if xcustomcount > 0 :
                xstatus = SWARNING
                xinfo = 'customized engine configurations exist'
            else :
                xstatus = SOK
                xinfo = None
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xconfigs), xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(len(xconfigs)) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_engineservers(self) :
        errorcount = 0
        inventory_name = 'engine servers'
        xobject: str = OBJ_ENGINE_SERVER
        xstatus: int = SOK
        xinfo: str = None
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            xengines = self.cxsast.get('/cxrestapi/sast/engineServers')
            # Register to inventory
            for engine in xengines :
                xinfo = 'max scans: ' + str(engine['maxScans']) + ', range: ' + str(engine['minLoc']) + ' to ' + str(engine['maxLoc'])
                self.__internal_write_config( [STATUS[xstatus], xobject, engine['id'], engine['name'], None, None, xinfo ], False )
            # Register index
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xengines), None ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(len(xengines)) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_customfields(self) :
        errorcount = 0
        inventory_name = 'custom fields'
        xobject: str = OBJ_CUSTOM_FIELDS
        xstatus: int = SOK
        xinfo: str = None
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            xfields = self.cxsast.get('/cxrestapi/customfields')
            # Register to inventory
            for field in xfields :
                self.__internal_write_config( [STATUS[xstatus], xobject, field['id'], field['name'], None, None, xinfo ] )
            # Register index
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xfields), None ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(len(xfields)) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_smtpsettings(self) :
        errorcount = 0
        inventory_name = 'smtp settings'
        xobject: str = OBJ_SMTP_SETTINGS
        xstatus: int = SWARNING
        xinfo: str = 'unsupported - refer to feedback apps'
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            xsettings = self.cxsast.get('/cxrestapi/configurationsextended/systemsettings')
            xsmtps = []
            xsmtpdata = list( filter( lambda el: el['key'] == 'SMTPHost', xsettings ) )[0]['value']
            if xsmtpdata :
                xsmtps.append( { "name": xsmtpdata } )
            # Register to inventory
            for smtp in xsmtps :
                self.__internal_write_config( [STATUS[xstatus], xobject, None, smtp['name'], None, None, xinfo ] )
            # Register index
            if len(xsmtps) == 0 :
                xstatus = SOK
                xinfo = None
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xsmtps), xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(len(xsmtps)) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_issuetrackers(self) :
        errorcount = 0
        inventory_name = 'issue trackers'
        xobject: str = OBJ_ISSUE_TRACKER
        xstatus: int = SWARNING
        xinfo: str = None
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            xtrackers = self.cxsast.get('/cxrestapi/issuetrackingsystems')
            # Register to inventory
            for tracker in xtrackers :
                xinfo = 'unsupported ' + tracker['type'] + ' issue tracker'
                self.__internal_write_config( [STATUS[xstatus], xobject, tracker['id'], tracker['name'], tracker['url'], None, xinfo ] )
            # Register index
            if len(xtrackers) == 0 :
                xstatus = SOK
                xinfo = None
            else:
                xstatus = SWARNING
                xinfo = 'unsupported - refer to feedback apps'
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xtrackers), xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(len(xtrackers)) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_scanactions(self) :
        errorcount = 0
        inventory_name = 'scan actions'
        xobject: str = OBJ_SCAN_ACTIONS
        xstatus: int = SOK
        xinfo: str = None
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            # This list brings pre and post scan actions, so let's handle the two
            xallactions = self.cxsast.get('/cxrestapi/customtasks')

            # Pre-scan actions
            xactions = list( filter( lambda el: el['type'] == 'SOURCE_CONTROL_COMMAND', xallactions ) )
            xobject = OBJ_PRE_SCAN_ACTION
            xstatus = SWARNING
            xinfo = None
            # Register to inventory
            for action in xactions :
                xinfo = 'pre-scan action unsupported'
                self.__internal_write_config( [STATUS[xstatus], xobject, action['id'], action['name'], action['data'], None, xinfo ] )
            # Register index
            if len(xactions) == 0 :
                xstatus = SOK
                xinfo = None
            else:
                xstatus = SDANGER
                xinfo = 'unsupported pre-scan actions'
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xactions), xinfo ] )

            # Post-scan actions
            xactions = list( filter( lambda el: el['type'] == 'POST_SCAN_COMMAND', xallactions ) )
            xobject = OBJ_POST_SCAN_ACTION
            xstatus = SWARNING
            xinfo = None
            # Register to inventory
            for action in xactions :
                xinfo = 'post-scan action unsupported'
                self.__internal_write_config( [STATUS[xstatus], xobject, action['id'], action['name'], action['data'], None, xinfo ] )
            # Register index
            if len(xactions) == 0 :
                xstatus = SOK
                xinfo = None
            else:
                xstatus = SWARNING
                xinfo = 'unsupported post-scan actions'
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xactions), xinfo ] )

            # Close
            inventory_name = 'scan actions'
            cxlogger.info('Processed ' + inventory_name + ' (' + str(len(xallactions)) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_resultstates(self) :
        errorcount = 0
        inventory_name = 'result states'
        xobject: str = OBJ_RESULT_STATES
        xstatus: int = SOK
        xinfo: str = None
        xcustomcount: int = 0
        xcustomusedcount: int = 0
        xcustomref: str = None
        xstateinuse: bool = None
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            xstates = self.cxsoap.getresultstates()
            # Register to inventory
            for state in xstates :
                if state['IsCustom'] :
                    xcustomref = 'Custom'
                    xstatus = SDANGER
                    xinfo = 'unsupported custom state'
                    xcustomcount += 1
                    xstateinuse = None
                    if (state['ResultID'] > 4) and ( (self.__customstateid <= 0) or (state['ResultID'] < self.__customstateid) ) :
                        self.__customstateid = state['ResultID']
                else :
                    xstatus = SOK
                    xinfo = None
                self.__internal_write_config( [STATUS[xstatus], xobject, state['ResultID'], state['ResultName'], xcustomref, xstateinuse, xinfo ] )
            # Register index
            if xcustomcount == 0 :
                xstatus = SOK
                xinfo = None
            elif xcustomusedcount > 0 :
                xstatus = SDANGER
                xinfo = 'unsupported custom states in use'
            else:
                xstatus = SWARNING
                xinfo = 'unsupported custom states defined'
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xstates), xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(len(xstates)) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_ac_users(self) :
        errorcount = 0
        inventory_name = 'access-control users'
        xobject: str = OBJ_AC_USERS
        xstatus: int = SWARNING

        if self.__noiam :
            xstatus = SWARNING
            xinfo = 'excluded by no-iam access-control option'
            self.__internal_write_summary( [STATUS[xstatus], xobject, None, xinfo ] )
            return errorcount

        xinfo: str = None
        xemaildomains: list[str] = []
        xemail: str = None
        xcounter: int = 0
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            # Go for the users cache
            xallusers = self.__internal_get_all_active_users()

            # Application users
            xproviders = self.__internal_get_identity_providertype_ids('Application')
            xcounter = 0
            xinfo = 'application user'
            xobject = OBJ_AC_USERS_APP
            xusers = list( filter( lambda el: el['authenticationProviderId'] in xproviders, xallusers ) )
            if len(xusers) > 0 :
                xstatus = SWARNING
            else :
                xstatus = SOK
            for user in xusers :
                xcounter += 1
                xemail = user['email']
                if not xemail :
                    xemail = None
                if self.__usersfull :
                    xprovidername = self.__internal_get_identity_provider_name(user['authenticationProviderId'])
                    self.__internal_write_user( [STATUS[xstatus], xprovidername, user['id'], user['userName'], xemail, user['firstName'], user['lastName'], xinfo] )
                # Process email domain
                if xemail :
                    p = xemail.find('@')
                    if p >= 0 :
                        xemail = xemail[p:].strip()
                if xemail :
                    xemaildomains.append(xemail)
            if xcounter > 1 :
                xinfo = str(xcounter) + ' users for manual creation'
            elif xcounter == 1 :
                xinfo = '1 user for manual creation'
            else :
                xstatus = SOK
                xinfo = None
            # Register index
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )

            # SAML users
            xproviders = self.__internal_get_identity_providertype_ids('SAML')
            xcounter = 0
            xinfo = 'SAML user'
            xobject = OBJ_AC_USERS_SAML
            xusers = list( filter( lambda el: el['authenticationProviderId'] in xproviders, xallusers ) )
            if len(xusers) > 0 :
                xstatus = SWARNING
            else :
                xstatus = SOK
            for user in xusers :
                xcounter += 1
                xemail = user['email']
                if not xemail :
                    xemail = None
                if self.__usersfull :
                    xprovidername = self.__internal_get_identity_provider_name(user['authenticationProviderId'])
                    self.__internal_write_user( [STATUS[xstatus], xprovidername, user['id'], user['userName'], xemail, user['firstName'], user['lastName'], xinfo] )
                # Process email domain
                if xemail :
                    p = xemail.find('@')
                    if p >= 0 :
                        xemail = xemail[p:].strip()
                if xemail :
                    xemaildomains.append(xemail)
            if xcounter > 1 :
                xinfo = str(xcounter) + ' users for SAML integration'
            elif xcounter == 1 :
                xinfo = '1 user for SAML integration'
            else :
                xstatus = SOK
                xinfo = None
            # Register index
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )

            # LDAP users
            xproviders = self.__internal_get_identity_providertype_ids('LDAP')
            xcounter = 0
            xinfo = 'LDAP user'
            xobject = OBJ_AC_USERS_LDAP
            xusers = list( filter( lambda el: el['authenticationProviderId'] in xproviders, xallusers ) )
            if len(xusers) > 0 :
                xstatus = SDANGER
            else :
                xstatus = SOK
            for user in xusers :
                xcounter += 1
                xemail = user['email']
                if not xemail :
                    xemail = None
                if self.__usersfull :
                    xprovidername = self.__internal_get_identity_provider_name(user['authenticationProviderId'])
                    self.__internal_write_user( [STATUS[xstatus], xprovidername, user['id'], user['userName'], xemail, user['firstName'], user['lastName'], xinfo] )
                # Process email domain
                if xemail :
                    p = xemail.find('@')
                    if p >= 0 :
                        xemail = xemail[p:].strip()
                if xemail :
                    xemaildomains.append(xemail)
            if xcounter > 1 :
                xinfo = str(xcounter) + ' users for LDAP integration'
            elif xcounter == 1 :
                xinfo = '1 user for LDAP integration'
            else :
                xstatus = SOK
                xinfo = None
            # Register index
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )

            # DOMAIN users
            xproviders = self.__internal_get_identity_providertype_ids('Domain')
            xcounter = 0
            xinfo = 'domain user'
            xobject = OBJ_AC_USERS_DOMAIN
            xusers = list( filter( lambda el: el['authenticationProviderId'] in xproviders, xallusers ) )
            if len(xusers) > 0 :
                xstatus = SDANGER
            else :
                xstatus = SOK
            for user in xusers :
                xcounter += 1
                xemail = user['email']
                if not xemail :
                    xemail = None
                if self.__usersfull :
                    xprovidername = self.__internal_get_identity_provider_name(user['authenticationProviderId'])
                    self.__internal_write_user( [STATUS[xstatus], xprovidername, user['id'], user['userName'], xemail, user['firstName'], user['lastName'], xinfo] )
                # Process email domain
                if xemail :
                    p = xemail.find('@')
                    if p >= 0 :
                        xemail = xemail[p:].strip()
                if xemail :
                    xemaildomains.append(xemail)
            if xcounter > 1 :
                xinfo = str(xcounter) + ' domain users for manual creation'
            elif xcounter == 1 :
                xinfo = '1 domain user for manual creation'
            else :
                xstatus = SOK
                xinfo = None
            # Register index
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )

            # Distinct email domains
            xinfo = 'distinct email domain'
            xemaildomains = list( dict.fromkeys(xemaildomains) )
            xobject = OBJ_AC_USERS_EMAILS
            if len(xemaildomains) > 0 :
                xstatus = SWARNING
            else :
                xstatus = SOK
            for email in xemaildomains :
                self.__internal_write_config( [STATUS[xstatus], xobject, None, email, None, None, xinfo ], False )
            # Register index
            xinfo = 'distinct email domains'
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xemaildomains), xinfo ] )

            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(len(xallusers)) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_ac_teams(self) :
        errorcount = 0
        inventory_name = 'access-control teams'
        xobject: str = OBJ_AC_TEAMS
        xstatus: int = SOK

        if self.__noiam :
            xstatus = SWARNING
            xinfo = 'excluded by no-iam access-control option'
            self.__internal_write_summary( [STATUS[xstatus], xobject, None, xinfo ] )
            return errorcount

        xinfo: str = None
        xusercount: int = 0
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            xteams = self.__internal_get_all_teams()
            xusers = self.__internal_get_all_active_users(True)
            # Register to inventory
            for team in xteams :
                # Have users
                xusercount = 0
                if len(xusers) :
                    xusercount = len(list( filter( lambda el: team['id'] in el['teamIds'], xusers ) ))
                if xusercount > 1 :
                    xinfo = str(xusercount) + ' members'
                elif xusercount == 1 :
                    xinfo = str(xusercount) + ' member'
                else :
                    xinfo = 'no members'
                self.__internal_write_team( [STATUS[xstatus], team['id'], team['fullName'], None, None, xinfo ])

            # Register index
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xteams), None ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(len(xteams)) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_ac_roles(self) :
        errorcount = 0
        inventory_name = 'access-control roles'
        xobject: str = OBJ_AC_ROLES
        xstatus: int = SOK
        xinfo: str = None

        if self.__noiam :
            xstatus = SWARNING
            xinfo = 'excluded by no-iam access-control option'
            self.__internal_write_summary( [STATUS[xstatus], xobject, None, xinfo ] )
            return errorcount

        xusercount: int = 0
        xcustomroles: int = 0
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            xroles = self.cxsast.get('/cxrestapi/auth/roles')
            xusers = self.__internal_get_all_active_users(True)
            # Register to inventory
            for role in xroles :
                xstatus = SOK
                # Have users
                xusercount = 0
                if len(xusers) > 0 :
                    xusercount = len(list( filter( lambda el: role['id'] in el['roleIds'], xusers ) ))
                if xusercount > 1 :
                    xinfo = str(xusercount) + ' members'
                elif xusercount == 1 :
                    xinfo = str(xusercount) + ' member'
                else :
                    xinfo = 'no members'
                if not role['isSystemRole'] :
                    xstatus = SWARNING
                    xinfo = 'custom role ' + xinfo
                    xcustomroles += 1
                self.__internal_write_role( [STATUS[xstatus], role['id'], role['name'], xinfo ])
            # Register index
            if xcustomroles > 0 :
                xinfo = str(xcustomroles) + ' custom roles'
                xstatus = SWARNING
            else :
                xinfo = None
                xstatus = SOK
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xroles), xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(len(xroles)) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_ac_samlsettings(self) :
        errorcount = 0
        inventory_name = 'access-control saml settings'
        xobject: str = OBJ_AC_SAML
        xstatus: int = SWARNING
        xinfo: str = None

        if self.__noiam :
            xstatus = SWARNING
            xinfo = 'excluded by no-iam access-control option'
            self.__internal_write_summary( [STATUS[xstatus], xobject, None, xinfo ] )
            return errorcount

        xcustomcount: int = 0
        xusercount: int = 0
        xcounter: int = 0
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            # Get users
            xusers = self.__internal_get_all_active_users(True)
            # Get SAML providers list
            xsamls = self.cxsast.get('/cxrestapi/auth/samlidentityproviders')
            # Register to inventory
            for saml in xsamls :
                if saml['active'] :
                    xcounter += 1
                    provid = self.__internal_get_identity_provider_id( saml['name'], 'SAML' )
                    # Check users count
                    xusercount = 0
                    if len(xusers) > 0 :
                        xusercount = len( list( filter( lambda el: el['authenticationProviderId'] == provid, xusers) ) )
                    xinfo = 'issuer: ' + saml['issuer']
                    if xusercount > 1 :
                        xinfo = xinfo + ' (' + str(xusercount) + ' users)'
                        xstatus = SWARNING
                        xcustomcount += 1
                    elif xusercount == 1 :
                        xinfo = xinfo + ' (' + str(xusercount) + ' user)'
                        xstatus = SWARNING
                        xcustomcount += 1
                    else :
                        xinfo = xinfo + ' (no users)'
                        xstatus = SOK
                    self.__internal_write_config( [STATUS[xstatus], xobject, provid, saml['name'], None, None, xinfo ], False )
            # Register index
            xstatus = SOK
            xinfo = None
            if xcounter > 0 :
                xinfo = 'manual configuration required'
                if xcustomcount == 0 :
                    xstatus = SOK
                else:
                    xstatus = SWARNING
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcounter) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_ac_ldapsettings(self) :
        errorcount = 0
        inventory_name = 'access-control ldap settings'
        xobject: str = OBJ_AC_LDAP
        xstatus: int = SWARNING
        xinfo: str = None

        if self.__noiam :
            xstatus = SWARNING
            xinfo = 'excluded by no-iam access-control option'
            self.__internal_write_summary( [STATUS[xstatus], xobject, None, xinfo ] )
            return errorcount

        xcustomcount: int = 0
        xusercount: int = 0
        xcounter: int = 0
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            # Get users
            xusers = self.__internal_get_all_active_users(True)
            # Get SAML providers list
            xldaps = self.cxsast.get('/cxrestapi/auth/ldapservers')
            # Register to inventory
            for ldap in xldaps :
                if ldap['active'] :
                    xcounter += 1
                    provid = self.__internal_get_identity_provider_id( ldap['name'], 'LDAP' )
                    # Check users count
                    xusercount = 0
                    if len(xusers) > 0 :
                        xusercount = len( list( filter( lambda el: el['authenticationProviderId'] == provid, xusers) ) )
                    xinfo = 'host: ' + ldap['host'] + ' - DN: ' + ldap['baseDn']
                    if xusercount > 1 :
                        xinfo = xinfo + ' (' + str(xusercount) + ' users)'
                        xstatus = SWARNING
                        xcustomcount += 1
                    elif xusercount == 1 :
                        xinfo = xinfo + ' (' + str(xusercount) + ' user)'
                        xstatus = SWARNING
                        xcustomcount += 1
                    else :
                        xinfo = xinfo + ' (no users)'
                        xstatus = SOK
                    self.__internal_write_config( [STATUS[xstatus], xobject, provid, ldap['name'], None, None, xinfo ], False )
            # Register index
            xstatus = SOK
            xinfo = None
            if xcounter > 0 :
                xinfo = 'manual configuration required'
                if xcustomcount == 0 :
                    xstatus = SOK
                else:
                    xstatus = SWARNING
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcounter) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_ac_domainsettings(self) :
        errorcount = 0
        inventory_name = 'access-control domain settings'
        xobject: str = OBJ_AC_DOMAIN
        xstatus: int = SWARNING
        xinfo: str = None

        if self.__noiam :
            xstatus = SWARNING
            xinfo = 'excluded by no-iam access-control option'
            self.__internal_write_summary( [STATUS[xstatus], xobject, None, xinfo ] )
            return errorcount

        xcustomcount: int = 0
        xusercount: int = 0
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            # Get users
            xusers = self.__internal_get_all_active_users(True)
            # Get Domain providers list
            xdomains = self.cxsast.get('/cxrestapi/auth/windowsdomains')
            # Register to inventory
            for domain in xdomains :
                provid = self.__internal_get_identity_provider_id( domain['name'], 'Domain' )
                # Check users count
                xusercount = 0
                if len(xusers) > 0 :
                    xusercount = len( list( filter( lambda el: el['authenticationProviderId'] == provid, xusers) ) )
                xinfo = 'fqdn: ' + domain['fullyQualifiedName']
                if xusercount > 1 :
                    xinfo = xinfo + ' (' + str(xusercount) + ' users)'
                    xstatus = SWARNING
                    xcustomcount += 1
                elif xusercount == 1 :
                    xinfo = xinfo + ' (' + str(xusercount) + ' user)'
                    xstatus = SWARNING
                    xcustomcount += 1
                else :
                    xinfo = xinfo + ' (no users)'
                    xstatus = SOK
                self.__internal_write_config( [STATUS[xstatus], xobject, provid, domain['name'], None, None, xinfo ], False )
            # Register index
            xstatus = SOK
            xinfo = None
            if len(xdomains) > 0 :
                xinfo = 'unsupported configuration'
                xstatus = SWARNING
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xdomains), xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(len(xdomains)) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_queries(self) :
        errorcount = 0
        inventory_name = 'queries'
        xobject: str = OBJ_QUERIES
        xstatus: int = SOK
        xinfo: str = None
        xteamname: str = None
        xteamid: int = None
        xparents: int = 0
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            xallqueries = self.__internal_get_all_queries()
            xallteams = self.__internal_get_all_teams(ignoreerrors = True)
            xteamscache = self.cxcaches.cache(CACHE_TEAMS)

            # Check custom corp queries
            xobject = OBJ_QUERIES_CORP
            xstatus = SOK
            xqueries = self.__internal_get_custom_queries('Corporate')
            xinfo = None
            # Register corp queries
            for query in xqueries :
                self.__internal_write_query( [STATUS[xstatus],
                                              query['QueryId'],
                                              query['PackageType'],
                                              query['LanguageName'],
                                              query['Name'],
                                              query['PackageFullName'],
                                              QSEVERITY[query['Severity']],
                                              None,
                                              None,
                                              None,
                                              xinfo ])
            # Register index
            xstatus = SOK
            xinfo = None
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xqueries), xinfo ] )

            # Check custom team queries
            xobject = OBJ_QUERIES_TEAM
            xstatus = SWARNING
            xqueries = self.__internal_get_custom_queries('Team')
            # Register corp queries
            for query in xqueries :
                xteamid = query['OwningTeam']
                xteamname = query['OwningTeamName']
                xparents = 0
                xinfo = None
                # Count parents
                if xteamname :
                    # Count hierachy (upwards)
                    parentqueries = list( filter( lambda el: el['LanguageName'] == query['LanguageName'] and el['Name'] == query['Name'] and
                                                 el['OwningTeamName'] is not None and el['OwningTeamName'].startswith(xteamname), xqueries ) )
                    if len(parentqueries) > 0 :
                        xparents = len(parentqueries) - 1
                elif xallteams and len(xallteams) > 0:
                    xinfo = 'orphan'
                if xparents > 0 :
                    if xinfo :
                        xinfo = xinfo + ' - ' + str(xparents) + ' parents'
                    else:
                        xinfo = str(xparents) + ' parents'
                self.__internal_write_query( [STATUS[xstatus],
                                              query['QueryId'],
                                              query['PackageType'],
                                              query['LanguageName'],
                                              query['Name'],
                                              query['PackageFullName'],
                                              QSEVERITY[query['Severity']],
                                              xteamid,
                                              xteamname,
                                              None,
                                              xinfo ])
                # Shall update teams query counters
                if xteamscache and len(xteamscache) > 0 and xteamname :
                    xteam = next( filter( lambda el: el['TEAM-ID'] == xteamid, xteamscache), None )
                    if xteam :
                        if not xteam['QUERY-USING'] :
                            xteam['QUERY-USING'] = 1
                        else :
                            xteam['QUERY-USING'] = xteam['QUERY-USING'] + 1
            # Register index
            if len(xqueries) > 0 :
                xstatus = SWARNING
                xinfo = 'team level queries require handling'
            else :
                xstatus = SOK
                xinfo = None
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xqueries), xinfo ] )

            # Check custom project queries
            xobject = OBJ_QUERIES_PROJ
            xstatus = SOK
            xqueries = self.__internal_get_custom_queries('Project')
            # Register project queries
            for query in xqueries :
                xinfo = None
                if not query['ProjectId'] :
                    xinfo = 'orphan'
                self.__internal_write_query( [STATUS[xstatus],
                                              query['QueryId'],
                                              query['PackageType'],
                                              query['LanguageName'],
                                              query['Name'],
                                              query['PackageFullName'],
                                              QSEVERITY[query['Severity']],
                                              query['ProjectId'],
                                              None,
                                              None,
                                              xinfo ])
            # Register index
            xstatus = SOK
            xinfo = None
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xqueries), xinfo ] )

            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(len(xallqueries)) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_presets(self) :
        errorcount = 0
        inventory_name = 'presets'
        xobject: str = OBJ_PRESETS
        xstatus: int = SWARNING
        xinfo: str = None
        xpresetid: int = 0
        xpresetname: str = None
        xisoriginal: bool = False
        xiscustomized: bool = None
        xpqrys: list = None
        xdqrys: list = None
        xcustomized: int = 0
        xpresettype: str = None
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            xpresets = self.cxsast.get('/cxrestapi/sast/presets')
            xdefaultpresets = sastdefaultpresets(self.cxsast.version())
            xallqueries: list[dict] = self.__internal_get_all_queries(ignoreerrors = True)

            # Populate presets with query ids
            for preset in xpresets :
                xpresetid = preset['id']
                xpresetname = preset['name']
                preset['queryIds'] = self.cxsast.get('/cxrestapi/sast/presets/' + str(preset['id']))['queryIds']

                # Is it a custom preset or a changed out-of-the-box preset
                defpreset = next( filter( lambda el: el['name'] == xpresetname, xdefaultpresets ), None )
                xisoriginal = defpreset is not None
                xiscustomized = not xisoriginal
                # Check if original was modified
                if xisoriginal :
                    xpqrys = set( preset['queryIds'] )
                    xdqrys = set( defpreset['queryIds'] )
                    xiscustomized = (len(list(xpqrys - xdqrys)) > 0) or (len(list(xdqrys - xpqrys)) > 0)
                else :
                    xpqrys = set( preset['queryIds'] )
                    xdqrys = []
                    xdqrys = set( xdqrys )
                # Check
                xstatus = SOK
                xinfo = None
                if not xisoriginal :
                    xcustomized += 1
                    xinfo = 'custom preset'
                    xstatus = SWARNING
                elif xiscustomized :
                    xcustomized += 1
                    xinfo = 'modified original preset'
                    xstatus = SWARNING

                # Write preset query data
                if xallqueries and len(xallqueries) > 0 :
                    if not xisoriginal :
                        xpresettype = PTYPE_CUSTOM
                    else :
                        xpresettype = PTYPE_OOB
                    # Queries that are on the preset but not the defaults
                    if xiscustomized :
                        xqueryids = list(xpqrys - xdqrys)
                    # Ordered query ids
                    xpresetqueries = list(xpqrys)

                    # Write preset query data (all queries)
                    for queryid in xpresetqueries :
                        query = next( filter( lambda el: el['QueryId'] == queryid, xallqueries ), None )
                        if query :
                            q_status = SOK
                            qq_status = QOK
                            if xiscustomized and queryid in xqueryids :
                                q_status = SWARNING
                                qq_status = QADDED
                            self.__internal_write_preset_query( [
                                            STATUS[q_status],
                                            xpresetid,
                                            xpresetname,
                                            xpresettype,
                                            QSTATUS[qq_status],
                                            queryid,
                                            query['Name'],
                                            query['LanguageName'],
                                            query['PackageName'],
                                            query['PackageTypeName']
                                        ] )
                    # Queries that are on the preset but not the defaults
                    if xiscustomized :
                        queryids = list(xdqrys - xpqrys)
                        q_status = SWARNING
                        qq_status = QMISSING
                        for queryid in queryids :
                            query = next( filter( lambda el: el['QueryId'] == queryid, xallqueries ), None )
                            if query :
                                self.__internal_write_preset_query( [
                                            STATUS[q_status],
                                            xpresetid,
                                            xpresetname,
                                            xpresettype,
                                            QSTATUS[qq_status],
                                            queryid,
                                            query['Name'],
                                            query['LanguageName'],
                                            query['PackageName'],
                                            query['PackageTypeName']
                                        ] )

                self.__internal_write_preset( [STATUS[xstatus], preset['id'], preset['name'], xpresettype, xiscustomized, None, xinfo ] )

            # Register index
            if xcustomized > 0 :
                xinfo = str(xcustomized) + ' customized or new presets exist'
                xstatus = SWARNING
            else :
                xinfo = None
                xstatus = SOK
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xpresets), xinfo ] )

            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(len(xpresets)) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_custom_categories(self) :
        errorcount = 0
        inventory_name = 'query categories'
        xobject: str = OBJ_QUERY_CATEGORIES
        xstatus: int = SOK
        xinfo: str = None
        xcustomized: int = 0
        xcategname: str = None
        xctypename: str = None
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            xcategories = self.cxsoap.getquerycategories()
            xdefaultcategories = sastdefaultcategories(self.cxsast.version())
            # Register to inventory
            for category in xcategories :
                xcategname = category['CategoryName']
                xctypename = category['CategoryType']['Name']
                if xctypename.startswith('ASD STIG') :
                    xctypename = 'ASD STIG'
                xdefault = next( filter( lambda el: el['CategoryName'] == xcategname and el['CategoryType']['Name'].startswith(xctypename), xdefaultcategories ), None )
                if not xdefault :
                    xstatus = SWARNING
                    xinfo = 'custom category found'
                    xcustomized += 1
                    self.__internal_write_custom_category( [STATUS[xstatus], category['Id'], xcategname, xinfo ] )
            # Register index
            if xcustomized > 0 :
                xinfo = str(xcustomized) + ' customized categories exist'
                xstatus = SWARNING
            else :
                xinfo = None
                xstatus = SOK
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcustomized, xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(len(xcategories)) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __internal_process_project_team(self, teamid: int) -> str :
        xteamname: str = None
        xteamscache: list[dict] = self.cxcaches.cache(CACHE_TEAMS)
        if xteamscache :
            xteam = next( filter( lambda el: el['TEAM-ID'] == teamid, xteamscache), None )
            if xteam :
                xusing = xteam['PROJ-USING']
                if not xusing :
                    xteam['PROJ-USING'] = 1
                else :
                    xteam['PROJ-USING'] = xusing + 1
                xteamname = xteam['TEAM-NAME']
        return xteamname


    def __internal_process_project_preset(self, presetid: int) -> tuple[str, str, bool] :
        xpresetname: str = None
        xpresettype: str = None
        xpresetcustom: bool = None
        xpresetscache: list[dict] = self.cxcaches.cache(CACHE_PRESETS)
        if xpresetscache :
            xpreset = next( filter( lambda el: el['PRESET-ID'] == presetid, xpresetscache), None )
            if xpreset :
                xusing = xpreset['PROJ-USING']
                if not xusing :
                    xpreset['PROJ-USING'] = 1
                else :
                    xpreset['PROJ-USING'] = xusing + 1
                xpresetname = xpreset['PRESET-NAME']
                xpresettype = xpreset['PRESET-TYPE']
                xpresetcustom = xpreset['CUSTOMIZED']
        return xpresetname, xpresettype, xpresetcustom


    def __internal_process_project_configuration_id(self, objtype: str, objid: int ) -> tuple[str, int] :
        xconfigname: str = None
        xconfigstatus: int = SOK
        xconfigscache: list[dict] = self.cxcaches.cache(CACHE_CONFIG)
        if xconfigscache :
            if objid :
                xconfig = next( filter( lambda el: el['OBJ-TYPE'] == objtype and el['OBJ-ID'] == objid, xconfigscache), None )
            else :
                xconfig = next( filter( lambda el: el['OBJ-TYPE'] == objtype, xconfigscache), None )
            if xconfig :
                xusing = xconfig['PROJ-USING']
                if not xusing :
                    xconfig['PROJ-USING'] = 1
                else :
                    xconfig['PROJ-USING'] = xusing + 1
                xconfigname = xconfig['OBJ-NAME']
                xconfigstatus = STATUS.index( xconfig['STATUS'] )
        return xconfigname, xconfigstatus


    def __internal_process_project_configuration_name(self, objtype: str, objname: str ) -> tuple[int, int] :
        xconfigid: int = None
        xconfigstatus: int = SOK
        xconfigscache: list[dict] = self.cxcaches.cache(CACHE_CONFIG)
        if xconfigscache :
            xconfig = next( filter( lambda el: el['OBJ-TYPE'] == objtype and el['OBJ-NAME'] == objname, xconfigscache), None )
            if xconfig :
                xusing = xconfig['PROJ-USING']
                if not xusing :
                    xconfig['PROJ-USING'] = 1
                else :
                    xconfig['PROJ-USING'] = xusing + 1
                xconfigid = xconfig['OBJ-ID']
                xconfigstatus = xconfig['STATUS']
        return xconfigid, xconfigstatus


    def __internal_process_project_scanconfigurations(self, projid: int) -> tuple[str, str, str, int, int, bool]:
        xerror: str = None
        xexisting: bool = False
        xreposettings: dict = None
        xrepositorytype: str = None
        xrepositorytypeuri: str = None
        xrepositoryurl: str = None
        xrepositorybranch: str = None
        xpostscanaction: int = None
        xprescanaction: int = None
        xemailnotifications: bool = None
        xauxdict: dict = None
        xsrcedict: dict = None
        xconfigscache: list[dict] = self.cxcaches.cache(CACHE_CONFIG)
        # Dont call if we do not have post-scan-actions or email server defined
        xexisting = ( next( filter( lambda el: el['OBJ-TYPE'] in [OBJ_POST_SCAN_ACTION, OBJ_SMTP_SETTINGS], xconfigscache), None ) is not None )
        if xexisting :
            try :
                xauxdict = self.cxsast.get('/cxrestapi/sast/scansettings/' + str(projid) )
                if xauxdict :
                    xpostscan = xauxdict.get('postScanAction')
                    if xpostscan :
                        xpostscanaction = xpostscan.get('id')
                    xemails = xauxdict.get('emailNotifications')
                    if xemails :
                        if ( len(xemails['failedScan']) + len(xemails['beforeScan']) + len(xemails['afterScan']) > 0 ):
                            xemailnotifications = True
            except Exception :
                xerror = 'unable to get scan settings for project ' + str(projid)
                cxlogger.debug(xerror)
                pass
            if xpostscanaction :
                self.__internal_process_project_configuration_id(OBJ_POST_SCAN_ACTION, xpostscanaction)
            if xemailnotifications :
                self.__internal_process_project_configuration_id(OBJ_SMTP_SETTINGS, None)

        # Get repository type, pre-scan-action, git-repo
        xerror = None
        try :
            xauxdict = self.cxsast.get('/cxrestapi/projects/' + str(projid) )
            if xauxdict :
                # Check source settings (address api version changes)
                if ('sourceSettingsLink' in xauxdict) and ('type' in xauxdict['sourceSettingsLink']) :
                    xsrcedict = xauxdict.get('sourceSettingsLink')
                    xrepositorytype = xsrcedict.get('type')
                    xrepositorytypeuri = xsrcedict.get('uri')
                elif ('links' in xauxdict) :
                    xsrcedict = next( filter( lambda el: el['rel'] == 'source', xauxdict['links'] ), None )
                    if xsrcedict :
                        xrepositorytype = xsrcedict.get('type')
                        xrepositorytypeuri = xsrcedict.get('uri')
                # Check for pre-scan action
                if (xrepositorytype == 'custom') and (xrepositorytypeuri) :
                    # Get pre-scan action id
                    try :
                        xreposettings = self.cxsast.get('/cxrestapi' + xrepositorytypeuri)
                        xprescanaction = xreposettings.get('pullingCommandId')
                    except Exception :
                        xprescanaction = None
                        pass
                    if self.__includerepos :
                        xrepositoryurl = xreposettings.get('path')
                elif (self.__includerepos) and (xrepositorytypeuri):
                    # Get git repo details
                    try :
                        xreposettings = self.cxsast.get('/cxrestapi' + xrepositorytypeuri )
                        xrepositoryurl = xreposettings.get('url')
                        if not xrepositoryurl :
                            xpaths: list[str] = xreposettings.get('paths')
                            if xpaths :
                                xrepositoryurl = SPLITTER.join(xpaths)
                        if not xrepositoryurl :
                            xuri: dict = xreposettings.get('uri')
                            if xuri :
                                xrepositoryurl = xuri.get('absoluteUrl')
                        xrepositorybranch = xreposettings.get('branch')
                        if xrepositorybranch :
                            xrepositorybranch = xrepositorybranch.replace('/refs/heads/', '')
                    except Exception :
                        xrepositoryurl = None
                        xrepositorybranch = None
                        pass

        except Exception :
            xerror = 'unable to get source code location settings for project ' + str(projid)
            cxlogger.debug(xerror)
            pass
        if xprescanaction :
            self.__internal_process_project_configuration_id(OBJ_PRE_SCAN_ACTION, xprescanaction)

        return xrepositorytype, xrepositoryurl, xrepositorybranch, xprescanaction, xpostscanaction, xemailnotifications


    def __internal_process_project_last_scan(self, projectid: int, fullscan: bool = True) -> dict :
        # Private scans are never included
        xscanslist: list = None
        xerror: str = None
        xfilter: str = ''
        if fullscan :
            xfilter = '((ProjectId eq ' + str(projectid) + ') and (IsPublic eq true) and (IsIncremental eq false))'
        else :
            xfilter = '((ProjectId eq ' + str(projectid) + ') and (IsPublic eq true))'
        try :
            xscanslist = self.cxsast.get('/Cxwebinterface/odata/v1/Scans?$top=1&$skip=0&$filter=' + xfilter + '&$expand=ScannedLanguages' )
        except Exception :
            xerror = 'unable to get last scan for project ' + str(projectid)
            cxlogger.debug(xerror)
            pass
        if xscanslist and len(xscanslist) > 0 :
            return xscanslist[0]
        else :
            return None


    def __internal_process_project_triages(self, scanid: int) -> tuple[int, int, str, str]:
        xtriages: int = None
        xcustomstates: int = None
        xtriageserror: str = None
        xcustomstateserror: str = None
        try :
            xtriages = int( self.cxsast.get('/Cxwebinterface/odata/v1/Scans(' + str(scanid) + ')/Results/$count?$filter=StateId gt 0 or Comment ne null' ) )
            if not xtriages or xtriages == 0 :
                xtriages = None
        except HTTPTimeout :
            xtriageserror = 't/o'
        except Exception :
            xtriageserror = 'n/p'
        # Go for custom states (only if triages also exist)
        if xtriages and not xtriageserror and self.__customstateid > 0 :
            xconfigcache: list = self.cxcaches.cache(CACHE_CONFIG)
            if xconfigcache and len(xconfigcache) :
                xstatescache = list( filter( lambda el: el['OBJ-TYPE'] == OBJ_RESULT_STATES and el['OBJ-ID'] >= self.__customstateid, xconfigcache) )
                try :
                    for xstate in xstatescache :
                        xtriagescustom = int( self.cxsast.get('/Cxwebinterface/odata/v1/Scans(' + str(scanid) + ')/Results/$count?$filter=StateId eq ' + str(xstate['OBJ-ID']) ) )
                        if xtriagescustom and xtriagescustom > 0 :
                            if not xcustomstates :
                                xcustomstates = xtriagescustom
                            else :
                                xcustomstates += xtriagescustom
                            if not xstate['PROJ-USING'] :
                                xstate['PROJ-USING'] = 1
                            else :
                                xstate['PROJ-USING'] = xstate['PROJ-USING'] + 1
                except HTTPTimeout :
                    xcustomstateserror = 't/o'
                except Exception :
                    xcustomstateserror = 'n/p'

        return xtriages, xcustomstates, xtriageserror, xcustomstateserror


    def __internal_process_project_queries(self, languages: list, projid: int, teamid: int, teamname: str ) -> tuple[int, int, int] :
        xqueriescorp: int = 0
        xqueriesteam: int = 0
        xqueriesproj: int = 0

        xqueriescache: list = self.cxcaches.cache(CACHE_QUERIES)
        if xqueriescache and languages and len(xqueriescache) > 0 and len(languages) > 0 :
            for language in languages :
                xlang: str = language.upper()

                # Check corp queries for this language
                xqueries = list( filter( lambda el: el['QUERY-PACKAGE-TYPE'] == 'Corporate' and el['QUERY-LANGUAGE'].upper() == xlang, xqueriescache) )
                for xquery in xqueries :
                    xusing = xquery['PROJ-USING']
                    if not xusing :
                        xquery['PROJ-USING'] = 1
                    else :
                        xquery['PROJ-USING'] = xusing + 1
                xqueriescorp += len(xqueries)

                # Check team queries for this language
                if teamid or teamname :
                    if teamname :
                        # Querys may be orphan, where they do not have names ...
                        xqueries = list( filter( lambda el: el['QUERY-PACKAGE-TYPE'] == 'Team' and el['QUERY-LANGUAGE'].upper() == xlang and el['REF-NAME'] and len(el['REF-NAME']) <= len(teamname) and teamname.startswith(el['REF-NAME']), xqueriescache) )
                    else :
                        xqueries = list( filter( lambda el: el['QUERY-PACKAGE-TYPE'] == 'Team' and el['QUERY-LANGUAGE'].upper() == xlang and el['REF-ID'] == teamid, xqueriescache) )
                    for xquery in xqueries :
                        xusing = xquery['PROJ-USING']
                        if not xusing :
                            xquery['PROJ-USING'] = 1
                        else :
                            xquery['PROJ-USING'] = xusing + 1
                    xqueriesteam += len(xqueries)

                # Check project queries for this language
                xqueries = list( filter( lambda el: el['QUERY-PACKAGE-TYPE'] == 'Project' and el['QUERY-LANGUAGE'].upper() == xlang and el['REF-ID'] == projid, xqueriescache) )
                for xquery in xqueries :
                    xusing = xquery['PROJ-USING']
                    if not xusing :
                        xquery['PROJ-USING'] = 1
                    else :
                        xquery['PROJ-USING'] = xusing + 1
                xqueriesproj += len(xqueries)

        if xqueriescorp <= 0 :
            xqueriescorp = None
        if xqueriesteam <= 0 :
            xqueriesteam = None
        if xqueriesproj <= 0 :
            xqueriesproj = None

        return xqueriescorp, xqueriesteam, xqueriesproj


    def __internal_process_project_counter(self, objname: str, valuename: str, status: int, value: int = 1) :
        xcounters: list = self.cxcaches.cache(CACHE_COUNTERS)
        xcounter: dict = None
        if len(xcounters) > 0 :
            xcounter = next( filter( lambda el: el['OBJ'] == objname and el['NAME'] == valuename, xcounters), None )
        if not xcounter :
            xcounters.append( { 'OBJ': objname, 'NAME': valuename, 'STATUS': status, 'COUNT': value })
        else :
            xcounter['COUNT'] = xcounter['COUNT'] + value


    def __internal_process_project_scan_origin(self, prescanaction: bool, sharedlocation: bool, plugin: str, origin: str ) -> int :
        xorigin: str = None
        xstatus: int = SOK
        xscanorigins: list = self.cxcaches.cache(CACHE_SCAN_ORIGINS)
        # Has pre-scan action ?
        if prescanaction :
            xorigin = "Pre-scan action"
        # Has shared location ?
        elif sharedlocation :
            xorigin = "Shared folder"
        # Has a plugin defined
        elif plugin :
            xorigin = plugin
        # Use origin
        else :
            xorigin = origin
        if xorigin :
            if xorigin in ["Pre-scan action", "Shared folder"] :
                xstatus = SDANGER
            elif (xorigin in ["CxFlow", "TFS", "VSTS", "SVN"]) or ("PERFORCE" in xorigin.upper()) :
                xstatus = SWARNING
            if not xscanorigins :
                xscanorigins = [ {"ORIGIN": xorigin, "COUNT": 1, "STATUS": xstatus} ]
                self.cxcaches.putcache(CACHE_SCAN_ORIGINS, xscanorigins)
            else :
                xscanorigin = next( filter( lambda el: el["ORIGIN"] == xorigin, xscanorigins), None )
                if xscanorigin :
                    xscanorigin["COUNT"] = int(xscanorigin["COUNT"]) + 1
                else :
                    xscanorigins.append( {"ORIGIN": xorigin, "COUNT": 1, "STATUS": xstatus } )
        return xstatus


    def __internal_process_project(self, project: dict) :
        # Status and control
        xstatus: int = SOK
        xnotes: list[str] = []
        xinfo: str = None

        # Caches
        xprojectnamescache: list[str] = self.cxcaches.cache(CACHE_PROJ_NAMES)
        xprojectduplicatedcache: list[str] = self.cxcaches.cache(CACHE_PROJ_DUPLICATED)

        # Auxiliary variables
        xauxdict: dict = None
        xauxint: int = None
        xauxstr: str = None

        # The variables holding the project output elements fields
        xprojid: int = project.get('Id')
        xprojname: str = project.get('Name')
        xprojduplicated: bool = None
        xprojpublic: bool = project.get('IsPublic')
        # If the project id is missing or the project is not public, go out
        if (not xprojid) or (not xprojpublic) :
            return
        xprojcreated: str = self.__dateparse( project.get('CreatedDate') )
        xtotalscans: int = project.get('TotalProjectScanCount')
        # Log debug we are checking this projects
        cxlogger.debug( 'Processing project [' + str(xprojid) + '] ' + str(xprojname) )
        # Team
        xteamid: int = project.get('OwningTeamId')
        xteamname: str = None
        # Preset
        xpresetid: int = project.get('PresetId')
        xpresetname: str = None
        xpresettype: str = None
        xpresetcustom: bool = None
        # Engine config
        xengineconfigid: int = project.get('EngineConfigurationId')
        xengineconfigname: str = None
        xengineconfigcustom: bool = False
        # Configurations common
        xcustomfieldsnames: list[str] = None
        xcustomfieldscount: int = None
        xissuetrackingid: int = None
        xscheduledscans: bool = None
        xexcludedfiles: str = None
        xexcludedfolders: str = None
        xexcludedglob: str = None
        # Configurations if scan data not excluded
        xrepositorytype: str = None
        xrepositoryurl: str = None          # From remote settings if repos included
        xrepositorybranch: str = None       # From remote settings if repos included
        xsharedlocation: bool = None
        xprescanaction: str = None
        xpostscanaction: str = None
        xemailnotifications: bool = None
        # Queries if scan data not excluded
        xqueriescorp: int = None
        xqueriesteam: int = None
        xqueriesproj: int = None
        # Scan and scan configurations if scan data not excluded
        xscanplugin: str = None
        xlastscanid: int = None
        xlastscandate: str = None
        xlastscanfull: bool = None
        xlastscanorigin: str = None
        xlastscanloc: int = None
        xlastscanlanguageslist: list[str] = None
        xlastscanlanguages: str = None
        # Results if scan data not excluded
        xresultstotal: int = None
        xresultscritical: int = None
        xresultshigh: int = None
        xresultsmedium: int = None
        xresultslow: int = None
        xresultsinfo: int = None
        # Triages if scan data / triages not excluded
        xtriagescount: int = None
        xcustomstatescount: int = None
        xtriageserror: str = None
        xcustomstateserror: str = None

        # Check for duplicated project name
        if xprojname.upper() in xprojectnamescache :
            xprojduplicated = True
            xprojectduplicatedcache.append(xprojname.upper())
            xnotes.append( 'duplicated name' )
            xstatus = SWARNING if xstatus < SWARNING else xstatus
        xprojectnamescache.append(xprojname.upper())

        # Process team
        xteamname = self.__internal_process_project_team(xteamid)
        if not xteamname :
            xauxdict = project.get('OwningTeam')
            if xauxdict :
                xteamname = xauxdict.get('FullName')
                if xteamname :
                    xteamname = '/' + xteamname.replace('\\', '/')
        if not xteamname :
            xnotes.append( 'unresolved team' )
            xstatus = SWARNING if xstatus < SWARNING else xstatus

        # Process preset
        xpresetname, xpresettype, xpresetcustom = self.__internal_process_project_preset(xpresetid)
        if xpresettype == PTYPE_CUSTOM :
            xnotes.append( 'custom preset' )
            xstatus = SWARNING if xstatus < SWARNING else xstatus
        elif xpresetcustom :
            xnotes.append( 'customized standard preset' )
            xstatus = SDANGER if xstatus < SDANGER else xstatus

        # Process engine config
        if xengineconfigid :
            xengineconfigcustom = False
            xengineconfigname, xauxint = self.__internal_process_project_configuration_id(OBJ_ENGINE_CONFIG, xengineconfigid)
            if not xauxint == SOK :
                xengineconfigcustom = True
            if xengineconfigcustom :
                xnotes.append( 'custom engine configuration' )
                xstatus = SDANGER if xstatus < SDANGER else xstatus

        # Process custom fields
        xcustomfields: list = project.get('CustomFields')
        if xcustomfields and len(xcustomfields) > 0 :
            xcustomfieldscount = len(xcustomfields)
            xcustomfieldsnames = []
            for field in xcustomfields :
                xcustomfieldsnames.append(field['FieldName'])
                self.__internal_process_project_configuration_name(OBJ_CUSTOM_FIELDS, field['FieldName'])

        # Process issue tracker
        xauxstr: str = project.get('IssueTrackingSettings')
        if xauxstr :
            try:
                xtracker = json.loads(xauxstr)
                if xtracker and (xtracker['TrackingSystemID']) and (xtracker['TrackingSystemID'] > 0) :
                    xissuetrackingid = xtracker['TrackingSystemID']
                if not xissuetrackingid :
                    xissuetrackingid = None
                else :
                    self.__internal_process_project_configuration_id(OBJ_ISSUE_TRACKER, xissuetrackingid)
                    xnotes.append( 'issue tracker configured' )
                    xstatus = SWARNING if xstatus < SWARNING else xstatus
            except Exception :
                pass

        # Process scheduled scans
        if project.get('SchedulingExpression') is not None :
            xscheduledscans = True
            xnotes.append( 'scheduled scans configured' )
            xstatus = SWARNING if xstatus < SWARNING else xstatus

        # Process exclusions
        xexcludedfiles = project.get('ExcludedFiles')
        xexcludedfolders = project.get('ExcludedFolders')
        # Exclusions, 9.6.1 up
        xexcludedglob = project.get('PathFilter')
        # Workaround for case #00187800
        if (not xexcludedglob) and ('PathFilter' in project.keys()) :
            xerror = None
            try :
                xauxdict = self.cxsast.get('/cxrestapi/projects/' + str(xprojid) + '/sourcecode/pathfilter', apiversion = '5.0' )
                if xauxdict :
                    xexcludedglob = xauxdict['pathFilter']
            except Exception as e :
                xerror = 'unable to get pathfilter data for project ' + str(xprojid) + ' with ' + str(e)
                cxlogger.debug(xerror)
                pass
        # Convert enxclusions to glob if needed
        if (xexcludedfiles or xexcludedfolders) :
            xnotes.append( 'wrong exclusions format' )
            xstatus = SWARNING if xstatus < SWARNING else xstatus
            if not xexcludedglob  :
                xexcludedglob = GlobFilters.getfilters(xexcludedfiles, xexcludedfolders)

        # The next data retrieval only runs if scan information is not excluded
        if not self.__noscandata :

            # Is it a shared location
            xauxstr = project.get('SourcePath')
            if xauxstr and xauxstr.startswith('\\\\') :
                if project.get('SourceProviderCredentials') :
                    xsharedlocation = True
                    xnotes.append( 'using shared folder' )
                    xstatus = SDANGER if xstatus < SDANGER else xstatus

            xrepositorytype, xrepositoryurl, xrepositorybranch, xprescanaction, xpostscanaction, xemailnotifications = self.__internal_process_project_scanconfigurations(xprojid)
            if (xprescanaction) :
                xnotes.append( 'using pre-scan action' )
                xstatus = SDANGER if xstatus < SDANGER else xstatus
            if (xpostscanaction) :
                xnotes.append( 'using post-scan action' )
                xstatus = SWARNING if xstatus < SWARNING else xstatus
            if (xemailnotifications) :
                xnotes.append( 'using email notifications' )
                xstatus = SWARNING if xstatus < SWARNING else xstatus

            # Get the project's last full scan
            xauxdict = None
            xlastscan = project.get('LastScan')
            if xlastscan :
                if not xlastscan['IsPublic'] :
                    xlastscan = None
                elif xlastscan['IsIncremental'] :
                    xauxdict = xlastscan
                    xlastscan = None
            if not xlastscan and xtotalscans > 0:
                xlastscan = self.__internal_process_project_last_scan(projectid = xprojid, fullscan = True)
            if not xlastscan :
                if xauxdict :
                    xlastscan = xauxdict
                elif xtotalscans > 0 :
                    xlastscan = self.__internal_process_project_last_scan(projectid = xprojid, fullscan = False)
                if xlastscan :
                    xlastscanfull = False
            else :
                xlastscanfull = True

            # Collect the scan elements
            if xlastscan :
                xlastscanid = project.get('LastScanId')
                xlastscandate = self.__dateparse( xlastscan.get('ScanRequestedOn') )
                xlastscanorigin = xlastscan.get('Origin')
                xlastscanloc = xlastscan.get('LOC')
                xlanguages: list = xlastscan.get('ScannedLanguages')
                if xlanguages and len(xlanguages) > 0:
                    xlastscanlanguageslist = []
                    try :
                        for language in xlanguages :
                            xlang = language.get('LanguageName')
                            if xlang :
                                xlastscanlanguageslist.append(xlang)
                        xlastscanlanguageslist.sort()
                    except Exception :
                        pass
                    if len(xlastscanlanguageslist) > 0 :
                        xlastscanlanguages = SPLITTER.join(xlastscanlanguageslist)
                    else :
                        xlastscanlanguageslist = None
                xresultstotal = xlastscan.get('TotalVulnerabilities')
                xresultscritical = xlastscan.get('Critical')
                xresultshigh = xlastscan.get('High')
                xresultsmedium = xlastscan.get('Medium')
                xresultslow = xlastscan.get('Low')
                xresultsinfo = xlastscan.get('Info')

            # Triages, just find one
            if xlastscanid and not self.__notriages :
                xtriagescount, xcustomstatescount, xtriageserror, xcustomstateserror = self.__internal_process_project_triages(xlastscanid)
                if xtriageserror :
                    xtriagescount = xtriageserror
                if xcustomstateserror :
                    xcustomstatescount = xcustomstateserror

            # Plugin
            if xlastscanorigin :
                if xlastscanorigin.upper().startswith('TEAMCITY') :
                    xscanplugin = 'TeamCity'
                elif xlastscanorigin.upper().startswith('JENKINS') :
                    xscanplugin = 'Jenkins'
                elif xlastscanorigin.upper().startswith('TFS') :
                    xscanplugin = 'TFS'
                elif xlastscanorigin.upper().startswith('ADO') :
                    xscanplugin = 'ADO'
                elif xlastscanorigin.upper().startswith('CXFLOW') :
                    xscanplugin = 'CxFlow'
                    xnotes.append( 'using CxFlow' )
                    xstatus = SWARNING if xstatus < SWARNING else xstatus

            # Queries
            xqueriescorp, xqueriesteam, xqueriesproj = self.__internal_process_project_queries(xlastscanlanguageslist, xprojid, xteamid, xteamname )
            if xqueriesteam :
                xnotes.append( 'team level queries' )
                xstatus = SWARNING if xstatus < SWARNING else xstatus

            # Check LOC
            if xlastscanloc and xlastscanloc > MAX_LOC_VAL :
                xnotes.append( 'loc above ' + MAX_LOC_TXT )
                xstatus = SDANGER if xstatus < SDANGER else xstatus

            # Cache scan origins
            self.__internal_process_project_scan_origin(xprescanaction, xsharedlocation, xscanplugin, xlastscanorigin )

        # Cache counters / constraints

        # Check project is private
        if not xprojpublic :
            self.__internal_process_project_counter( OBJ_PROJECTS, 'private projects', SWARNING, 1)
        # Check team name is missing (orphan)
        if not xteamname :
            self.__internal_process_project_counter( OBJ_PROJECTS, 'unresolved team names', SWARNING, 1)
        # Check modified out of the box preset
        if xpresettype == PTYPE_OOB and xpresetcustom :
            self.__internal_process_project_counter( OBJ_PROJECTS, 'modified standard preset', SDANGER, 1)
        # Check custom preset
        if xpresettype == PTYPE_CUSTOM :
            self.__internal_process_project_counter( OBJ_PROJECTS, 'custom preset', SWARNING, 1)
        # Check engine configuration is custom
        if xengineconfigcustom :
            self.__internal_process_project_counter( OBJ_PROJECTS, 'custom engine configuration', SDANGER, 1)
        # Check email notifications
        if xemailnotifications :
            self.__internal_process_project_counter( OBJ_PROJECTS, 'using email notifications', SWARNING, 1)
        # Check issue tracker
        if xissuetrackingid :
            self.__internal_process_project_counter( OBJ_PROJECTS, 'using issue tracker', SWARNING, 1)
        # Check scheduled scans
        if xscheduledscans :
            self.__internal_process_project_counter( OBJ_PROJECTS, 'using scheduled scans', SWARNING, 1)
        # Check pre-scan action
        if xprescanaction :
            self.__internal_process_project_counter( OBJ_PROJECTS, 'using pre-scan action', SDANGER, 1)
        # Check shared folder
        if xsharedlocation :
            self.__internal_process_project_counter( OBJ_PROJECTS, 'using shared folder', SDANGER, 1)
        # Check post-scan action
        if xpostscanaction :
            self.__internal_process_project_counter( OBJ_PROJECTS, 'using post-scan action', SWARNING, 1)
        # Check unsupported repository location
        if xrepositorytype and xrepositorytype not in ['local', 'custom', 'git'] :
            self.__internal_process_project_counter( OBJ_PROJECTS, 'unsupported repository type', SDANGER, 1)
        # Check custom team queries in use
        if xqueriesteam :
            self.__internal_process_project_counter( OBJ_PROJECTS, 'using team level queries', SWARNING, 1)
        # Check a full scan was found
        if not xlastscanid and not self.__noscandata :
            self.__internal_process_project_counter( OBJ_PROJECTS, 'no full scan found', SWARNING, 1)
        # Check origin uses CxFlow
        if xscanplugin and xscanplugin == "CxFlow" :
            self.__internal_process_project_counter( OBJ_PROJECTS, 'using CxFlow', SWARNING, 1)
        # Check triages with custom states
        if not xcustomstateserror and xcustomstatescount and xcustomstatescount > 0 :
            self.__internal_process_project_counter( OBJ_PROJECTS, 'triages with custom states', SDANGER, 1)
        # Max LOC passed
        if xlastscanloc and xlastscanloc > MAX_LOC_VAL :
            self.__internal_process_project_counter( OBJ_PROJECTS, 'loc above ' + MAX_LOC_TXT, SWARNING, 1)

        # Mount info from notes
        if len(xnotes) > 0 :
            xinfo = NOTESSPLITTER.join(xnotes)

        # Write it to csv
        if not self.__projshandler :
            filename = self.__datapath + os.sep + OUT_PROJECTS
            self.__projshandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__projswriter = csv.writer(self.__projshandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__projswriter.writerow(CSV_PROJECTS)
        # Write it
        self.__projswriter.writerow( [ STATUS[xstatus], xprojid, xprojname, xprojduplicated, xprojpublic, xprojcreated, xtotalscans,
                                    xteamid, xteamname, xpresetname, xengineconfigname,
                                    xcustomfieldscount, xissuetrackingid, xscheduledscans,
                                    xexcludedfiles, xexcludedfolders, xexcludedglob,
                                    xemailnotifications, xprescanaction, xpostscanaction, xsharedlocation,
                                    xqueriescorp, xqueriesteam, xqueriesproj,
                                    xrepositorytype, xrepositoryurl, xrepositorybranch,
                                    xscanplugin, xlastscanorigin,
                                    xlastscanid, xlastscandate, xlastscanfull,
                                    xlastscanloc, xlastscanlanguages,
                                    xresultstotal, xresultscritical, xresultshigh, xresultsmedium, xresultslow, xresultsinfo,
                                    xtriagescount, xcustomstatescount, xinfo
                                    ] )


    def __inventory_projects(self) :
        errorcount = 0
        inventory_name = 'projects'
        xobject: str = OBJ_PROJECTS
        xstatus: int = SOK
        xinfo: str = None
        # xodataskip: int = 0
        xcounter: int = 0
        xprojectcount: int = 0
        xprojectid: int = 0
        xodatafilter: str = None
        xodatafilterstart: str = ''
        xodatafilternext: str = ''
        xgo: bool = True
        # Init internal caches for project names duplicate checks and counters
        self.cxcaches.putcache( CACHE_PROJ_NAMES, [] )
        self.cxcaches.putcache( CACHE_PROJ_DUPLICATED, [] )
        self.cxcaches.putcache( CACHE_COUNTERS, [] )
        xstarted = CxDatetime.now()
        if self.__noscandata :
            cxlogger.info( 'Processing ' + inventory_name + ' without scan data' )
        else :
            cxlogger.info( 'Processing ' + inventory_name )
        try:
            # Count projects
            xprojectcount = self.cxsast.get('/Cxwebinterface/odata/v1/Projects/$count')
            cxlogger.info('Counted ' + str(xprojectcount) + ' total projects (unfiltered) ... ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )

            xprjstarted = CxDatetime.now()

            # Check filter and filter kind
            if (self.__projectfilter) :
                if not isinstance(self.__projectfilter, list) :
                    xodatafilter = CxParamFilters.processodatafilter(self.__projectfilter, odatafield = "Id", prefixed = False)
                    xodatafilterstart = '&$filter=(' + xodatafilter + ')'
                    xodatafilternext = ' and (' + xodatafilter + ')'

            # If projects are filtered, decide if we go one by one or check the filter in bulk
            if (self.__projectfilter) and isinstance(self.__projectfilter, list) and ( (len(self.__projectfilter) <= 5) or ( (len(self.__projectfilter) < 100) and (int(xprojectcount) > 1000) ) ) :
                for projectid in self.__projectfilter :
                    if self.__noscandata :
                        xprojects = self.cxsast.get('/Cxwebinterface/odata/v1/Projects/' + str(projectid) + '?$expand=Preset,CustomFields,OwningTeam' )
                    else :
                        xprojects = self.cxsast.get('/Cxwebinterface/odata/v1/Projects/' + str(projectid) + '?$expand=Preset,CustomFields,OwningTeam,LastScan($expand=ScannedLanguages)' )
                    for project in xprojects :
                        self.__internal_process_project(project)
                        xcounter += 1
            else :
                # Use paged ODATA to retrieve projects, with related data
                # Use projectid in filter (where clause) is more efficient than skip
                if self.__noscandata :
                    xprojects = self.cxsast.get('/Cxwebinterface/odata/v1/Projects?$top=100' + xodatafilterstart + '&$expand=Preset,CustomFields,OwningTeam' )
                else :
                    xprojects = self.cxsast.get('/Cxwebinterface/odata/v1/Projects?$top=100' + xodatafilterstart + '&$expand=Preset,CustomFields,OwningTeam,LastScan($expand=ScannedLanguages)' )
                while len(xprojects) > 0 :
                    # Process each project
                    for project in xprojects :
                        xprojectid = project['Id']
                        # Shall apply filters ?
                        xgo = True
                        if (self.__projectfilter) and isinstance(self.__projectfilter, list) :
                            xgo = (xprojectid in self.__projectfilter) or (str(xprojectid) in self.__projectfilter)
                        if xgo :
                            self.__internal_process_project(project)
                            xcounter += 1
                    # Log page time
                    if self.__projectfilter :
                        cxlogger.info('Processed ' + str(xcounter) + ' of ' + str(xprojectcount) + ' filtered projects ... ' + CxDatetime.elapsed(xprjstarted, hoursonly = True) + ' secs' )
                    else :
                        cxlogger.info('Processed ' + str(xcounter) + ' of ' + str(xprojectcount) + ' projects ... ' + CxDatetime.elapsed(xprjstarted, hoursonly = True) + ' secs' )
                    # Go for next page (if any)
                    # xodataskip += 100
                    xprjstarted = CxDatetime.now()
                    if len(xprojects) < 100 :
                        xprojects = []
                    else :
                        if self.__noscandata :
                            xprojects = self.cxsast.get('/Cxwebinterface/odata/v1/Projects?$top=100&$filter=(Id gt ' + str(xprojectid) + ')' + xodatafilternext + '&$expand=Preset,CustomFields,OwningTeam' )
                        else :
                            xprojects = self.cxsast.get('/Cxwebinterface/odata/v1/Projects?$top=100&$filter=(Id gt ' + str(xprojectid) + ')' + xodatafilternext + '&$expand=Preset,CustomFields,OwningTeam,LastScan($expand=ScannedLanguages)' )

            # Clear unneeded cache
            self.cxcaches.uncache( CACHE_PROJ_NAMES )
            # Register index
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcounter) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxsast.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_process_duplicates(self) :
        errorcount: int = 0
        xduplicates = self.cxcaches.cache(CACHE_PROJ_DUPLICATED)
        if xduplicates and len(xduplicates) > 0 :
            xduplicatescount: int = 0
            inventory_name = 'duplicated projects'
            csvreader: int = None
            csvwriter: int = None
            datafile: str = None
            tempfile: str = None
            xproject: dict = None
            xprojectname: str = None
            xstarted = CxDatetime.now()
            cxlogger.info( 'Processing ' + inventory_name )

            try:
                datafile = self.__datapath + os.sep + OUT_PROJECTS
                tempfile = self.__datapath + os.sep + '_' + OUT_PROJECTS
                auxfile = self.__datapath + os.sep + '__' + OUT_PROJECTS
                csvreader = self.cxcsv.csvopenread(datafile)
                csvwriter = self.cxcsv.csvopenwrite(tempfile)
                xproject = self.cxcsv.csvread(csvreader)

                # Process the projects list
                while xproject :
                    xprojectname = str(xproject.get('NAME')).upper()
                    if xprojectname in xduplicates :
                        xduplicatescount += 1
                        xproject['DUPLICATED'] = True
                        if xproject['STATUS'] == STATUS[SOK] :
                            xproject['STATUS'] = STATUS[SWARNING]
                        if xproject['NOTES'] :
                            if 'duplicated name' not in xproject['NOTES'] :
                                xproject['NOTES'] = 'duplicated name' + NOTESSPLITTER + xproject['NOTES']
                        else :
                            xproject['NOTES'] = 'duplicated name'
                        # Update constraints
                        self.__internal_process_project_counter( OBJ_PROJECTS, 'duplicated names', SWARNING, 1)
                    # Write it to temp
                    self.cxcsv.csvwrite(csvwriter, xproject)
                    # Go for the next
                    xproject = self.cxcsv.csvread(csvreader)

                # Reset files
                self.cxcsv.csvclose(csvreader)
                self.cxcsv.csvclose(csvwriter)
                csvreader = None
                csvwriter = None
                os.rename(datafile, auxfile)
                os.rename(tempfile, datafile)
                if os.path.exists(auxfile) :
                    os.remove(auxfile)

            except Exception as e:
                errorcount += 1
                cxlogger.exception( e, level = DEBUG )
                cxlogger.error('failed to process duplicated projects')
            finally :
                if csvreader :
                    self.cxcsv.csvclose(csvreader)
                if csvwriter :
                    self.cxcsv.csvclose(csvwriter)
            # Clear unneeded cache
            self.cxcaches.uncache(CACHE_PROJ_DUPLICATED)
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xduplicatescount) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )

        return errorcount


    def __inventory_process_config_counters(self) :
        errorcount: int = 0
        xcache = self.cxcaches.cache(CACHE_CONFIG)
        if xcache and len(xcache) > 0 :
            xcount: int = 0
            inventory_name = 'config counters'
            csvreader: int = None
            csvwriter: int = None
            datafile: str = None
            tempfile: str = None
            xobject: dict = None
            xcacheobj: dict = None
            xstarted = CxDatetime.now()
            cxlogger.info( 'Processing ' + inventory_name )

            try:
                datafile = self.__datapath + os.sep + OUT_CONFIG
                tempfile = self.__datapath + os.sep + '_' + OUT_CONFIG
                auxfile = self.__datapath + os.sep + '__' + OUT_CONFIG
                csvreader = self.cxcsv.csvopenread(datafile)
                csvwriter = self.cxcsv.csvopenwrite(tempfile)
                xobject = self.cxcsv.csvread(csvreader)

                # Process the counters list
                while xobject :
                    # Find the counter
                    xcacheobj = next( filter( lambda el: el['OBJ-TYPE'] == xobject['OBJ-TYPE'] and el['OBJ-ID'] == xobject['OBJ-ID'] and el['OBJ-NAME'] == xobject['OBJ-NAME'], xcache ), None )
                    if xcacheobj and xcacheobj['PROJ-USING'] :
                        xcount += 1
                        xobject['PROJ-USING'] = xcacheobj['PROJ-USING']
                    # Write it to temp
                    self.cxcsv.csvwrite(csvwriter, xobject)
                    # Go for the next
                    xobject = self.cxcsv.csvread(csvreader)

                # Reset files
                self.cxcsv.csvclose(csvreader)
                self.cxcsv.csvclose(csvwriter)
                csvreader = None
                csvwriter = None
                CxDatetime.sleep(0.01)    # Give OS some breath for file IO operations
                os.rename(datafile, auxfile)
                CxDatetime.sleep(0.01)    # Give OS some breath for file IO operations
                os.rename(tempfile, datafile)
                CxDatetime.sleep(0.01)    # Give OS some breath for file IO operations
                if os.path.exists(auxfile) :
                    os.remove(auxfile)

            except Exception as e:
                errorcount += 1
                cxlogger.exception( e, level = DEBUG )
                cxlogger.error('failed to process configuration counters')
            finally :
                if csvreader :
                    self.cxcsv.csvclose(csvreader)
                if csvwriter :
                    self.cxcsv.csvclose(csvwriter)
            # Clear unneeded cache
            self.cxcaches.uncache(CACHE_CONFIG)
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcount) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )

        return errorcount


    def __inventory_process_teams_counters(self) :
        errorcount: int = 0
        xcache = self.cxcaches.cache(CACHE_TEAMS)
        if xcache and len(xcache) > 0 :
            xcount: int = 0
            inventory_name = 'teams counters'
            csvreader: int = None
            csvwriter: int = None
            datafile: str = None
            tempfile: str = None
            xobject: dict = None
            xcacheobj: dict = None
            xstarted = CxDatetime.now()
            cxlogger.info( 'Processing ' + inventory_name )

            try:
                datafile = self.__datapath + os.sep + OUT_ACTEAMS
                tempfile = self.__datapath + os.sep + '_' + OUT_ACTEAMS
                auxfile = self.__datapath + os.sep + '__' + OUT_ACTEAMS
                csvreader = self.cxcsv.csvopenread(datafile)
                csvwriter = self.cxcsv.csvopenwrite(tempfile)
                xobject = self.cxcsv.csvread(csvreader)

                # Process the counters list
                while xobject :
                    # Find the counter
                    xcacheobj = next( filter( lambda el: el['TEAM-ID'] == xobject['TEAM-ID'] and el['TEAM-NAME'] == xobject['TEAM-NAME'], xcache ), None )
                    if xcacheobj and ( xcacheobj['PROJ-USING'] or xcacheobj['PROJ-USING'] ):
                        xcount += 1
                        xobject['PROJ-USING'] = xcacheobj['PROJ-USING']
                        xobject['QUERY-USING'] = xcacheobj['QUERY-USING']
                    # Write it to temp
                    self.cxcsv.csvwrite(csvwriter, xobject)
                    # Go for the next
                    xobject = self.cxcsv.csvread(csvreader)

                # Reset files
                self.cxcsv.csvclose(csvreader)
                self.cxcsv.csvclose(csvwriter)
                csvreader = None
                csvwriter = None
                CxDatetime.sleep(0.01)    # Give OS some breath for file IO operations
                os.rename(datafile, auxfile)
                CxDatetime.sleep(0.01)    # Give OS some breath for file IO operations
                os.rename(tempfile, datafile)
                CxDatetime.sleep(0.01)    # Give OS some breath for file IO operations
                if os.path.exists(auxfile) :
                    os.remove(auxfile)

            except Exception as e:
                errorcount += 1
                cxlogger.exception( e, level = DEBUG )
                cxlogger.error('failed to process teams counters')
            finally :
                if csvreader :
                    self.cxcsv.csvclose(csvreader)
                if csvwriter :
                    self.cxcsv.csvclose(csvwriter)
            # Clear unneeded cache
            self.cxcaches.uncache(CACHE_TEAMS)
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcount) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )

        return errorcount


    def __inventory_process_queries_counters(self) :
        errorcount: int = 0
        xcache = self.cxcaches.cache(CACHE_QUERIES)
        if xcache and len(xcache) > 0 :
            xcount: int = 0
            inventory_name = 'queries counters'
            csvreader: int = None
            csvwriter: int = None
            datafile: str = None
            tempfile: str = None
            xobject: dict = None
            xcacheobj: dict = None
            xstarted = CxDatetime.now()
            cxlogger.info( 'Processing ' + inventory_name )

            try:
                datafile = self.__datapath + os.sep + OUT_QUERIES
                tempfile = self.__datapath + os.sep + '_' + OUT_QUERIES
                auxfile = self.__datapath + os.sep + '__' + OUT_QUERIES
                csvreader = self.cxcsv.csvopenread(datafile)
                csvwriter = self.cxcsv.csvopenwrite(tempfile)
                xobject = self.cxcsv.csvread(csvreader)

                # Process the counters list
                while xobject :
                    # Find the counter
                    xcacheobj = next( filter( lambda el: el['QUERY-PACKAGE-TYPE'] == xobject['QUERY-PACKAGE-TYPE'] and el['QUERY-ID'] == xobject['QUERY-ID'] and el['QUERY-NAME'] == xobject['QUERY-NAME'] and el['QUERY-LANGUAGE'] == xobject['QUERY-LANGUAGE'], xcache ), None )
                    if xcacheobj and xcacheobj['PROJ-USING'] :
                        xcount += 1
                        xobject['PROJ-USING'] = xcacheobj['PROJ-USING']
                    # Write it to temp
                    self.cxcsv.csvwrite(csvwriter, xobject)
                    # Go for the next
                    xobject = self.cxcsv.csvread(csvreader)

                # Reset files
                self.cxcsv.csvclose(csvreader)
                self.cxcsv.csvclose(csvwriter)
                csvreader = None
                csvwriter = None
                CxDatetime.sleep(0.01)    # Give OS some breath for file IO operations
                os.rename(datafile, auxfile)
                CxDatetime.sleep(0.01)    # Give OS some breath for file IO operations
                os.rename(tempfile, datafile)
                CxDatetime.sleep(0.01)    # Give OS some breath for file IO operations
                if os.path.exists(auxfile) :
                    os.remove(auxfile)

            except Exception as e:
                errorcount += 1
                cxlogger.exception( e, level = DEBUG )
                cxlogger.error('failed to process queries counters')
            finally :
                if csvreader :
                    self.cxcsv.csvclose(csvreader)
                if csvwriter :
                    self.cxcsv.csvclose(csvwriter)
            # Clear unneeded cache
            self.cxcaches.uncache(CACHE_QUERIES)
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcount) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )

        return errorcount


    def __inventory_process_presets_counters(self) :
        errorcount: int = 0
        xcache = self.cxcaches.cache(CACHE_PRESETS)
        if xcache and len(xcache) > 0 :
            xcount: int = 0
            inventory_name = 'presets counters'
            csvreader: int = None
            csvwriter: int = None
            datafile: str = None
            tempfile: str = None
            xobject: dict = None
            xcacheobj: dict = None
            xstarted = CxDatetime.now()
            cxlogger.info( 'Processing ' + inventory_name )

            try:
                datafile = self.__datapath + os.sep + OUT_PRESETS
                tempfile = self.__datapath + os.sep + '_' + OUT_PRESETS
                auxfile = self.__datapath + os.sep + '__' + OUT_PRESETS
                csvreader = self.cxcsv.csvopenread(datafile)
                csvwriter = self.cxcsv.csvopenwrite(tempfile)
                xobject = self.cxcsv.csvread(csvreader)

                # Process the counters list
                while xobject :
                    # Find the counter
                    xcacheobj = next( filter( lambda el: el['PRESET-ID'] == xobject['PRESET-ID'] and el['PRESET-NAME'] == xobject['PRESET-NAME'], xcache ), None )
                    if xcacheobj and xcacheobj['PROJ-USING'] :
                        xcount += 1
                        xobject['PROJ-USING'] = xcacheobj['PROJ-USING']
                    # Write it to temp
                    self.cxcsv.csvwrite(csvwriter, xobject)
                    # Go for the next
                    xobject = self.cxcsv.csvread(csvreader)

                # Reset files
                self.cxcsv.csvclose(csvreader)
                self.cxcsv.csvclose(csvwriter)
                csvreader = None
                csvwriter = None
                CxDatetime.sleep(0.01)    # Give OS some breath for file IO operations
                os.rename(datafile, auxfile)
                CxDatetime.sleep(0.01)    # Give OS some breath for file IO operations
                os.rename(tempfile, datafile)
                CxDatetime.sleep(0.01)    # Give OS some breath for file IO operations
                if os.path.exists(auxfile) :
                    os.remove(auxfile)

            except Exception as e:
                errorcount += 1
                cxlogger.exception( e, level = DEBUG )
                cxlogger.error('failed to process presets counters')
            finally :
                if csvreader :
                    self.cxcsv.csvclose(csvreader)
                if csvwriter :
                    self.cxcsv.csvclose(csvwriter)
            # Clear unneeded cache
            self.cxcaches.uncache(CACHE_PRESETS)
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcount) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )

        return errorcount


    def __inventory_process_constraints(self) :
        errorcount: int = 0
        xcacheorigins = self.cxcaches.cache(CACHE_SCAN_ORIGINS)
        xcachecounters = self.cxcaches.cache(CACHE_COUNTERS)
        # Have we anything to process ?
        if not ( ( xcacheorigins and len(xcacheorigins) > 0 ) or ( xcachecounters and len(xcachecounters) > 0 ) ) :
            return errorcount

        xcount: int = 0
        inventory_name = 'constraints'
        xsummary: list[dict] = None
        xsummaryfile = self.__datapath + os.sep + OUT_SUMMARY
        xconfig: list[dict] = None
        xconfigfile = self.__datapath + os.sep + OUT_CONFIG
        xmaxstatus: int = SOK
        xstatus: int = SOK
        xdata: dict = None
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )

        try :
            xsummary = self.cxcsv.csvload( xsummaryfile )

            # Go for scan origins
            if ( xcacheorigins and len(xcacheorigins) > 0 ) :
                # Update config file
                xconfig = self.cxcsv.csvload( xconfigfile )
                for origin in xcacheorigins :
                    xstatus = origin['STATUS']
                    if xstatus > xmaxstatus :
                        xmaxstatus = xstatus
                    xdata = { 'STATUS': STATUS[xstatus],
                             'OBJ-TYPE': OBJ_SCAN_ORIGINS,
                             'OBJ-ID': None,
                             'OBJ-NAME': origin['ORIGIN'],
                             'OBJ-REF': None,
                             'PROJ-USING': origin['COUNT'],
                             'NOTES': None
                             }
                    xconfig.append(xdata)
                    xcount += 1
                # Summary scan origins counts
                xdata = { 'STATUS': STATUS[xstatus],
                         'OBJ-TYPE': OBJ_SCAN_ORIGINS,
                         'OBJ-COUNT': len(xcacheorigins),
                         'NOTES': 'scan origins'
                         }
                xsummary.append(xdata)

            # Go for constraints
            if ( xcachecounters and len(xcachecounters) > 0 ) :
                for counter in xcachecounters :
                    xdata = { 'STATUS': STATUS[counter['STATUS']],
                             'OBJ-TYPE': OBJ_CONSTRAINTS,
                             'OBJ-COUNT': counter['COUNT'],
                             'NOTES': counter['NAME']
                             }
                    xsummary.append(xdata)
                    xcount += 1

        except Exception as e :
            errorcount += 1
            cxlogger.exception( e, level = DEBUG )
            cxlogger.error('failed to process constraints')
        finally :
            if xsummary :
                self.cxcsv.csvsave( xsummaryfile, xsummary )
            if xconfig :
                self.cxcsv.csvsave( xconfigfile, xconfig )

        # Clear unneeded cache
        self.cxcaches.uncache(CACHE_SCAN_ORIGINS)
        self.cxcaches.uncache(CACHE_COUNTERS)
        # Close
        cxlogger.info('Processed ' + inventory_name + ' (' + str(xcount) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )

        return errorcount


    def __initconnection(self) :
        xstatus: bool = True
        xstarted = CxDatetime.now()
        cxlogger.info( 'Connecting to SAST' )

        try :

            # Initialize sast rest/odata connection
            self.__cxsast = CxSastHttpClient( fqdn = cxconfig.getvalue( "sast.url" ),
                                    username = cxconfig.getvalue( "sast.username" ),
                                    password = cxconfig.getvalue( "sast.password" ),
                                    certverify = not bool( cxconfig.getvalue( "sast.insecure" ) ),
                                    proxy_url = cxconfig.getvalue( "sast.proxy_url" ),
                                    proxy_username = cxconfig.getvalue( "sast.proxy_username" ),
                                    proxy_password = cxconfig.getvalue( "sast.proxy_password" ) )

            # Validate connection and authentication
            try:
                cxlogger.debug( "Connecting to SAST, authenticating, and get version" )
                self.cxsast.connect()
                self.cxsast.version()
            except HTTPUnauthorizedException as ne :
                cxlogger.error( 'Unauthorized to connect to SAST')
                cxlogger.exception( ne, level = DEBUG )
                xstatus = False
                raise ne
            except Exception as e :
                cxlogger.error( 'Unable to connect to SAST')
                cxlogger.exception( e, level = DEBUG )
                xstatus = False

            if xstatus :
                # Validate required permissions
                # Access-control data
                #       Access Control Manager (all)
                #       User Manager, Teams Manager, or User and Teams Manager
                #       Manage Authentication Providers
                # SAST data
                #       SAST Admin (all)
                #       Use ODATA
                #       View Results
                #       Manage Custom Fields
                #       Manage Engine Servers
                #       Manage Issue Tracking Systems
                #       Manage Pre Post Scan Actions
                #       Manage System Settings
                cxlogger.debug( "Checking current user permissions" )
                perm_error: list[str] = []
                perm_warns: list[str] = []
                cxsastperms: dict = self.cxsast.userpermissions(includeteams = True)
                if len(cxsastperms['iam']) == 0 :
                    perm_error.append("Can't resolve user permissions, missing user manager role!")
                else :
                    if not ( 'manage-users' in cxsastperms['iam'] or 'manage-teams' in cxsastperms['iam'] ):
                        perm_warns.append("User is not authorized to retrieve users and teams data!")
                    # Check root team membership
                    if 'CxServer' not in cxsastperms['teams'] :
                        perm_warns.append( "User is not a member of CxServer team. Data may be incomplete!" )
                    # Check admin permissions for access-control layer (except if --no-iam flag is set)
                    if not self.__noiam :
                        if 'manage-authentication-providers' not in cxsastperms['iam'] :
                            perm_warns.append( "User is not authorized to retrieve authentication providers data!" )
                        if 'manage-roles' not in cxsastperms['iam'] :
                            perm_warns.append("User is not authorized to retrieve roles data!")
                    # Check system information permissions
                    if 'manage-engine-servers' not in cxsastperms['sast'] :
                        perm_warns.append( "User is not authorized to retrieve engine servers data!" )
                    if not ( 'manage-custom-fields' in cxsastperms['sast'] or 'manage-issue-tracking-systems' in cxsastperms['sast'] or 'manage-pre-post-scan-actions' in cxsastperms['sast'] ) :
                        perm_warns.append( "User is not authorized to retrieve data from custom fields, issue trackers, scan actions!" )
                    if 'manage-system-settings' not in cxsastperms['sast'] :
                        perm_warns.append( "User is not authorized to retrieve data from system configuration!" )
                    # Check permissions for results
                    if 'view-results' not in cxsastperms['sast'] :
                        perm_error.append( "User is not authorized to retrieve scan results data which is required!" )
                    # Check permissions for project settings
                    if not ( 'save-project' in cxsastperms['sast'] or 'update-project' in cxsastperms['sast'] ) :
                        perm_warns.append( "User is not authorized to retrieve project scan configurations!" )
                    # Check permissions for ODATA
                    if 'use-odata' not in cxsastperms['sast'] :
                        perm_error.append("User is not authorized to use ODATA which is required!")

                # Fail mandatory permissions missing
                if len(perm_error) > 0 :
                    for msg_str in perm_error :
                        cxlogger.error( msg_str )
                    xstatus = False
                # Warn recommended permissions missing
                elif len(perm_warns) > 0:
                    for msg_str in perm_warns :
                        cxlogger.warning( msg_str )

                # If all passed, compose connection to soap
                if xstatus :
                    self.__cxsoap: CxSastSoapClient = CxSastSoapClient( fqdn = cxconfig.getvalue( "sast.url" ),
                                                                username = cxconfig.getvalue( "sast.username" ),
                                                                password = cxconfig.getvalue( "sast.password" ),
                                                                certverify = not bool( cxconfig.getvalue( "sast.insecure" ) ),
                                                                proxy_url = cxconfig.getvalue( "sast.proxy_url" ),
                                                                proxy_username = cxconfig.getvalue( "sast.proxy_username" ),
                                                                proxy_password = cxconfig.getvalue( "sast.proxy_password" ) )
        finally :
            if xstatus :
                cxlogger.info('Connected to SAST, ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )

        return xstatus


    def execute(self) -> int :
        errorcount: int = 0
        xstarted = CxDatetime.now()

        cxlogger.info( '=============================================================================' )
        cxlogger.info( 'CxSAST inventory start, ' + CxDatetime.nowastext() )
        cxlogger.info( '=============================================================================' )

        # Describe options
        if self.__noiam or self.__usersfull or self.__noscandata or self.__notriages or self.__projectfilter :
            cxlogger.info( 'Execution options:' )
            if self.__noiam :
                cxlogger.info( "> options.no-iam" )
            if self.__usersfull :
                cxlogger.info( "> options.detailed-users" )
            if self.__noscandata :
                cxlogger.info( "> options.no-scans" )
            if self.__notriages :
                cxlogger.info( "> options.no-triages" )
            if self.__includerepos :
                cxlogger.info( "> options.include-repos" )
            if self.__projectfilter :
                # Throws exception
                try :
                    xfilterdata: any = CxParamFilters.processfilter(filter = self.__projectfilter, numerics = True, guids = False, odatanum = True)
                    if xfilterdata :
                        if isinstance(xfilterdata, list) :
                            self.__projectfilter = xfilterdata
                            if len(xfilterdata) == 1 :
                                cxlogger.info( "> options.projects-filter: " + str(xfilterdata[0]) )
                            else :
                                cxlogger.info( "> options.projects-filter: " + str(len(xfilterdata)) + " projects" )
                        else :
                            self.__projectfilter = xfilterdata
                            cxlogger.info( "> options.projects-filter: " + str(xfilterdata) )
                    else :
                        cxlogger.error( "> options.projects-filter: invalid expression" )
                        self.__projectfilter = None
                        errorcount += 1
                except Exception :
                    cxlogger.error( "> options.projects-filter: invalid expression" )
                    self.__projectfilter = None
                    errorcount += 1
            cxlogger.info( '=============================================================================' )

        # Connect to CXSAST
        if errorcount == 0 :
            if not self.__initconnection() :
                errorcount += 1

            # Initialize output folders and files
            elif self.__preparedatafiles() :
                try :
                    # Process SAST version
                    errorcount += self.__inventory_sastinstance()
                    # Process SAST system configurations
                    errorcount += self.__inventory_addoncomponents()
                    errorcount += self.__inventory_engineconfigs()
                    errorcount += self.__inventory_engineservers()
                    errorcount += self.__inventory_customfields()
                    errorcount += self.__inventory_smtpsettings()
                    errorcount += self.__inventory_issuetrackers()
                    errorcount += self.__inventory_scanactions()
                    errorcount += self.__inventory_resultstates()
                    # Process SAST access-control data
                    errorcount += self.__inventory_ac_users()
                    errorcount += self.__inventory_ac_teams()
                    errorcount += self.__inventory_ac_roles()
                    errorcount += self.__inventory_ac_samlsettings()
                    errorcount += self.__inventory_ac_ldapsettings()
                    errorcount += self.__inventory_ac_domainsettings()
                    # Dispose of ac caches we don't need anymore
                    self.cxcaches.uncache(CACHE_AC_PROVIDERS)
                    self.cxcaches.uncache(CACHE_AC_USERS)
                    self.cxcaches.uncache(CACHE_AC_TEAMS)
                    # Process queries, presets, categories
                    errorcount += self.__inventory_queries()
                    errorcount += self.__inventory_presets()
                    errorcount += self.__inventory_custom_categories()
                    # Projects
                    errorcount += self.__inventory_projects()
                    # Close the files
                    self.__closedatafiles()
                    # Post-process project duplicated names, if exists
                    errorcount += self.__inventory_process_duplicates()
                    # Post-process object counters
                    errorcount += self.__inventory_process_config_counters()
                    errorcount += self.__inventory_process_teams_counters()
                    errorcount += self.__inventory_process_queries_counters()
                    errorcount += self.__inventory_process_presets_counters()
                    # Post-process constraints
                    errorcount += self.__inventory_process_constraints()

                except Exception as e :
                    errorcount += 1
                    cxlogger.exception(e)

            else :
                errorcount += 1

        # Ensure data files closure
        self.__closedatafiles()

        cxlogger.info( '=============================================================================' )
        cxlogger.info( 'CxSAST inventory end, ' + CxDatetime.nowastext() )
        if errorcount > 0 :
            cxlogger.warning( 'Found ' + str(errorcount) + ' errors, check the logs' )
        cxlogger.info( 'Duration ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        cxlogger.info( '=============================================================================' )

        return errorcount
