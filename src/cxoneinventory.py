import csv
import os
import uuid
from http import HTTPStatus
from shared.package.clients.cxhttpclient import HTTPForbiddenException
from shared.package.clients.cxhttpclient import HTTPTimeout
from shared.package.clients.cxhttpclient import HTTPUnauthorizedException
from shared.package.common import cxutils
from shared.package.common.cxcaches import CxCaches
from shared.package.common.cxconfig import cxconfig
from shared.package.common.cxcsv import CxCsv
from shared.package.common.cxdatetime import CxDatetime
from shared.package.common.cxlogging import DEBUG
from shared.package.common.cxlogging import cxlogger
from shared.package.common.cxparamfilters import CxParamFilters
from shared.package.cxone.cxonehttpclient import CxOneHttpClient
from urllib import parse


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

# HTTP RELATED EXCEPTIONS
SFORBIDDEN: str = 'Insufficient permissions to get this data'
SEXCEPTION: str = 'Failed to get this data'

# CACHE NAMES FOR DATA
CACHE_CONFIG: str = 'CACHE-CONFIG'
CACHE_GROUPS: str = 'CACHE-GROUPS'
CACHE_QUERIES: str = 'CACHE-QUERIES'
CACHE_PRESETS: str = 'CACHE-PRESETS'
CACHE_APPLICATIONS: str = 'CACHE-APPLICATIONS'

# CACHE NAMES INTERNAL
CACHE_AC_USERS: str = 'CACHE-AC-USERS'
CACHE_AC_GROUPS: str = 'CACHE-AC-GROUPS'
CACHE_TENANT_QUERIES: str = 'CACHE-TENANT-QUERIES'
CACHE_SCAN_ORIGINS: str = 'CACHE-SCAN-ORIGINS'

# CONFIGURATION OUTPUT OBJECT TYPES
OBJ_CXONE_INSTANCE: str = 'CXONE-INSTANCE'
OBJ_TENANT_CONFIG: str = 'TENANT-CONFIG'
# IAM ACCESS-CONTROL OUTPUT OBJECT TYPES
OBJ_AC_USERS: str = 'IAM-USERS'
OBJ_AC_GROUPS: str = 'IAM-GROUPS'
OBJ_AC_ROLES: str = 'IAM-ROLES'
OBJ_AC_USERS_EMAILS: str = 'IAM-USERS-EMAIL-DOMAINS'
OBJ_AC_IDPS: str = 'IAM-IDP-SETTINGS'
OBJ_AC_SAML: str = 'IAM-SAML-SETTINGS'
OBJ_AC_OIDC: str = 'IAM-OIDC-SETTINGS'
OBJ_AC_LDAP: str = 'IAM-LDAP-SETTINGS'
# PRESETS, QUERIES
OBJ_QUERIES: str = 'QUERIES'
OBJ_QUERIES_CORP: str = 'CUSTOM-QUERIES-TENANT'
OBJ_QUERIES_TEAM: str = 'CUSTOM-QUERIES-APPLICATION'
OBJ_QUERIES_PROJ: str = 'CUSTOM-QUERIES-PROJ'
OBJ_PRESETS: str = 'PRESETS'
# PROJECTS, APPLICATIONS
OBJ_APPLICATIONS: str = 'APPLICATIONS'
OBJ_PROJECTS: str = 'PROJECTS'
# OTHER
OBJ_SCAN_ORIGINS: str = 'SCAN-ORIGINS'

# INVENTORY CSV OUTPUT FILES
OUT_SUMMARY: str = 'cxone_inventorysummary.csv'
OUT_CONFIG: str = 'cxone_inventoryconfigurations.csv'
OUT_ACUSERS: str = 'cxone_inventoryusers.csv'
OUT_ACGROUPS: str = 'cxone_inventorygroups.csv'
OUT_ACROLES: str = 'cxone_inventoryroles.csv'
OUT_QUERIES: str = 'cxone_inventoryqueries.csv'
OUT_PRESETS: str = 'cxone_inventorypresets.csv'
OUT_PRESETQUERIES: str = 'cxone_inventorypresetqueries.csv'
OUT_APPLICATIONS: str = 'cxone_inventoryapplications.csv'
OUT_PROJECTS: str = 'cxone_inventoryprojects.csv'

# CSV FILES HEADERS
CSV_SUMMARY: list[str] = ['STATUS', 'OBJ-TYPE', 'OBJ-COUNT', 'NOTES']
CSV_CONFIG: list[str] = ['STATUS', 'OBJ-TYPE', 'OBJ-ID', 'OBJ-NAME', 'OBJ-REF', 'PROJ-USING', 'NOTES']
CSV_ACUSERS: list[str] = ['STATUS', 'ID', 'NAME', 'EMAIL', 'FIRST-NAME', 'LAST-NAME', 'PROVIDER-TYPE', 'NOTES']
CSV_ACGROUPS: list[str] = ['STATUS', 'GROUP-ID', 'GROUP-NAME', 'PROJ-USING', 'NOTES']
CSV_ACROLES: list[str] = ['STATUS', 'ROLE-ID', 'ROLE-NAME', 'ROLE-DESCRIPTION', 'ROLE-TYPE', 'NOTES']
CSV_QUERIES: list[str] = ['STATUS', 'QUERY-ID', 'QUERY-LEVEL', 'QUERY-LANGUAGE', 'QUERY-NAME', 'QUERY-GROUP', 'QUERY-SEVERITY',
                          'REF-ID', 'REF-NAME', 'PROJ-USING', 'NOTES']
CSV_PRESETS: list[str] = ['STATUS', 'PRESET-ID', 'PRESET-NAME', 'PRESET-TYPE', 'CUSTOMIZED', 'PROJ-USING', 'NOTES']
CSV_PRESETQUERIES: list[str] = ['STATUS', 'PRESET-ID', 'PRESET-NAME', 'PRESET-TYPE',
                                'QUERY-ID', 'QUERY-NAME', 'QUERY-LANGUAGE', 'QUERY-GROUP', 'QUERY-PACKAGE-TYPE']
CSV_APPLICATIONS: list[str] = ['STATUS', 'APP-ID', 'APP-NAME', 'APP-REF', 'PROJ-USING', 'NOTES']
CSV_PROJECTS: list[str] = ['STATUS', 'ID', 'NAME', 'CREATED-ON', 'UPDATED-ON', 'PRIMARY-BRANCH',
                           'REPOSITORY-TYPE', 'REPOSITORY-URL', 'REPOSITORY-BRANCH',
                        #    'SCM-REPONAME', 'SCM-REPOID', 'SCM-BRANCHES',
                           'CRITICALITY', 'APPLICATIONS', 'GROUPS', 'TAGS',
                           'SKIP-SUBMODULES', 'SOURCE-MODE',
                           'SAST-LANGUAGE-MODE', 'SAST-FAST-SCAN', 'SAST-PRESET', 'SAST-FILTER',
                           'SCA-EXPLOITABLE-PATH', 'SCA-EXPLOITABLE-TIME', 'SCA-FILTER',
                           'LANGUAGES', 'SCANNERS',
                           'SAST-LASTSCAN-ID', 'SAST-LASTSCAN-CREATED', 'SAST-LASTSCAN-ORIGIN', 'SAST-LASTSCAN-SOURCE', 'SAST-LASTSCAN-RESULTS', 'SAST-LASTSCAN-TRIAGES',
                           'SCA-LASTSCAN-ID', 'SCA-LASTSCAN-CREATED', 'SCA-LASTSCAN-ORIGIN', 'SAST-LASTSCAN-SOURCE', 'SCA-LASTSCAN-RESULTS', 'SCA-LASTSCAN-TRIAGES',
                           'OTHERS-LASTSCAN-ID', 'OTHERS-LASTSCAN-CREATED', 'OTHERS-LASTSCAN-ORIGIN', 'OTHERS-LASTSCAN-SOURCE', 'OTHERS-LASTSCAN-RESULTS', 'OTHERS-LASTSCAN-TRIAGES',
                           'NOTES']


class CxOneInventory(object) :

    def __init__(self ) :
        self.__cxone: CxOneHttpClient = None
        self.__cxcsv: CxCsv = CxCsv()
        self.__cxcaches: CxCaches = CxCaches()
        self.__datapath: str = None
        # Tenant Id
        self.__tenantid: str = None
        # Client Ids
        self.__ast_app: str = None
        self.__cb_app: str = None
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
        # Tenant configuration internal variables
        self.__tenantpreset: str = None
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
        # Well known file for csv containing applications
        self.__appshandler = None
        self.__appswriter = None
        # Well known file for csv containing projects
        self.__projshandler = None
        self.__projswriter = None


    @property
    def cxone(self) -> CxOneHttpClient :
        return self.__cxone


    @property
    def cxcsv(self) -> CxCsv :
        return self.__cxcsv


    @property
    def cxcaches(self) -> CxCaches :
        return self.__cxcaches


    @property
    def tenantid(self) :
        if not self.__tenantid :
            tenantinfo: dict = self.cxone.get(self.cxone.iamapiroot)
            self.__tenantid = tenantinfo.get('id')
        return self.__tenantid


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
            filename = self.__datapath + os.sep + OUT_ACGROUPS
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
            # Well known file for csv containing applications
            filename = self.__datapath + os.sep + OUT_APPLICATIONS
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
        if (self.__appshandler):
            self.__appshandler.close()
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
        self.__appshandler = None
        self.__projshandler = None


    def __initconnection(self) :
        xstatus: bool = True
        xstarted = CxDatetime.now()
        cxlogger.info( 'Connecting to CxONE' )

        try :

            # Initialize sast rest/odata connection
            self.__cxone = CxOneHttpClient( fqdn = cxconfig.getvalue( "cxone.url" ),
                                            tenant = cxconfig.getvalue( "cxone.tenant" ),
                                            apikey_secret = cxconfig.getvalue( "cxone.apikey" ),
                                            aclfqdn = cxconfig.getvalue( "cxone.iamurl" ),
                                            clientid = cxconfig.getvalue( "cxone.clientid" ),
                                            granttype = cxconfig.getvalue( "cxone.granttype" ),
                                            certverify = not bool( cxconfig.getvalue( "cxone.insecure" ) ),
                                            proxy_url = cxconfig.getvalue( "cxone.proxy_url" ),
                                            proxy_username = cxconfig.getvalue( "cxone.proxy_username" ),
                                            proxy_password = cxconfig.getvalue( "cxone.proxy_password" ) )

            # Validate connection and authentication
            try:
                cxlogger.debug( "Connecting to CxONE, authenticating, and get version" )
                self.cxone.connect()
                self.cxone.version()
            except HTTPUnauthorizedException as ne :
                cxlogger.error( 'Unauthorized to connect to CxONE')
                cxlogger.exception( ne, level = DEBUG )
                xstatus = False
                raise ne
            except Exception as e :
                cxlogger.error( 'Unable to connect to CxONE')
                cxlogger.exception( e, level = DEBUG )
                xstatus = False
                raise e

            if xstatus :
                # Validate required permissions
                # IAM data
                #       manage-groups or manage-users   Users and Groups
                #       iam-admin  All in
                # AST data
                #       view-tenant-params > engine configuration
                #       view-queries > queries
                #       view-preset > presets
                #       view-projects & view-project-params > projects
                #       view-scans > scans
                #       view-results > scan results
                cxlogger.debug( "Checking current user permissions" )
                perm_error: list[str] = []
                perm_warns: list[str] = []
                cxoneperms: dict = self.cxone.userpermissions(wantedpermissions = ['view-tenant-params', 'view-queries', 'view-preset', 'view-projects', 'view-project-params', 'view-scans', 'view-results'])
                # Check for iam permissions
                if not ( 'manage-users' in cxoneperms['iam'] or 'manage-teams' in cxoneperms['iam'] ):
                    perm_warns.append("User is not authorized to retrieve uses and teams data!")
                if ( 'iam-admin' not in cxoneperms['iam'] ) and ( 'view-identity-providers' not in cxoneperms['iam'] ) :
                    perm_warns.append("User is not authorized to retrieve IdP data!")
                # Check for ast permissions
                if 'view-tenant-params' not in cxoneperms['ast'] :
                    perm_warns.append( "User is not authorized to retrieve tenant configuration data!" )
                if 'view-queries' not in cxoneperms['ast'] :
                    perm_warns.append( "User is not authorized to retrieve queries data!" )
                if 'view-preset' not in cxoneperms['ast'] :
                    perm_error.append( "User is not authorized to retrieve presets data!" )
                if 'view-projects' not in cxoneperms['ast'] or 'view-project-params' not in cxoneperms['ast'] :
                    perm_error.append( "User is not authorized to retrieve projects data!" )
                if 'view-scans' not in cxoneperms['ast'] :
                    perm_warns.append( "User is not authorized to retrieve scans data!" )
                if 'view-results' not in cxoneperms['ast'] :
                    perm_warns.append( "User is not authorized to retrieve scans results data!" )
                # Fail mandatory permissions missing
                if len(perm_error) > 0 :
                    for msg_str in perm_error :
                        cxlogger.error( msg_str )
                    xstatus = False
                # Warn recommended permissions missing
                elif len(perm_warns) > 0:
                    for msg_str in perm_warns :
                        cxlogger.warning( msg_str )

        finally :
            if xstatus :
                cxlogger.info('Connected to CxONE, ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )

        return xstatus


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


    def __internal_write_group( self, data: list, cacheit: bool = True ) :
        # Check output file is ready
        if not self.__teamshandler :
            filename = self.__datapath + os.sep + OUT_ACGROUPS
            self.__teamshandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__teamswriter = csv.writer(self.__teamshandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__teamswriter.writerow(CSV_ACGROUPS)
        # Write it
        self.__teamswriter.writerow( data )
        # Cache it
        if cacheit :
            xpos: int = 0
            xval: any = None
            xdict: dict = {}
            for xkey in CSV_ACGROUPS :
                xval = data[xpos]
                xdict[xkey] = xval
                xpos += 1
            xcache: list[dict] = self.cxcaches.cache(CACHE_GROUPS)
            if not xcache :
                xcache = []
                xcache.append(xdict)
                self.cxcaches.putcache(CACHE_GROUPS, xcache)
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


    def __internal_write_application( self, data: list, cacheit: bool = True ) :
        # Check output file is ready
        if not self.__appshandler :
            filename = self.__datapath + os.sep + OUT_APPLICATIONS
            self.__appshandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__appswriter = csv.writer(self.__appshandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__appswriter.writerow(CSV_APPLICATIONS)
        # Write it
        self.__appswriter.writerow( data )
        # Cache it
        if cacheit :
            xpos: int = 0
            xval: any = None
            xdict: dict = {}
            for xkey in CSV_APPLICATIONS :
                xval = data[xpos]
                xdict[xkey] = xval
                xpos += 1
            xcache: list[dict] = self.cxcaches.cache(CACHE_APPLICATIONS)
            if not xcache :
                xcache = []
                xcache.append(xdict)
                self.cxcaches.putcache(CACHE_APPLICATIONS, xcache)
            else :
                xcache.append(xdict)



    def __internal_get_clientids( self, ignoreerrors: bool = False ) :
        # Resolve keycloak client ids for "ast-app" and "cb-app", relevant for roles and premissions
        if not self.__ast_app or not self.__cb_app :
            try :
                xclients = self.cxone.get( self.cxone.iamapiroot + '/clients' )
                if not self.__ast_app :
                    xclient = next( filter( lambda el: el['clientId'] == 'ast-app', xclients ), None )
                    if xclient :
                        self.__ast_app = xclient['id']
                if not self.__cb_app :
                    xclient = next( filter( lambda el: el['clientId'] == 'cb-app', xclients ), None )
                    if xclient :
                        self.__cb_app = xclient['id']
            except Exception as e:
                if ignoreerrors :
                    pass
                else :
                    raise e


    def __internal_get_all_active_users(self, ignoreerrors: bool = False) -> list[dict] :
        xallusers: list = self.cxcaches.cache(CACHE_AC_USERS)
        if not xallusers :
            xskip: int = 0
            xallusers: list = []
            xuserid: str = None
            self.__internal_get_clientids( True )
            try :
                # Get paged
                xusers = self.cxone.get( self.cxone.iamapiroot + '/users?enabled=true&first=' + str(xskip) + '&max=100' )
                while len(xusers) > 0 :
                    for xuser in xusers :
                        xuserid = xuser.get('id')
                        # Fix data
                        if 'email' not in xuser :
                            xuser['email'] = None
                        if 'firstName' not in xuser :
                            xuser['firstName'] = None
                        if 'lastName' not in xuser :
                            xuser['lastName'] = None
                        # Get federated identities
                        xuser['federatedIdentities'] = []
                        xuserdata = self.cxone.get( self.cxone.iamapiroot + '/users/' + xuserid )
                        xfederations: list = xuserdata.get('federatedIdentities')
                        if xfederations :
                            for xfederation in xfederations :
                                xuser['federatedIdentities'].append(xfederation['identityProvider'])
                        # Add-it
                        xallusers.append(xuser)
                    if len(xusers) < 100 :
                        xusers = []
                    else :
                        xskip += 100
                        xusers = self.cxone.get( self.cxone.iamapiroot + '/users?enabled=true&first=' + str(xskip) + '&max=100' )
            except Exception as e:
                if ignoreerrors :
                    pass
                else :
                    raise e

            self.cxcaches.putcache( cachename = CACHE_AC_USERS, cachedata = xallusers )
        return xallusers


    def __internal_get_all_groups(self, ignoreerrors: bool = False) -> list[dict] :
        xallgroups: list = self.cxcaches.cache(CACHE_AC_GROUPS)

        # Recursively get groups and group children
        def __get_groups_from_level( parentid: str ) :
            skip: int = 0
            allgroups: list = []
            if not parentid :
                groups = self.cxone.get( self.cxone.iamapiroot + '/groups?first=' + str(skip) + '&max=100' )
                while len(groups) > 0 :
                    for group in groups :
                        allgroups.append(group)
                        if group['subGroupCount'] > 0 :
                            allgroups.extend( __get_groups_from_level(group['id']) )
                    if len(groups) < 100 :
                        groups = []
                    else :
                        skip += 100
                        groups = self.cxone.get( self.cxone.iamapiroot + '/groups?first=' + str(skip) + '&max=100' )
            else :
                groups = self.cxone.get( self.cxone.iamapiroot + '/groups/' + parentid + '/children?first=' + str(skip) + '&max=100' )
                while len(groups) > 0 :
                    for group in groups :
                        allgroups.append(group)
                        if group['subGroupCount'] > 0 :
                            allgroups.extend( __get_groups_from_level(group['id']) )
                    if len(groups) < 100 :
                        groups = []
                    else :
                        skip += 100
                        groups = self.cxone.get( self.cxone.iamapiroot + '/groups/' + parentid + '/children?first=' + str(skip) + '&max=100' )
            return allgroups

        if not xallgroups :
            xallgroups = []
            try :
                xallgroups = __get_groups_from_level( None )
            except Exception as e:
                if ignoreerrors :
                    pass
                else :
                    raise e
            self.cxcaches.putcache( cachename = CACHE_AC_GROUPS, cachedata = xallgroups )
        return xallgroups


    def __inventory_cxoneinstance(self) :
        errorcount: int = 0
        inventory_name: str = 'cxone instance'
        xobject: str = OBJ_CXONE_INSTANCE
        xstatus: int = SOK
        xinfo: str = None
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            cxonename = 'CxOne ' + cxconfig.getvalue( "cxone.tenant" ) + ' - version ' + self.cxone.versionstr()
            # Register to inventory
            self.__internal_write_config( [STATUS[xstatus], xobject, None, cxonename, None, None, xinfo ] )
            # Register to summary
            if xinfo :
                xinfo = cxonename + ', ' + xinfo
            else :
                xinfo = cxonename
            self.__internal_write_summary( [STATUS[xstatus], xobject, 1, xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (1) - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxone.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_tenantconfigs(self) :
        errorcount: int = 0
        inventory_name = 'tenant configurations'
        xobject: str = OBJ_TENANT_CONFIG
        xstatus: int = SOK
        xinfo: str = None
        xdata: dict = None
        xstarted = CxDatetime.now()
        xcounter: int = 0
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            xconfigs = self.cxone.get('/api/configuration/tenant')
            # Register to inventory
            if xconfigs :
                # Source code management
                xdata = next( filter( lambda el: el['key'] == 'scan.config.general.sourceCodeManagement', xconfigs), None )
                if xdata :
                    self.__internal_write_config( [STATUS[xstatus], xobject, xdata.get('name'), xdata.get('value'), xdata.get('category'), None, xinfo ] )
                    xcounter += 1
                # Skip submodules
                xdata = next( filter( lambda el: el['key'] == 'scan.handler.git.skipSubModules', xconfigs), None )
                if xdata :
                    self.__internal_write_config( [STATUS[xstatus], xobject, xdata.get('name'), xdata.get('value'), xdata.get('category'), None, xinfo ] )
                    xcounter += 1
                # SAST Preset
                xdata = next( filter( lambda el: el['key'] == 'scan.config.sast.presetName', xconfigs), None )
                if xdata :
                    self.__internal_write_config( [STATUS[xstatus], xobject, xdata.get('name'), xdata.get('value'), xdata.get('category'), None, xinfo ] )
                    self.__tenantpreset = xdata.get('value')
                    if not self.__tenantpreset :
                        self.__tenantpreset = None
                    xcounter += 1
                # SAST Fast scan
                xdata = next( filter( lambda el: el['key'] == 'scan.config.sast.fastScanMode', xconfigs), None )
                if xdata :
                    self.__internal_write_config( [STATUS[xstatus], xobject, xdata.get('name'), xdata.get('value'), xdata.get('category'), None, xinfo ] )
                    xcounter += 1
                # SAST Language mode
                xdata = next( filter( lambda el: el['key'] == 'scan.config.sast.languageMode', xconfigs), None )
                if xdata :
                    self.__internal_write_config( [STATUS[xstatus], xobject, xdata.get('name'), xdata.get('value'), xdata.get('category'), None, xinfo ] )
                    xcounter += 1
                # SAST Recommended exclusions
                xdata = next( filter( lambda el: el['key'] == 'scan.config.sast.recommendedExclusions', xconfigs), None )
                if xdata :
                    self.__internal_write_config( [STATUS[xstatus], xobject, xdata.get('name'), xdata.get('value'), xdata.get('category'), None, xinfo ] )
                    xcounter += 1
                # SAST Filters
                xdata = next( filter( lambda el: el['key'] == 'scan.config.sast.filter', xconfigs), None )
                if xdata :
                    self.__internal_write_config( [STATUS[xstatus], xobject, xdata.get('name'), xdata.get('value'), xdata.get('category'), None, xinfo ] )
                    xcounter += 1
                # SCA Exploitable Path
                xdata = next( filter( lambda el: el['key'] == 'scan.config.sca.ExploitablePath', xconfigs), None )
                if xdata :
                    self.__internal_write_config( [STATUS[xstatus], xobject, xdata.get('name'), xdata.get('value'), xdata.get('category'), None, xinfo ] )
                    xcounter += 1
                xdata = next( filter( lambda el: el['key'] == 'scan.config.sca.filter', xconfigs), None )
                if xdata :
                    self.__internal_write_config( [STATUS[xstatus], xobject, xdata.get('name'), xdata.get('value'), xdata.get('category'), None, xinfo ] )
                    xcounter += 1

            # # Register to summary
            self.__internal_write_summary( [STATUS[xstatus], xobject, str(xcounter), xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcounter) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxone.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_iam_users(self) :
        errorcount: int = 0
        inventory_name = 'iam users'
        xobject: str = OBJ_AC_USERS
        xstatus: int = SOK

        if self.__noiam :
            xstatus = SWARNING
            xinfo = 'excluded by no-iam access-control option'
            self.__internal_write_summary( [STATUS[xstatus], xobject, None, xinfo ] )
            return errorcount

        xinfo: str = None
        xstarted = CxDatetime.now()
        xcounter: int = 0
        xemail: str = None
        xemaildomains: list[str] = []
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            # Get active users
            xusers = self.__internal_get_all_active_users()
            for xuser in xusers :
                xcounter += 1
                xemail = xuser.get('email')
                if xemail :
                    p = xemail.find('@')
                    if p >= 0 :
                        xemail = xemail[p:].strip()
                    if xemail :
                        xemaildomains.append(xemail)
                if self.__usersfull :
                    xproviders: str = ""
                    for xprovider in xuser.get('federatedIdentities') :
                        if xproviders == "" :
                            xproviders = xprovider
                        else :
                            xproviders = xproviders + SPLITTER + xprovider
                    self.__internal_write_user( [STATUS[xstatus], xuser['id'], xuser['username'], xuser['email'], xuser['firstName'], xuser['lastName'], xproviders, xinfo] )

            # Register to summary
            self.__internal_write_summary( [STATUS[xstatus], xobject, str(xcounter), xinfo ] )

            # Distinct email domains
            xinfo = 'distinct email domain'
            xemaildomains = list( dict.fromkeys(xemaildomains) )
            xobject = OBJ_AC_USERS_EMAILS
            xstatus = SOK
            for email in xemaildomains :
                self.__internal_write_config( [STATUS[xstatus], xobject, None, email, None, None, xinfo ], False )
            # Register index
            xinfo = 'distinct email domains'
            self.__internal_write_summary( [STATUS[xstatus], xobject, len(xemaildomains), xinfo ] )

            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcounter) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxone.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_iam_groups(self) :
        errorcount: int = 0
        inventory_name = 'iam groups'
        xobject: str = OBJ_AC_GROUPS
        xstatus: int = SOK

        if self.__noiam :
            xstatus = SWARNING
            xinfo = 'excluded by no-iam access-control option'
            self.__internal_write_summary( [STATUS[xstatus], xobject, None, xinfo ] )
            return errorcount

        xinfo: str = None
        xstarted = CxDatetime.now()
        xcounter: int = 0
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            # Get  groups
            xgroups = self.__internal_get_all_groups()
            for xgroup in xgroups :
                xcounter += 1
                self.__internal_write_group( [STATUS[xstatus], xgroup['id'], xgroup['path'], None, xinfo ] )
            # Register to summary
            self.__internal_write_summary( [STATUS[xstatus], xobject, str(xcounter), xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcounter) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxone.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_iam_roles(self) :
        errorcount: int = 0
        inventory_name = 'iam roles'
        xobject: str = OBJ_AC_ROLES
        xstatus: int = SOK

        if self.__noiam :
            xstatus = SWARNING
            xinfo = 'excluded by no-iam access-control option'
            self.__internal_write_summary( [STATUS[xstatus], xobject, None, xinfo ] )
            return errorcount

        xinfo: str = None
        xstarted = CxDatetime.now()
        xcounter: int = 0
        xcustomroles: int = 0
        xcustomrole: bool = False
        xiamrole: bool = False
        xdescription: str = None
        xskip: int = 0
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            # Resolve defult clients
            self.__internal_get_clientids()
            xroles: list = []
            xallroles: list = []
            xcompositeroles: list = []
            # Get tenant roles (for iam)
            xroles = self.cxone.get( self.cxone.iamapiroot + '/roles?briefRepresentation=false&first=' + str(xskip) + '&max=100' )
            while len(xroles) > 0 :
                xallroles.extend(xroles)
                if len(xroles) < 100 :
                    xroles = []
                else :
                    xskip += 100
                    xroles = self.cxone.get( self.cxone.iamapiroot + '/roles?briefRepresentation=false&first=' + str(xskip) + '&max=100' )
            # Get ast-app roles
            xskip = 0
            xroles = self.cxone.get( self.cxone.iamapiroot + '/clients/' + self.__ast_app + '/roles?briefRepresentation=false&first=' + str(xskip) + '&max=100' )
            while len(xroles) > 0 :
                xallroles.extend(xroles)
                if len(xroles) < 100 :
                    xroles = []
                else :
                    xskip += 100
                    xroles = self.cxone.get( self.cxone.iamapiroot + '/clients/' + self.__ast_app + '/roles?briefRepresentation=false&first=' + str(xskip) + '&max=100' )
            # Get the composite ones
            xcompositeroles = list( filter( lambda el: el['composite'], xallroles) )
            # Identify custom roles
            xroles = []
            for xrole in xcompositeroles :
                xcustomrole = False
                xiamrole = False
                xdescription = xrole.get('description')
                xattributes: dict = xrole.get('attributes')
                if xattributes :
                    # Check if it is iam role
                    xtype = xattributes.get('type')
                    if xtype and ('iam' in xtype) :
                        xiamrole = True
                    # Check if it is custom role
                    xcreator = xattributes.get('creator')
                    if xcreator and ('Checkmarx' not in xcreator) :
                        xcustomrole = not xiamrole
                    xrole['isSystemRole'] = not xcustomrole
                    xroles.append(xrole)
                    xcounter += 1
                    if xcustomrole :
                        xcustomroles += 1
                        xstatus = SWARNING
                        xinfo = 'custom role'
                    else :
                        xstatus = SOK
                        xinfo = None
                    if xiamrole :
                        self.__internal_write_role( [STATUS[xstatus], xrole['id'], xrole['name'], xdescription, 'iam', xinfo ] )
                    else :
                        self.__internal_write_role( [STATUS[xstatus], xrole['id'], xrole['name'], xdescription, 'ast-app', xinfo ] )

            # Register to summary
            if xcustomroles > 0 :
                xinfo = str(xcustomroles) + ' custom roles'
                xstatus = SWARNING
            else :
                xinfo = None
                xstatus = SOK
            self.__internal_write_summary( [STATUS[xstatus], xobject, str(xcounter), xinfo ] )
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcounter) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxone.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_iam_idpsettings(self) :
        errorcount: int = 0
        inventory_name = 'iam idp settings'
        xobject: str = OBJ_AC_IDPS

        if self.__noiam :
            xstatus = SWARNING
            xinfo = 'excluded by no-iam access-control option'
            self.__internal_write_summary( [STATUS[xstatus], xobject, None, xinfo ] )
            return errorcount

        xinfo: str = None
        xobject: str = OBJ_AC_SAML
        xstatus: int = SOK
        xcounter: int = 0
        xissuer: str = None
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            # Get identity providers available
            xallproviders: list = self.cxone.get( self.cxone.iamapiroot + '/identity-provider/instances' )

            # From those, get enabled
            if xallproviders :
                xallusers: list = self.__internal_get_all_active_users()

                # Go fo SAML
                xobject = OBJ_AC_SAML
                xstatus = SOK
                xproviders: list = list( filter( lambda el: el['providerId'] == 'saml' and el['enabled'], xallproviders ) )
                if xproviders and len(xproviders) > 0 :
                    for xsaml in xproviders :
                        xissuer = xsaml['config']['singleSignOnServiceUrl']
                        xusers = list( filter( lambda el: xsaml['alias'] in el['federatedIdentities'], xallusers) )
                        if len(xusers) == 0 :
                            xinfo = 'issuer: ' + xissuer + ' (no users)'
                        elif len(xusers) == 1 :
                            xinfo = 'issuer: ' + xissuer + ' (1 user)'
                        else :
                            xinfo = 'issuer: ' + xissuer + ' (' + str(len(xusers)) + ' user)'
                        xcounter += 1
                        self.__internal_write_config( [STATUS[xstatus], xobject, xsaml['internalId'], xsaml['alias'], None, None, xinfo ], False )
                    # Summary
                    xinfo = None
                    self.__internal_write_summary( [STATUS[xstatus], xobject, str(len(xproviders)), xinfo ] )

                # Go fo OIDC
                xobject = OBJ_AC_OIDC
                xstatus = SOK
                xproviders: list = list( filter( lambda el: el['providerId'] == 'oidc' and el['enabled'], xallproviders ) )
                if xproviders and len(xproviders) > 0 :
                    for xoidc in xproviders :
                        xissuer = xoidc['config']['authorizationUrl']
                        xusers = list( filter( lambda el: xsaml['alias'] in el['federatedIdentities'], xallusers) )
                        if len(xusers) == 0 :
                            xinfo = 'issuer: ' + xissuer + ' (no users)'
                        elif len(xusers) == 1 :
                            xinfo = 'issuer: ' + xissuer + ' (1 user)'
                        else :
                            xinfo = 'issuer: ' + xissuer + ' (' + str(len(xusers)) + ' user)'
                        xcounter += 1
                        self.__internal_write_config( [STATUS[xstatus], xobject, xoidc['internalId'], xoidc['alias'], None, None, xinfo ], False )
                    # Summary
                    xinfo = None
                    self.__internal_write_summary( [STATUS[xstatus], xobject, str(len(xproviders)), xinfo ] )

            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcounter) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxone.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_iam_ldapsettings(self) :
        errorcount: int = 0
        inventory_name = 'iam ldap settings'
        xobject: str = OBJ_AC_LDAP

        if self.__noiam :
            xstatus = SWARNING
            xinfo = 'excluded by no-iam access-control option'
            self.__internal_write_summary( [STATUS[xstatus], xobject, None, xinfo ] )
            return errorcount

        xinfo: str = None
        xstatus: int = SOK
        xcounter: int = 0
        xissuer: str = None
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            # Get storages available
            xallproviders: list = self.cxone.get( self.cxone.iamapiroot + '/components?parent=' + self.tenantid + '&type=org.keycloak.storage.UserStorageProvider')
            # From those, get saml and enabled
            if xallproviders :
                xproviders = list( filter( lambda el: el['providerId'] == 'ldap', xallproviders) )
                if xproviders and len(xproviders) > 0 :
                    xallusers: list = self.__internal_get_all_active_users()
                    for xldap in xproviders :
                        if xldap['config'] and xldap['config']['enabled'] and 'true' in xldap['config']['enabled'] :
                            xissuer = ' '.join(xldap['config']['vendor']) + ' ' + ' '.join(xldap['config']['connectionUrl'])
                            xusers = list( filter( lambda el: xldap['name'] in el['federatedIdentities'], xallusers) )
                            if len(xusers) == 0 :
                                xinfo = 'issuer: ' + xissuer + ' (no users)'
                            elif len(xusers) == 1 :
                                xinfo = 'issuer: ' + xissuer + ' (1 user)'
                            else :
                                xinfo = 'issuer: ' + xissuer + ' (' + str(len(xusers)) + ' user)'
                            xcounter += 1
                            self.__internal_write_config( [STATUS[xstatus], xobject, xldap['id'], xldap['name'], None, None, xinfo ], False )

                    # Summary
                    xinfo = None
                    self.__internal_write_summary( [STATUS[xstatus], xobject, str(len(xproviders)), xinfo ] )

            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcounter) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxone.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __internal_get_tenant_and_corp_queries(self, ignoreerrors: bool = False) -> list[dict] :
        xallqueries = self.cxcaches.cache(CACHE_TENANT_QUERIES)
        if not xallqueries :
            xallqueries = []
            try :
                xallqueries = self.cxone.get( '/api/cx-audit/queries')
            except Exception as e:
                if ignoreerrors :
                    pass
                else :
                    raise e
            self.cxcaches.putcache( cachename = CACHE_TENANT_QUERIES, cachedata = xallqueries )
        return xallqueries


    def __inventory_queries_tenant(self) :
        errorcount: int = 0
        inventory_name = 'queries tenant'
        xinfo: str = None
        xobject: str = OBJ_QUERIES_CORP
        xstatus: int = SOK
        xcounter: int = 0
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            # This call only gets cx and corp queries
            xallqueries: list = self.__internal_get_tenant_and_corp_queries()
            # From it, filter tenant level only
            xqueries: list = list( filter( lambda el: el['level'] == 'Tenant', xallqueries) )

            for xquery in xqueries :
                xcounter += 1
                self.__internal_write_query( [ STATUS[xstatus], xquery['Id'], xquery['level'], xquery['lang'], xquery['name'], xquery['group'], xquery['severity'], None, None, None, xinfo ] )

            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )

            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcounter) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxone.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_presets(self) :
        errorcount: int = 0
        inventory_name = 'presets'
        xinfo: str = None
        xobject: str = OBJ_PRESETS
        xstatus: int = SOK
        xcounter: int = 0
        xcustomized: int = 0
        xskip: int = 0
        xpresettype: str = None
        xstarted = CxDatetime.now()
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            xpresets: list[dict] = []
            xqueryids: list = None
            xallqueries: list[dict] = self.__internal_get_tenant_and_corp_queries(ignoreerrors = True)
            # Get the presets
            xpresets = self.cxone.get('/api/presets?offset=' + str(xskip) + '&limit=100')
            xpresets = xpresets.get('presets')
            if not xpresets :
                xpresets = []
            while len(xpresets) > 0 :
                for xpreset in xpresets :
                    xcounter += 1
                    xqueries = self.cxone.get('/api/presets/' + str(xpreset['id']))
                    xpreset.update(xqueries)
                    xinfo = None
                    xstatus = SOK
                    xqueryids = xpreset.get('queryIds')
                    xpresettype = PTYPE_OOB
                    if xpreset['custom'] :
                        xpresettype = PTYPE_CUSTOM
                        xcustomized += 1
                        xstatus = SWARNING
                        xinfo = 'custom preset'
                    if not xqueryids :
                        xstatus = SDANGER
                        if not xinfo :
                            xinfo = 'preset without queries'
                        else :
                            xinfo = xinfo + ' - ' + xinfo

                    self.__internal_write_preset( [ STATUS[xstatus], xpreset['id'], xpreset['name'], xpresettype, xpreset['custom'], None, xinfo ] )

                    if xallqueries and len(xallqueries) > 0 and xqueryids :
                        for xqueryid in xqueryids :
                            xquery = next( filter( lambda el: el['Id'] == xqueryid, xallqueries), None )
                            if xquery :
                                self.__internal_write_preset_query( [ STATUS[SOK], xpreset['id'], xpreset['name'], xpresettype, xquery['Id'], xquery['name'], xquery['lang'], xquery['group'], xquery['level'] ] )

                if len(xpresets) < 100 :
                    xpresets = []
                else :
                    xskip += 100
                    xpresets = self.cxone.get('/api/presets?offset=' + str(xskip) + '&limit=100')
                    xpresets = xpresets.get('presets')
                    if not xpresets :
                        xpresets = []

            xinfo = None
            xstatus = SOK
            if xcustomized > 0 :
                xstatus = SWARNING
                xinfo = str(xcustomized) + ' customized'
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )

            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcounter) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxone.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __internal_process_level_queries(self, objid: str, objname: str, application: bool = False) -> str :
        xallqueries: list = []
        xlevel: str = 'Project'
        xstatus: int = SOK
        xinfo: str = None
        xcounter: int = 1
        xerror: str = None
        # This call only gets for application or project levels
        try :
            if application :
                xcounter = None
                xlevel = 'Application'
                # TO-BE DONE
            else :
                xallqueries = self.cxone.get( '/api/cx-audit/queries?projectId=' + objid )
        except HTTPForbiddenException :
            xerror = 'forbidden processing level queries'
        except Exception :
            xerror = 'forbidden processing level queries'
        # From it, filter current level only
        if xallqueries and len(xallqueries) > 0 :
            xqueries: list = list( filter( lambda el: el['level'] == xlevel, xallqueries) )
            for xquery in xqueries :
                self.__internal_write_query( [ STATUS[xstatus], xquery['Id'], xlevel, xquery['lang'], xquery['name'], xquery['group'], xquery['severity'], objid, objname, xcounter, xinfo ] )
        return xerror


    def __inventory_applications(self) :
        errorcount: int = 0
        inventory_name = 'applications'
        xinfo: str = None
        xobject: str = OBJ_APPLICATIONS
        xstatus: int = SOK
        xcounter: int = 0
        xskip: int = 0
        xstarted = CxDatetime.now()
        xapplications: list[dict] = None
        cxlogger.info( 'Processing ' + inventory_name )
        try:
            xapplications = self.cxone.get('/api/applications?offset=' + str(xskip) + '&limit=100')
            xapplications = xapplications.get('applications')
            if not xapplications :
                xapplications = []
            for xapplication in xapplications :
                xcounter += 1
                xinfo = None
                xstatus = SOK
                # Process application level queries
                xinfo = self.__internal_process_level_queries(xapplication['id'], xapplication['name'], application = True)
                if xinfo :
                    xstatus = SWARNING
                self.__internal_write_application( [STATUS[xstatus], xapplication['id'], xapplication['name'], xapplication['description'], None, xinfo ] )

                if len(xapplications) < 100 :
                    xapplications = []
                else :
                    xskip += 100
                    xapplications = self.cxone.get('/api/applications?offset=' + str(xskip) + '&limit=100')
                    xapplications = xapplications.get('applications')
                    if not xapplications :
                        xapplications = []

            xinfo = None
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )

            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcounter) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxone.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __internal_process_project_last_scan(self, projectid: str, branch: str = None) -> tuple[dict, dict, dict, str] :
        xscan: dict = None
        xsastscan: dict = None
        xscascan: dict = None
        xotherscan: dict = None
        xerror: str = None
        xscans: list = []
        xquery: str = '/api/scans?offset=0&limit=100&project-ids=' + projectid + '&statuses=Completed'
        if branch :
            xquery = xquery + '&branch=' + branch
        try :
            xscans = self.cxone.get( xquery )
            if xscans:
                xscans = xscans.get('scans')
        except HTTPForbiddenException :
            xerror = 'scans retrieval forbidden'
        except HTTPTimeout :
            xerror = 'scans retrieval timeout'
        except Exception :
            xerror = 'scans retrieval failed'

        # Find the scans
        idx: int = 0
        while idx < len(xscans) and (xsastscan is None or xscascan is None or xotherscan is None) :
            xscan = xscans[idx]
            if not xsastscan and 'sast' in xscan['engines'] :
                xsastscan = xscan
            if not xscascan and 'sca' in xscan['engines'] :
                xscascan = xscan
            if not xotherscan and ('kics' in xscan['engines'] or 'apisec' in xscan['engines'] or 'containers' in xscan['engines']) :
                xotherscan = xscan
            idx += 1
        return xsastscan, xscascan, xotherscan, xerror


    def __internal_process_project_scans_summary(self, sastscan: dict, scascan: dict, otherscan: dict) -> tuple[dict, dict, dict, str] :
        xerror: str = None
        xsastid: str = None
        xsastsummary: dict = None
        xscaid: str = None
        xscasummary: dict = None
        xotherid: str = None
        xothersummary: dict = None
        xscanids: list[str] = []
        if sastscan :
            xsastid = sastscan.get('id')
        if scascan :
            xscaid = scascan.get('id')
        if otherscan :
            xotherid = otherscan.get('id')

        # Get scan summary
        def __get_scan_summary( scanid: str ) -> tuple[dict, str] :
            xscansummary: dict = None
            xerrorstr: str = None
            try :
                xdata: dict = self.cxone.get( '/api/scan-summary?scan-ids=' + scanid + '&include-queries=false&include-status-counters=false&include-files=false' )
                if xdata :
                    xdata = xdata.get('scansSummaries')
                    if xdata and len(xdata) > 0 :
                        xscansummary = xdata[0]
            except HTTPForbiddenException :
                xerrorstr = 'scan summary retrieval forbidden'
            except HTTPTimeout :
                xerrorstr = 'scan summary retrieval timeout'
            except Exception :
                xerrorstr = 'scan summary retrieval failed'
            return xscansummary, xerrorstr

        # Get SAST scan summary
        if not xerror and xsastid :
            if xsastid not in xscanids :
                xscanids.append(xsastid)
                xsastsummary, xerror = __get_scan_summary( xsastid )
            elif xsastid == xscaid :
                xsastsummary = xscasummary
            elif xsastid == xotherid :
                xsastsummary = xothersummary
        # Get SCA scan summary
        if not xerror and xscaid :
            if xscaid not in xscanids :
                xscanids.append(xscaid)
                xscasummary, xerror = __get_scan_summary( xscaid )
            elif xscaid == xsastid :
                xscasummary = xsastsummary
            elif xscaid == xotherid :
                xscasummary = xothersummary
        # Get OTHER scan summary
        if not xerror and xotherid :
            if xotherid not in xscanids :
                xscanids.append(xotherid)
                xothersummary, xerror = __get_scan_summary( xotherid )
            elif xotherid == xsastid :
                xothersummary = xsastsummary
            elif xotherid == xscaid :
                xothersummary = xscasummary

        # Process SAST counters
        if not xerror and xsastsummary :
            xcounter: dict = xsastsummary.get('sastCounters')
            xlanguages: list[str] = []
            if xcounter :
                # Identify languages
                xscanlanguages: list = xcounter.get('languageCounters')
                for xlanguage in xscanlanguages :
                    xlanguages.append(xlanguage['language'])
                sastscan['sastlanguages'] = xlanguages
                # Count results
                sastscan['sastresults'] = xcounter.get('totalCounter')
                if not sastscan['sastresults'] :
                    sastscan['sastresults'] = None
                # Count triages results
                xtriages: int = 0
                xstates: list = xcounter.get('stateCounters')
                if xstates :
                    for xstate in xstates :
                        if not xstate['state'] == 'TO_VERIFY' :
                            xtriages += xstate['counter']
                if xtriages > 0 :
                    sastscan['sasttriages'] = xtriages
                else :
                    sastscan['sasttriages'] = None
            else :
                sastscan['sastlanguages'] = []
                sastscan['sastresults'] = None
                sastscan['sasttriages'] = None

        # Process SCA counters
        if not xerror and xscasummary :
            xcounter: dict = xscasummary.get('scaCounters')
            if xcounter :
                # Count results
                scascan['scaresults'] = xcounter.get('totalCounter')
                if not scascan['scaresults'] :
                    scascan['scaresults'] = None
                # Count triages results
                xtriages: int = 0
                xstates: list = xcounter.get('stateCounters')
                if xstates :
                    for xstate in xstates :
                        if not xstate['state'] == 'TO_VERIFY' :
                            xtriages += xstate['counter']
                if xtriages > 0 :
                    scascan['scatriages'] = xtriages
                else :
                    scascan['scatriages'] = None
            else :
                scascan['scaresults'] = None
                scascan['scatriages'] = None

        # Process OTHER counters
        if not xerror and xothersummary :
            xcounters: list = xothersummary.keys()
            xresults: int = 0
            xtriages: int = 0
            for xcounterkey in xcounters :
                if str(xcounterkey).endswith('Counters') and not (xcounterkey == 'scaCounters' or xcounterkey == 'sastCounters' or xcounterkey == 'scaPackagesCounters') :
                    xcounter = xothersummary.get(xcounterkey)
                    # Count results
                    xcount = xcounter.get('totalCounter')
                    if xcount :
                        xresults += xcount
                    # Count triages results
                    xstates: list = xcounter.get('stateCounters')
                    if xstates :
                        for xstate in xstates :
                            if not xstate['state'] == 'TO_VERIFY' :
                                xtriages += xstate['counter']
            if xresults > 0 :
                otherscan['otherresults'] = xresults
            else :
                otherscan['otherresults'] = None
            if xtriages > 0 :
                otherscan['othertriages'] = xtriages
            else :
                otherscan['othertriages'] = None

        return sastscan, scascan, otherscan, xerror


    def __internal_process_project_scan_origin(self, sastorigin: str, scaorigin: str, otherorigin: str, sastsource: str, scasource: str, othersource: str, scmrepo: str ) -> int :
        xorigin: str = None
        xsource: str = None
        xstatus: int = SOK
        xscanorigins: list = self.cxcaches.cache(CACHE_SCAN_ORIGINS)

        if sastorigin :
            xorigin = sastorigin
            xsource = sastsource
        elif scaorigin :
            xorigin = scaorigin
            xsource = scasource
        elif otherorigin :
            xorigin = otherorigin
            xsource = othersource
        elif scmrepo :
            xorigin = 'Scm Integration'
        if xorigin :
            if not xscanorigins :
                xscanorigins = [ {"ORIGIN": xorigin, "SOURCE": xsource, "COUNT": 1, "STATUS": xstatus} ]
                self.cxcaches.putcache(CACHE_SCAN_ORIGINS, xscanorigins)
            else :
                xscanorigin = next( filter( lambda el: el["ORIGIN"] == xorigin and el["SOURCE"] == xsource, xscanorigins), None )
                if xscanorigin :
                    xscanorigin["COUNT"] = int(xscanorigin["COUNT"]) + 1
                else :
                    xscanorigins.append( {"ORIGIN": xorigin, "SOURCE": xsource, "COUNT": 1, "STATUS": xstatus} )
        return xstatus


    def __internal_process_project(self, project: dict) :

        xstatus: int = SOK
        xnotes: list[str] = []
        xinfo: str = None

        # Caches
        xapplicationscache: list = self.cxcaches.cache(CACHE_APPLICATIONS)
        xgroupscache: list = self.cxcaches.cache(CACHE_GROUPS)
        xallgroupscache: list = self.cxcaches.cache(CACHE_AC_GROUPS)

        # Auxiliary variables
        xauxlist: list = None
        xauxdict: dict = None
        xauxstrs: list[str] = None
        xauxstr: str = None

        # The variables holding the project output elements fields
        xprojid: int = project.get('id')
        xprojname: str = project.get('name')
        xprojcreated: str = self.__dateparse( project.get('createdAt') )
        xprojupdated: str = self.__dateparse( project.get('updatedAt') )
        xbranchprimary: str = project.get('mainBranch')
        xscmrepoid: str = project.get('repoId')
        if xscmrepoid :
            xscmrepoid = str(xscmrepoid)
        else :
            xscmrepoid = None
        xcriticality: int = project.get('criticality')
        xapplicationslist: list[str] = []
        xapplications: str = None           # Resolved
        xgroups: str = None                 # Resolved
        xtagcount: int = None               # Resolved
        xskipsubmodules: bool = None        # From configs
        xsourcecodemode: str = None         # From configs
        xsastlanguagemode: str = None       # From configs
        xsastfastscan: bool = None          # From configs
        xsastpreset: str = None             # From configs
        xsastfilter: str = None             # From configs
        xscaexploitable: bool = None        # From configs
        xscaexploitabletime: int = None     # From configs
        xscafilter: str = None              # From configs
        # Repository info, if selected
        xrepositorytype: str = None
        xrepositoryurl: str = None
        xrepositorybranch: str = None
        # From scans
        xlanguageslist: list[str] = None
        xsastlanguages: str = None
        xscanners: str = None
        # SAST scan
        xsastlastscan: str = None
        xsastscandate: str = None
        xsastscanorigin: str = None
        xsastscansource: str = None
        xsastscanresults: int = None
        xsastscantriages: int = None
        # SCA scan
        xscalastscan: str = None
        xscascandate: str = None
        xscascanorigin: str = None
        xscascansource: str = None
        xscascanresults: int = None
        xscascantriages: int = None
        # Other scan
        xotherlastscan: str = None
        xotherscandate: str = None
        xotherscanorigin: str = None
        xotherscansource: str = None
        xothercanresults: int = None
        xothercantriages: int = None

        # Process applications
        xauxlist = project.get('applicationIds')
        if xauxlist and xapplicationscache :
            xauxstrs = []
            for xappid in xauxlist :
                xapplicationslist.append(xappid)
                xauxdict = next( filter( lambda el: el['APP-ID'] == xappid, xapplicationscache), None )
                if xauxdict :
                    xauxstrs.append(xauxdict['APP-NAME'])
                    if not xauxdict['PROJ-USING'] :
                        xauxdict['PROJ-USING'] = 1
                    else :
                        xauxdict['PROJ-USING'] = xauxdict['PROJ-USING'] + 1
            if len(xauxstrs) > 0 :
                xapplications = SPLITTER.join(xauxstrs)

        # Process groups
        xauxlist = project.get('groups')
        if xauxlist and (xgroupscache or xallgroupscache) :
            xauxstrs = []
            for xgroupid in xauxlist :
                if xgroupscache :
                    xauxdict = next( filter( lambda el: el['GROUP-ID'] == xgroupid, xgroupscache), None )
                    if xauxdict :
                        xauxstrs.append(xauxdict['GROUP-NAME'])
                        if not xauxdict['PROJ-USING'] :
                            xauxdict['PROJ-USING'] = 1
                        else :
                            xauxdict['PROJ-USING'] = xauxdict['PROJ-USING'] + 1
                else :
                    xauxdict = next( filter( lambda el: el['id'] == xgroupid, xallgroupscache), None )
                    if xauxdict :
                        xauxstrs.append(xauxdict['path'])
            if len(xauxstrs) > 0 :
                xgroups = SPLITTER.join(xauxstrs)

        # Process tags
        xauxdict = project.get('tags')
        if xauxdict :
            xauxlist = list(xauxdict.keys())
            if xauxlist and len(xauxlist) > 0:
                xtagcount = len(xauxlist)

        # Process project configurations
        xprojdata: list[dict] = self.cxone.get('/api/configuration/project?project-id=' + xprojid)
        # Skip submodules
        xvalue = next( filter( lambda el: el['key'] == 'scan.handler.git.skipSubModules' and el['originLevel'] == 'Project' and el['value'], xprojdata ), None )
        if xvalue :
            xskipsubmodules = xvalue['value'] if xvalue['value'] else None
        # Source-code mode
        xvalue = next( filter( lambda el: el['key'] == 'scan.config.general.sourceCodeManagement' and el['originLevel'] == 'Project' and el['value'], xprojdata ), None )
        if xvalue :
            xsourcecodemode = xvalue['value'] if xvalue['value'] else None
        # SAST language mode
        xvalue = next( filter( lambda el: el['key'] == 'scan.config.sast.languageMode' and el['originLevel'] == 'Project' and el['value'], xprojdata ), None )
        if xvalue :
            xsastlanguagemode = xvalue['value'] if xvalue['value'] else None
        # SAST fastscan
        xvalue = next( filter( lambda el: el['key'] == 'scan.config.sast.fastScanMode' and el['originLevel'] == 'Project' and el['value'], xprojdata ), None )
        if xvalue :
            xsastfastscan = xvalue['value'] if xvalue['value'] else None
        # SAST preset
        xvalue = next( filter( lambda el: el['key'] == 'scan.config.sast.presetName' and el['originLevel'] == 'Project' and el['value'], xprojdata ), None )
        if xvalue :
            xsastpreset = xvalue['value'] if xvalue['value'] else None
            if not xsastpreset :
                xsastpreset = self.__tenantpreset
        else :
            xsastpreset = self.__tenantpreset
        # SAST filters (exclusions)
        xvalue = next( filter( lambda el: el['key'] == 'scan.config.sast.filter' and el['originLevel'] == 'Project' and el['value'], xprojdata ), None )
        if xvalue :
            xsastfilter = xvalue['value'] if xvalue['value'] else None
        # Get SCA exploitable path
        xvalue = next( filter( lambda el: el['key'] == 'scan.config.sca.ExploitablePath' and el['originLevel'] == 'Project' and el['value'], xprojdata ), None )
        if xvalue :
            xscaexploitable = xvalue['value'] if xvalue['value'] else None
        # Get SCA last sast scan time path
        xvalue = next( filter( lambda el: el['key'] == 'scan.config.sca.LastSastScanTime' and el['originLevel'] == 'Project' and el['value'], xprojdata ), None )
        if xvalue :
            xscaexploitabletime = xvalue['value'] if xvalue['value'] else None
        # SCA filters (exclusions)
        xvalue = next( filter( lambda el: el['key'] == 'scan.config.sca.filter' and el['originLevel'] == 'Project' and el['value'], xprojdata ), None )
        if xvalue :
            xscafilter = xvalue['value'] if xvalue['value'] else None

        # Process scm repo
        if self.__includerepos :
            # Check for scm webhook
            if xscmrepoid :
                try :
                    xauxdict = self.cxone.get('/api/repos-manager/repo/' + str(xscmrepoid) )
                    if xauxdict :
                        xrepositoryurl = xauxdict.get('url')
                        if xrepositoryurl :
                            xrepositorytype = 'webhook'
                            xauxstrs = []
                            xauxlist = xauxdict.get('branches')
                            if xauxlist :
                                for xbranch in xauxlist :
                                    xauxstrs.append(xbranch['name'])
                            if len(xauxstrs) > 0 :
                                xrepositorybranch = SPLITTER.join(xauxstrs)
                except Exception :
                    pass
            # Otherwise check for project git repo setting
            if not xrepositorytype :
                xvalue = next( filter( lambda el: el['key'] == 'scan.handler.git.repository' and el['originLevel'] == 'Project' and el['value'], xprojdata ), None )
                if xvalue :
                    xrepositoryurl = xvalue['value'] if xvalue['value'] else None
                if xrepositoryurl :
                    xrepositorytype = 'git'
                    xvalue = next( filter( lambda el: el['key'] == 'scan.handler.git.branch' and el['originLevel'] == 'Project' and el['value'], xprojdata ), None )
                    if xvalue :
                        xrepositorybranch = xvalue['value'] if xvalue['value'] else None

        # The next data retrieval only runs if scan information is not excluded
        if not self.__noscandata :
            xscanengines: list[str] = []
            xsastscan: dict = None
            xscascan: dict = None
            xotherscan: dict = None
            xsastscan, xscascan, xotherscan, xauxstr = self.__internal_process_project_last_scan(projectid = xprojid)
            if xauxstr :
                xnotes.append(xauxstr)
            if xsastscan :
                xsastlastscan = xsastscan.get('id')
                xsastscandate = self.__dateparse( xsastscan.get('createdAt') )
                xsastscanorigin = xsastscan.get('sourceOrigin')
                xsastscansource = xsastscan.get('sourceType')
                xscanengines.extend( xsastscan.get('engines') )
            if xscascan :
                xscalastscan = xscascan.get('id')
                xscascandate = self.__dateparse( xscascan.get('createdAt') )
                xscascanorigin = xscascan.get('sourceOrigin')
                xscascansource = xscascan.get('sourceType')
                xscanengines.extend( xscascan.get('engines') )
            if xotherscan :
                xotherlastscan = xotherscan.get('id')
                xotherscandate = self.__dateparse( xotherscan.get('createdAt') )
                xotherscanorigin = xotherscan.get('sourceOrigin')
                xotherscansource = xotherscan.get('sourceType')
                xscanengines.extend( xotherscan.get('engines') )

            xscanengines = list(set(xscanengines))
            if len(xscanengines) > 0 :
                xscanners = SPLITTER.join(xscanengines)

            # Triages and results, from summary
            if not self.__notriages :
                xsastscan, xscascan, xotherscan, xauxstr = self.__internal_process_project_scans_summary(sastscan = xsastscan, scascan = xscascan, otherscan = xotherscan)
                if xauxstr :
                    xnotes.append(xauxstr)
                if xsastscan :
                    xlanguageslist = xsastscan['sastlanguages']
                    xsastlanguages = SPLITTER.join(xlanguageslist)
                    if not xsastlanguages :
                        xsastlanguages = None
                    xsastscanresults = xsastscan['sastresults']
                    xsastscantriages = xsastscan['sasttriages']
                if xscascan :
                    xscascanresults = xscascan['scaresults']
                    xscascantriages = xscascan['scatriages']
                if xotherscan :
                    xothercanresults = xotherscan['otherresults']
                    xothercantriages = xotherscan['otherresults']

        # Check preset counters
        if xsastpreset :
            xcachepresets: list = self.cxcaches.cache(CACHE_PRESETS)
            if xcachepresets and len(xcachepresets) > 0 :
                xpreset = next(filter( lambda el: el['PRESET-NAME'] == xsastpreset, xcachepresets ), None)
                if xpreset :
                    if not xpreset['PROJ-USING'] :
                        xpreset['PROJ-USING'] = 1
                    else :
                        xpreset['PROJ-USING'] = xpreset['PROJ-USING'] + 1

        # Check queries counters
        if xlanguageslist and len(xlanguageslist) > 0 :
            xqueriescache: list = self.cxcaches.cache(CACHE_QUERIES)
            if xqueriescache and len(xqueriescache) > 0 :
                for xlanguage in xlanguageslist :
                    xqueries: list = list( filter( lambda el: el['QUERY-LEVEL'] in ['Tenant', 'Application'] and el['QUERY-LANGUAGE'] == xlanguage, xqueriescache ) )
                    for xquery in xqueries :
                        if (xquery['QUERY-LEVEL'] == 'Tenant') or (xquery['QUERY-LEVEL'] == 'Application' and xquery['REF-ID'] in xapplicationslist ) :
                            if not xquery['PROJ-USING'] :
                                xquery['PROJ-USING'] = 1
                            else :
                                xquery['PROJ-USING'] = xquery['PROJ-USING'] + 1

        # Process project level queries
        xauxstr = self.__internal_process_level_queries(xprojid, xprojname, False)

        # Check scan origins
        self.__internal_process_project_scan_origin( xsastscanorigin, xscascanorigin, xotherscanorigin, xsastscansource, xscascansource, xotherscansource, xscmrepoid )

        # Mount info from notes
        if len(xnotes) > 0 :
            xinfo = NOTESSPLITTER.join(xnotes)
            xstatus = SWARNING

        # Write it to csv
        if not self.__projshandler :
            filename = self.__datapath + os.sep + OUT_PROJECTS
            self.__projshandler = open(filename, 'w', encoding='UTF8', newline='', buffering=1)
            self.__projswriter = csv.writer(self.__projshandler, delimiter = self.cxcsv.csvseparator, quotechar = '"', doublequote = True, skipinitialspace = True, lineterminator = '\r\n' )
            self.__projswriter.writerow(CSV_PROJECTS)
        # Write it
        self.__projswriter.writerow( [ STATUS[xstatus], xprojid, xprojname, xprojcreated, xprojupdated, xbranchprimary,
                                    xrepositorytype, xrepositoryurl, xrepositorybranch,
                                    xcriticality, xapplications, xgroups, xtagcount,
                                    xskipsubmodules, xsourcecodemode,
                                    xsastlanguagemode, xsastfastscan, xsastpreset, xsastfilter,
                                    xscaexploitable, xscaexploitabletime, xscafilter,
                                    xsastlanguages, xscanners,
                                    xsastlastscan, xsastscandate, xsastscanorigin, xsastscansource, xsastscanresults, xsastscantriages,
                                    xscalastscan, xscascandate, xscascanorigin, xscascansource, xscascanresults, xscascantriages,
                                    xotherlastscan, xotherscandate, xotherscanorigin, xotherscansource, xothercanresults, xothercantriages,
                                    xinfo ] )


    def __inventory_projects(self) :
        errorcount: int = 0
        inventory_name = 'projects'
        xinfo: str = None
        xobject: str = OBJ_PROJECTS
        xstatus: int = SOK
        xcounter: int = 0
        xnotfoundcount: int = 0
        xskip: int = 0
        xstarted = CxDatetime.now()
        xfilterfield: str = None
        xfiltervalue: str = None
        xprojects: list[dict] = None
        xprojectcount: int = None
        cxlogger.info( 'Processing ' + inventory_name )
        try:

            # Is filtered
            if self.__projectfilter and len(self.__projectfilter) > 0 :
                xprjstarted = CxDatetime.now()
                for xfilter in self.__projectfilter :
                    xfilterfield = 'ids'
                    xfiltervalue = str(xfilter)
                    # If not a GUID, then use the name
                    try:
                        uuid.UUID(xfiltervalue)
                    except ValueError:
                        xfilterfield = 'names'
                        xfiltervalue = parse.quote(str(xfiltervalue), safe = '')
                    # Get the project
                    xprojects = self.cxone.get('/api/projects?' + xfilterfield + '=' + xfiltervalue + '&offset=0&limit=1')
                    if xprojectcount is None :
                        xprojectcount = xprojects.get('totalCount')
                        cxlogger.info('Counted ' + str(xprojectcount) + ' total projects (unfiltered) ... ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                    xprojects = xprojects.get('projects')
                    if not xprojects :
                        xprojects = []
                    if len(xprojects) > 0 :
                        self.__internal_process_project(xprojects[0])
                        xcounter += 1
                    else :
                        xnotfoundcount += 1
                    if (((xcounter + xnotfoundcount) % 100) == 0) or ((xcounter + xnotfoundcount) == len(self.__projectfilter)) :
                        # Log page time
                        cxlogger.info('Processed ' + str(xcounter + xnotfoundcount) + ' of ' + str(xprojectcount) + ' filtered projects ... ' + CxDatetime.elapsed(xprjstarted, hoursonly = True) + ' secs' )
                        xprjstarted = CxDatetime.now()

            else :
                # Non filtered
                xprjstarted = CxDatetime.now()
                xprojects = self.cxone.get('/api/projects?offset=' + str(xskip) + '&limit=100')
                xprojectcount = xprojects.get('totalCount')
                cxlogger.info('Counted ' + str(xprojectcount) + ' total projects (unfiltered) ... ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                xprojects = xprojects.get('projects')
                if not xprojects :
                    xprojects = []
                while len(xprojects) > 0 :
                    for xproject in xprojects :
                        self.__internal_process_project(xproject)
                        xcounter += 1
                    # Log page time
                    cxlogger.info('Processed ' + str(xcounter) + ' of ' + str(xprojectcount) + ' projects ... ' + CxDatetime.elapsed(xprjstarted, hoursonly = True) + ' secs' )
                    xprjstarted = CxDatetime.now()
                    if len(xprojects) < 100 :
                        xprojects = []
                    else :
                        xskip += 100
                        xprojects = self.cxone.get('/api/projects?offset=' + str(xskip) + '&limit=100')
                        xprojects = xprojects.get('projects')
                        if not xprojects :
                            xprojects = []

            xinfo = None
            xstatus = SOK
            if xnotfoundcount == 1 :
                xstatus = SWARNING
                xinfo = '1 filtered project not found'
            elif xnotfoundcount > 1 :
                xstatus = SWARNING
                xinfo = str(xnotfoundcount) + ' filtered projects not found'
            self.__internal_write_summary( [STATUS[xstatus], xobject, xcounter, xinfo ] )

            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcounter) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        except HTTPForbiddenException :
            errorcount += 1
            cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
            self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
        except Exception as e:
            errorcount += 1
            if self.cxone.statuscode == HTTPStatus.FORBIDDEN :
                cxlogger.warning('Processing ' + inventory_name + ' forbidden - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SFORBIDDEN] )
            else :
                cxlogger.error('Processing ' + inventory_name + ' failed - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
                self.__internal_write_summary( [STATUS[SFAILED], xobject, None, SEXCEPTION] )
                raise e
        return errorcount


    def __inventory_process_groups_counters(self) :
        errorcount: int = 0
        xcache = self.cxcaches.cache(CACHE_GROUPS)
        if xcache and len(xcache) > 0 :
            xcount: int = 0
            inventory_name = 'ac groups counters'
            csvreader: int = None
            csvwriter: int = None
            datafile: str = None
            tempfile: str = None
            xobject: dict = None
            xcacheobj: dict = None
            xstarted = CxDatetime.now()
            cxlogger.info( 'Processing ' + inventory_name )

            try:
                datafile = self.__datapath + os.sep + OUT_ACGROUPS
                tempfile = self.__datapath + os.sep + '_' + OUT_ACGROUPS
                auxfile = self.__datapath + os.sep + '__' + OUT_ACGROUPS
                csvreader = self.cxcsv.csvopenread(datafile)
                csvwriter = self.cxcsv.csvopenwrite(tempfile)
                xobject = self.cxcsv.csvread(csvreader)

                # Process the counters list
                while xobject :
                    # Find the counter
                    xcacheobj = next( filter( lambda el: el['GROUP-ID'] == xobject['GROUP-ID'] and el['GROUP-NAME'] == xobject['GROUP-NAME'], xcache ), None )
                    if xcacheobj and ( xcacheobj['PROJ-USING'] or xcacheobj['PROJ-USING'] ):
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
                cxlogger.error('failed to ac process groups counters')
            finally :
                if csvreader :
                    self.cxcsv.csvclose(csvreader)
                if csvwriter :
                    self.cxcsv.csvclose(csvwriter)
            # Clear unneeded cache
            self.cxcaches.uncache(CACHE_GROUPS)
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
                    xcacheobj = next( filter( lambda el: el['QUERY-LEVEL'] == xobject['QUERY-LEVEL'] and str(el['QUERY-ID']) == str(xobject['QUERY-ID']) and el['QUERY-NAME'] == xobject['QUERY-NAME'] and el['QUERY-LANGUAGE'] == xobject['QUERY-LANGUAGE'], xcache ), None )
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


    def __inventory_process_application_counters(self) :
        errorcount: int = 0
        xcache = self.cxcaches.cache(CACHE_APPLICATIONS)
        if xcache and len(xcache) > 0 :
            xcount: int = 0
            inventory_name = 'applications counters'
            csvreader: int = None
            csvwriter: int = None
            datafile: str = None
            tempfile: str = None
            xobject: dict = None
            xcacheobj: dict = None
            xstarted = CxDatetime.now()
            cxlogger.info( 'Processing ' + inventory_name )

            try:
                datafile = self.__datapath + os.sep + OUT_APPLICATIONS
                tempfile = self.__datapath + os.sep + '_' + OUT_APPLICATIONS
                auxfile = self.__datapath + os.sep + '__' + OUT_APPLICATIONS
                csvreader = self.cxcsv.csvopenread(datafile)
                csvwriter = self.cxcsv.csvopenwrite(tempfile)
                xobject = self.cxcsv.csvread(csvreader)

                # Process the counters list
                while xobject :
                    # Find the counter
                    xcacheobj = next( filter( lambda el: el['APP-ID'] == xobject['APP-ID'] and el['APP-NAME'] == xobject['APP-NAME'], xcache ), None )
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
                cxlogger.error('failed to applications presets counters')
            finally :
                if csvreader :
                    self.cxcsv.csvclose(csvreader)
                if csvwriter :
                    self.cxcsv.csvclose(csvwriter)
            # Clear unneeded cache
            self.cxcaches.uncache(CACHE_APPLICATIONS)
            # Close
            cxlogger.info('Processed ' + inventory_name + ' (' + str(xcount) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )

        return errorcount


    def __inventory_process_origins(self) :
        errorcount: int = 0
        xcacheorigins = self.cxcaches.cache(CACHE_SCAN_ORIGINS)
        # Have we anything to process ?
        if not ( xcacheorigins and len(xcacheorigins) > 0 ) :
            return errorcount

        xcount: int = 0
        inventory_name = 'scan origins'
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
                             'OBJ-REF': origin['SOURCE'],
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
        # Close
        cxlogger.info('Processed ' + inventory_name + ' (' + str(xcount) + ') - ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )

        return errorcount


    def execute(self) -> int :
        errorcount: int = 0
        xstarted = CxDatetime.now()

        cxlogger.info( '=============================================================================' )
        cxlogger.info( 'CxONE inventory start, ' + CxDatetime.nowastext() )
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
                    xfilterdata: any = CxParamFilters.processfilter(filter = self.__projectfilter, numerics = False, guids = False, odatanum = False)
                    if xfilterdata :
                        if isinstance(xfilterdata, list) :
                            self.__projectfilter = xfilterdata
                            if len(xfilterdata) == 1 :
                                cxlogger.info( "> options.projects-filter: " + str(xfilterdata[0]) )
                            else :
                                cxlogger.info( "> options.projects-filter: " + str(len(xfilterdata)) + " projects" )
                        else :
                            self.__projectfilter = [xfilterdata]
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
                    # Process CXONE version
                    errorcount += self.__inventory_cxoneinstance()
                    # Process CXONE tenant configurations
                    errorcount += self.__inventory_tenantconfigs()
                    # Process CXONE iam data
                    errorcount += self.__inventory_iam_users()
                    errorcount += self.__inventory_iam_groups()
                    errorcount += self.__inventory_iam_roles()
                    errorcount += self.__inventory_iam_idpsettings()
                    errorcount += self.__inventory_iam_ldapsettings()
                    # Dispose of caches we don't need anymore
                    self.cxcaches.uncache(CACHE_AC_USERS)
                    # self.cxcaches.uncache(CACHE_AC_GROUPS)
                    # Process queries, presets
                    errorcount += self.__inventory_queries_tenant()
                    errorcount += self.__inventory_presets()
                    # Projects and applications
                    errorcount += self.__inventory_applications()
                    errorcount += self.__inventory_projects()
                    # Close the files
                    self.__closedatafiles()
                    # Dispose of caches we don't need anymore
                    self.cxcaches.uncache(CACHE_AC_GROUPS)
                    self.cxcaches.uncache(CACHE_TENANT_QUERIES)
                    # Post-process object counters
                    errorcount += self.__inventory_process_groups_counters()
                    errorcount += self.__inventory_process_queries_counters()
                    errorcount += self.__inventory_process_presets_counters()
                    errorcount += self.__inventory_process_application_counters()
                    # Post-process origins
                    errorcount += self.__inventory_process_origins()

                except Exception as e :
                    errorcount += 1
                    cxlogger.exception(e)

            else :
                errorcount += 1

        # Ensure data files closure
        self.__closedatafiles()

        cxlogger.info( '=============================================================================' )
        cxlogger.info( 'CxONE inventory end, ' + CxDatetime.nowastext() )
        if errorcount > 0 :
            cxlogger.warning( 'Found ' + str(errorcount) + ' errors, check the logs' )
        cxlogger.info( 'Duration ' + CxDatetime.elapsed(xstarted, hoursonly = True) + ' secs' )
        cxlogger.info( '=============================================================================' )

        return errorcount
